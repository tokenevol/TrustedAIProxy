package mitmproxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"tap/internal/attestation"
)

type Config struct {
	CA             tls.Certificate
	Signer         *attestation.Signer
	PathRules      *CompiledPathRules
	MaxJSONBytes   int64
	Verbose        bool
	Transport      *http.Transport
	ProofReference string
}

const DefaultMaxJSONBytes int64 = 2 << 20

// PathRule selects the versioned protocol extractor used to normalize the
// ordered request and response text messages covered by a signature.
type PathRule struct {
	Extractor string `json:"extractor"`
}

type requestState struct {
	domain        string
	path          string
	requestFields []attestation.Field
	extractor     textExtractor
}

func New(config Config) *goproxy.ProxyHttpServer {
	if config.MaxJSONBytes <= 0 {
		config.MaxJSONBytes = DefaultMaxJSONBytes
	}
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = config.Verbose
	proxy.CertStore = &memoryCertStore{certificates: make(map[string]*tls.Certificate)}
	if config.Transport != nil {
		proxy.Tr = config.Transport
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Do not inherit HTTP_PROXY/HTTPS_PROXY in the proxy's own outbound
		// transport; that can create an accidental loop back to this process.
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		proxy.Tr = transport
	}

	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&config.CA),
	}
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitmAction, host
	}))

	proxy.OnRequest().DoFunc(func(request *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		domain := strings.ToLower(request.URL.Hostname())
		ctx.Proxy.Logger.Printf("[%03d] FORWARD: method=%s target=%s", ctx.Session&0xffff, request.Method, forwardingTarget(request))
		rule, ok := config.PathRules.Match(request.URL.Path)
		if !ok || !isJSON(request.Header.Get("Content-Type")) || request.Body == nil {
			return request, nil
		}
		body, complete, err := readAndRestore(&request.Body, config.MaxJSONBytes)
		if err != nil || !complete {
			ctx.Warnf("cannot inspect JSON request for %s: %v", domain, err)
			return request, nil
		}
		extractor, ok := lookupTextExtractor(rule.Extractor)
		if !ok {
			ctx.Warnf("unknown text extractor %q for %s%s", rule.Extractor, domain, request.URL.Path)
			return request, nil
		}
		fields, err := extractor.ExtractRequest(body, request.URL.Path)
		if err != nil {
			ctx.Warnf("cannot extract signed request conversation for %s%s: %v", domain, request.URL.Path, err)
			return request, nil
		}
		ctx.UserData = requestState{domain: domain, path: request.URL.Path, requestFields: fields, extractor: extractor}
		return request, nil
	})

	proxy.OnResponse().DoFunc(func(response *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if response == nil {
			return response
		}
		clearAttestationHeaders(response.Header)
		state, ok := ctx.UserData.(requestState)
		if !ok || !isJSON(response.Header.Get("Content-Type")) || response.Body == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || len(response.TLS.VerifiedChains) == 0 {
			return response
		}
		body, complete, err := readAndRestore(&response.Body, config.MaxJSONBytes)
		if err != nil || !complete {
			ctx.Warnf("cannot inspect JSON response for %s: %v", state.domain, err)
			return response
		}
		fields, err := state.extractor.ExtractResponse(body)
		if err != nil {
			ctx.Warnf("cannot extract signed response conversation for %s%s: %v", state.domain, state.path, err)
			return response
		}
		fingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
		if err := config.Signer.Sign(response.Header, state.domain, hex.EncodeToString(fingerprint[:]), state.path, state.requestFields, fields); err != nil {
			ctx.Warnf("sign response for %s: %v", state.domain, err)
		} else if config.ProofReference != "" {
			response.Header.Set(attestation.HeaderProofReference, config.ProofReference)
		}
		return response
	})
	return proxy
}

func forwardingTarget(request *http.Request) string {
	target := *request.URL
	// Query parameters and URL userinfo can contain credentials. They are not
	// needed to identify the upstream route in forwarding logs.
	target.User = nil
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	return target.String()
}

func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"))
}

type restoredReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *restoredReadCloser) Close() error { return r.closer.Close() }

func readAndRestore(body *io.ReadCloser, limit int64) ([]byte, bool, error) {
	original := *body
	data, err := io.ReadAll(io.LimitReader(original, limit+1))
	if err != nil {
		*body = &restoredReadCloser{Reader: io.MultiReader(bytes.NewReader(data), original), closer: original}
		return nil, false, err
	}
	if int64(len(data)) > limit {
		*body = &restoredReadCloser{Reader: io.MultiReader(bytes.NewReader(data), original), closer: original}
		return nil, false, nil
	}
	*body = io.NopCloser(bytes.NewReader(data))
	if err := original.Close(); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func clearAttestationHeaders(header http.Header) {
	for _, name := range []string{
		attestation.HeaderAlgorithm,
		attestation.HeaderProfile,
		attestation.HeaderKeyID,
		attestation.HeaderDomain,
		attestation.HeaderRequestPath,
		attestation.HeaderModel,
		attestation.HeaderCertificateFingerprint,
		attestation.HeaderTimestamp,
		attestation.HeaderNonce,
		attestation.HeaderSignedFields,
		attestation.HeaderSignature,
		attestation.HeaderProofReference,
	} {
		header.Del(name)
	}
}

type memoryCertStore struct {
	mu           sync.Mutex
	certificates map[string]*tls.Certificate
}

func (s *memoryCertStore) Fetch(hostname string, generate func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if certificate, ok := s.certificates[hostname]; ok {
		return certificate, nil
	}
	certificate, err := generate()
	if err != nil {
		return nil, err
	}
	s.certificates[hostname] = certificate
	return certificate, nil
}
