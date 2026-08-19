package mitmproxy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tap/internal/attestation"
)

func TestHTTPSMITMSignsNormalizedTextAndUpstreamCertificate(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte(`"model":"gpt-test"`)) {
			t.Errorf("unexpected request body: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices":[{"message":{"role":"assistant","content":[{"type":"text","text":"hello "},{"type":"text","text":"world"}]}}],
			"ignored":"not-signed"
		}`))
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	outbound := http.DefaultTransport.(*http.Transport).Clone()
	outbound.Proxy = nil
	outbound.TLSClientConfig = &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12}

	pathRules := mustCompilePathRules(t, map[string]PathRule{
		"/v1/chat/completions": {Extractor: ExtractorOpenAIChatConversation},
	})
	proxy := New(Config{
		CA:             ca,
		Signer:         attestation.NewSigner(privateKey, "integration-key"),
		PathRules:      pathRules,
		MaxJSONBytes:   1 << 20,
		Transport:      outbound,
		ProofReference: "proof-test",
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.Leaf)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12},
	}}

	requestBody := `{
		"model":"gpt-test",
		"messages":[
			{"role":"system","content":"be concise"},
			{"role":"user","content":[{"type":"text","text":"hel"},{"type":"text","text":"lo"}]}
		]
	}`
	request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat/completions?ignored=true", bytes.NewBufferString(requestBody))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	var responseJSON any
	if err := json.Unmarshal(body, &responseJSON); err != nil {
		t.Fatalf("proxy changed response into invalid JSON: %v", err)
	}

	fingerprint := sha256.Sum256(upstream.Certificate().Raw)
	expectedFingerprint := hex.EncodeToString(fingerprint[:])
	requestFields := []attestation.Field{
		mustAttestationField(t, "model", `"gpt-test"`),
		mustAttestationField(t, "messages", `[{"role":"system","text":"be concise"},{"role":"user","text":"hello"}]`),
	}
	responseFields := []attestation.Field{mustAttestationField(t, "messages", `[{"role":"assistant","text":"hello world"}]`)}
	if err := attestation.Verify(publicKey, response.Header, "127.0.0.1", expectedFingerprint, "/v1/chat/completions", requestFields, responseFields, time.Now(), 5*time.Minute); err != nil {
		t.Fatalf("verify MITM attestation: %v", err)
	}
	if got, want := response.Header.Get(attestation.HeaderProfile), attestation.Profile; got != want {
		t.Fatalf("profile = %q, want %q", got, want)
	}
	if response.Header.Get(attestation.HeaderProofReference) != "proof-test" {
		t.Fatalf("proof reference = %q", response.Header.Get(attestation.HeaderProofReference))
	}
}

func TestHTTPSMITMSignsStreamingRequestBeforeForwardingBody(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	upstreamChallenge := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamChallenge <- r.Header.Get(attestation.HeaderChallenge)
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set(attestation.HeaderChallenge, "forged_upstream_challenge")
		w.Header().Set(attestation.HeaderSignature, "forged-upstream-signature")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream response writer does not support flush")
			return
		}
		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()
		<-release
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	outbound := http.DefaultTransport.(*http.Transport).Clone()
	outbound.Proxy = nil
	outbound.TLSClientConfig = &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12}
	proxy := New(Config{
		CA:             ca,
		Signer:         attestation.NewSigner(privateKey, "integration-key"),
		PathRules:      mustCompilePathRules(t, map[string]PathRule{"/v1/chat/completions": {Extractor: ExtractorOpenAIChatConversation}}),
		Transport:      outbound,
		ProofReference: "proof-test",
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.Leaf)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12}}}

	requestBody := `{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}`
	request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat/completions", bytes.NewBufferString(requestBody))
	request.Header.Set("Content-Type", "application/json")
	challenge := "customer_challenge_123"
	request.Header.Set(attestation.HeaderChallenge, challenge)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := <-upstreamChallenge; got != "" {
		t.Fatalf("challenge leaked to upstream: %q", got)
	}
	if got, want := response.Header.Get(attestation.HeaderProfile), attestation.RequestUpstreamProfile; got != want {
		t.Fatalf("profile = %q, want %q", got, want)
	}
	if response.Header.Get(attestation.HeaderSignature) == "forged-upstream-signature" {
		t.Fatal("upstream-supplied signature was forwarded")
	}
	if response.Header.Get(attestation.HeaderProofReference) != "proof-test" {
		t.Fatalf("proof reference = %q", response.Header.Get(attestation.HeaderProofReference))
	}
	fingerprint := sha256.Sum256(upstream.Certificate().Raw)
	observation := attestation.RequestUpstreamObservation{
		Domain:                 "127.0.0.1",
		CertificateFingerprint: hex.EncodeToString(fingerprint[:]),
		RequestPath:            "/v1/chat/completions",
		RequestFields: []attestation.Field{
			mustAttestationField(t, "model", `"gpt-test"`),
			mustAttestationField(t, "messages", `[{"role":"user","text":"hello"}]`),
			mustAttestationField(t, "stream", `true`),
		},
		Challenge:           challenge,
		ResponseStatus:      http.StatusOK,
		ResponseContentType: "text/event-stream",
	}
	if err := attestation.VerifyRequestUpstream(publicKey, response.Header, observation, time.Now(), 5*time.Minute); err != nil {
		t.Fatalf("verify streaming request attestation: %v", err)
	}
	reader := bufio.NewReader(response.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil || firstLine != "data: first\n" {
		t.Fatalf("first streamed line = %q, err = %v", firstLine, err)
	}
	blankLine, err := reader.ReadString('\n')
	if err != nil || blankLine != "\n" {
		t.Fatalf("streamed event separator = %q, err = %v", blankLine, err)
	}
	close(release)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(rest), "data: [DONE]\n\n"; got != want {
		t.Fatalf("remaining stream = %q, want %q", got, want)
	}
}

func TestStreamingResponseWithoutChallengeRemainsUnsigned(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()
	caDir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	outbound := http.DefaultTransport.(*http.Transport).Clone()
	outbound.Proxy = nil
	outbound.TLSClientConfig = &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12}
	proxy := New(Config{
		CA:        ca,
		Signer:    attestation.NewSigner(privateKey, "integration-key"),
		PathRules: mustCompilePathRules(t, map[string]PathRule{"/v1/chat/completions": {Extractor: ExtractorOpenAIChatConversation}}),
		Transport: outbound,
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.Leaf)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12}}}
	request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get(attestation.HeaderSignature) != "" {
		t.Fatal("stream without a client challenge unexpectedly received a signature")
	}
	if got, want := string(body), "data: [DONE]\n\n"; got != want {
		t.Fatalf("stream body = %q, want %q", got, want)
	}
}

func TestHTTPSMITMDoesNotSignUnsupportedTextRequest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"world"}}]}`))
	}))
	defer upstream.Close()

	caDir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(caDir, "ca.pem"), filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	outbound := http.DefaultTransport.(*http.Transport).Clone()
	outbound.Proxy = nil
	outbound.TLSClientConfig = &tls.Config{RootCAs: upstreamRoots, MinVersion: tls.VersionTLS12}
	proxy := New(Config{
		CA:        ca,
		Signer:    attestation.NewSigner(privateKey, "integration-key"),
		PathRules: mustCompilePathRules(t, map[string]PathRule{"/v1/chat/completions": {Extractor: ExtractorOpenAIChatConversation}}),
		Transport: outbound,
	})
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.Leaf)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12}}}

	request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat/completions", bytes.NewBufferString(`{
		"model":"gpt-test",
		"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.ReadAll(response.Body)
	if response.Header.Get(attestation.HeaderSignature) != "" {
		t.Fatal("unsupported non-text request unexpectedly received an attestation signature")
	}
}

func mustAttestationField(t *testing.T, path, value string) attestation.Field {
	t.Helper()
	field, err := attestation.NewField(path, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return field
}

func mustCompilePathRules(t *testing.T, configured map[string]PathRule) *CompiledPathRules {
	t.Helper()
	rules, err := CompilePathRules(configured)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestLogsForwardedRequestWithoutQueryParameters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxy := New(Config{})
	var logs bytes.Buffer
	proxy.Logger = log.New(&logs, "", 0)
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	response, err := client.Get(upstream.URL + "/v1/demo?api_key=secret")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if got := logs.String(); !strings.Contains(got, "FORWARD: method=GET target="+upstream.URL+"/v1/demo") {
		t.Fatalf("forward log = %q", got)
	}
	if strings.Contains(logs.String(), "api_key") || strings.Contains(logs.String(), "secret") {
		t.Fatalf("forward log exposed query parameters: %q", logs.String())
	}
}

func TestDefaultMaxJSONBytesIsTwoMiB(t *testing.T) {
	if got, want := DefaultMaxJSONBytes, int64(2*1024*1024); got != want {
		t.Fatalf("default max JSON bytes = %d, want %d", got, want)
	}
}

func TestClearAttestationHeadersRemovesSemanticHeaders(t *testing.T) {
	header := make(http.Header)
	header.Set(attestation.HeaderRequestPath, "/untrusted")
	header.Set(attestation.HeaderModel, "untrusted-model")
	header.Set(attestation.HeaderProfile, "untrusted-profile")
	header.Set(attestation.HeaderChallenge, "untrusted-challenge")
	header.Set(attestation.HeaderResponseStatus, "200")
	clearAttestationHeaders(header)
	if header.Get(attestation.HeaderRequestPath) != "" || header.Get(attestation.HeaderModel) != "" || header.Get(attestation.HeaderProfile) != "" || header.Get(attestation.HeaderChallenge) != "" || header.Get(attestation.HeaderResponseStatus) != "" {
		t.Fatalf("attestation semantic headers were not cleared: %v", header)
	}
}

func TestTakeChallengeStripsInternalHeader(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		valid  bool
	}{
		{name: "valid", values: []string{"customer_challenge_123"}, valid: true},
		{name: "missing"},
		{name: "invalid", values: []string{"contains spaces"}},
		{name: "duplicate", values: []string{"customer_challenge_123", "another_challenge_123"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range test.values {
				header.Add(attestation.HeaderChallenge, value)
			}
			_, valid := takeChallenge(header)
			if valid != test.valid {
				t.Fatalf("valid = %v, want %v", valid, test.valid)
			}
			if header.Get(attestation.HeaderChallenge) != "" {
				t.Fatal("challenge header was not stripped")
			}
		})
	}
}
