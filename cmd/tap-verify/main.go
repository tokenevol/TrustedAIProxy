package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"tap/internal/attestation"
)

func main() {
	publicKeyText := flag.String("public-key", "", "base64url Ed25519 attestation public key")
	expectedDomain := flag.String("expected-domain", "", "expected upstream domain")
	expectedFingerprint := flag.String("expected-certificate-sha256", "", "optional expected upstream leaf certificate SHA-256")
	prompt := flag.String("prompt", "hello", "request prompt value")
	model := flag.String("model", "demo-model", "request model value")
	proxyURL := flag.String("proxy", "", "explicit proxy URL; otherwise use HTTP_PROXY/HTTPS_PROXY")
	caCert := flag.String("ca-cert", "", "MITM CA PEM to trust for this demo client")
	maxAge := flag.Duration("max-age", 5*time.Minute, "maximum attestation age")
	stream := flag.Bool("stream", false, "request and verify a request-only streaming attestation")
	challenge := flag.String("challenge", "", "URL-safe client challenge for -stream (generated when omitted)")
	flag.Parse()
	if *publicKeyText == "" || *expectedDomain == "" || flag.NArg() != 1 {
		log.Fatal("usage: tap-verify -public-key BASE64URL -expected-domain api.example.com [-proxy http://127.0.0.1:8080] [-ca-cert mitm-ca.pem] URL")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(*publicKeyText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		log.Fatal("-public-key must be a base64url Ed25519 public key")
	}
	client, err := newClient(*proxyURL, *caCert)
	if err != nil {
		log.Fatal(err)
	}
	requestValues := map[string]any{
		"model":    *model,
		"messages": []map[string]string{{"role": "user", "content": *prompt}},
	}
	if *stream {
		requestValues["stream"] = true
		if *challenge == "" {
			*challenge = randomChallenge()
		}
		if err := attestation.ValidateChallenge(*challenge); err != nil {
			log.Fatalf("-challenge: %v", err)
		}
	}
	requestBody, _ := json.Marshal(requestValues)
	request, err := http.NewRequest(http.MethodPost, flag.Arg(0), bytes.NewReader(requestBody))
	if err != nil {
		log.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if *stream {
		request.Header.Set(attestation.HeaderChallenge, *challenge)
	}
	response, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	if *stream {
		signedModel := response.Header.Get(attestation.HeaderModel)
		if signedModel == "" {
			log.Fatal("response is missing X-Attestation-Model")
		}
		modelField, err := attestation.NewField("model", mustJSON(signedModel))
		if err != nil {
			log.Fatal(err)
		}
		messagesField, err := attestation.NewField("messages", mustJSON([]attestation.TextMessage{{Role: "user", Text: *prompt}}))
		if err != nil {
			log.Fatal(err)
		}
		streamField, err := attestation.NewField("stream", []byte("true"))
		if err != nil {
			log.Fatal(err)
		}
		contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil {
			log.Fatalf("parse streaming response Content-Type: %v", err)
		}
		observation := attestation.RequestUpstreamObservation{
			Domain:                 *expectedDomain,
			CertificateFingerprint: *expectedFingerprint,
			RequestPath:            request.URL.Path,
			RequestFields:          []attestation.Field{modelField, messagesField, streamField},
			Challenge:              *challenge,
			ResponseStatus:         response.StatusCode,
			ResponseContentType:    contentType,
		}
		if err := attestation.VerifyRequestUpstream(ed25519.PublicKey(publicKey), response.Header, observation, time.Now(), *maxAge); err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VALID REQUEST ONLY: domain=%s certificate_sha256=%s challenge=%s response_body=unverified\n",
			response.Header.Get(attestation.HeaderDomain),
			response.Header.Get(attestation.HeaderCertificateFingerprint),
			*challenge)
		if _, err := io.Copy(os.Stdout, response.Body); err != nil {
			log.Fatal(err)
		}
		return
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	var fields struct {
		Choices []struct {
			Message struct {
				Role    string  `json:"role"`
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &fields); err != nil || len(fields.Choices) != 1 || fields.Choices[0].Message.Content == nil || fields.Choices[0].Message.Role != "assistant" {
		log.Fatalf("response is not OpenAI-compatible text JSON: %v", err)
	}
	signedModel := response.Header.Get(attestation.HeaderModel)
	if signedModel == "" {
		log.Fatal("response is missing X-Attestation-Model")
	}
	modelField, err := attestation.NewField("model", mustJSON(signedModel))
	if err != nil {
		log.Fatal(err)
	}
	requestField, err := attestation.NewField("messages", mustJSON([]attestation.TextMessage{{Role: "user", Text: *prompt}}))
	if err != nil {
		log.Fatal(err)
	}
	responseField, err := attestation.NewField("messages", mustJSON([]attestation.TextMessage{{Role: "assistant", Text: *fields.Choices[0].Message.Content}}))
	if err != nil {
		log.Fatal(err)
	}
	if err := attestation.Verify(ed25519.PublicKey(publicKey), response.Header, *expectedDomain, *expectedFingerprint, request.URL.Path, []attestation.Field{modelField, requestField}, []attestation.Field{responseField}, time.Now(), *maxAge); err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID: domain=%s certificate_sha256=%s message=%q\n",
		response.Header.Get(attestation.HeaderDomain),
		response.Header.Get(attestation.HeaderCertificateFingerprint),
		*fields.Choices[0].Message.Content)
}

func randomChallenge() string {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		log.Fatalf("generate challenge: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func newClient(proxyAddress, caCertPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	if proxyAddress != "" {
		proxyURL, err := url.Parse(proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("parse proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	if caCertPath != "" {
		caPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read MITM CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("MITM CA contains no certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func normalizedDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
