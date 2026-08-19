package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestSignAndVerifySemanticTextFields(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	signer := NewSigner(privateKey, "demo-key")
	signer.now = func() time.Time { return now }
	header := make(http.Header)
	requestFields := []Field{mustField(t, "input.prompt", `"hello"`)}
	responseFields := []Field{mustField(t, "choices.0.message.content", `"world"`)}
	if err := signer.Sign(header, "API.Example.com", "AABBCC", "/v1/chat", requestFields, responseFields); err != nil {
		t.Fatal(err)
	}
	if err := Verify(publicKey, header, "api.example.com", "aabbcc", "/v1/chat", requestFields, responseFields, now, 5*time.Minute); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if got, want := header.Get(HeaderSignedFields), "tls_certificate_sha256,domain,request.path,request.body.input.prompt,response.body.choices.0.message.content"; got != want {
		t.Fatalf("signed fields = %q, want %q", got, want)
	}
	if got, want := header.Get(HeaderRequestPath), "/v1/chat"; got != want {
		t.Fatalf("request path header = %q, want %q", got, want)
	}
	if got, want := header.Get(HeaderProfile), Profile; got != want {
		t.Fatalf("profile header = %q, want %q", got, want)
	}
	if hasHeader(header, HeaderModel) {
		t.Fatal("unexpected model header without a signed model field")
	}
}

func TestSignAndVerifyExposeSignedModel(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	signer := NewSigner(privateKey, "demo-key")
	header := make(http.Header)
	requestFields := []Field{
		mustField(t, "model", `"gpt-4o"`),
		mustField(t, "prompt", `"hello"`),
	}
	responseFields := []Field{mustField(t, "message", `"world"`)}
	if err := signer.Sign(header, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields); err != nil {
		t.Fatal(err)
	}
	if got, want := header.Get(HeaderModel), "gpt-4o"; got != want {
		t.Fatalf("model header = %q, want %q", got, want)
	}
	if err := Verify(publicKey, header, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields, now, 5*time.Minute); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	tamperedModel := header.Clone()
	tamperedModel.Set(HeaderModel, "other-model")
	if err := Verify(publicKey, tamperedModel, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields, now, 5*time.Minute); err == nil {
		t.Fatal("expected changed model header to fail verification")
	}
	tamperedPath := header.Clone()
	tamperedPath.Set(HeaderRequestPath, "/v1/other")
	if err := Verify(publicKey, tamperedPath, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields, now, 5*time.Minute); err == nil {
		t.Fatal("expected changed path header to fail verification")
	}
	duplicateModel := header.Clone()
	duplicateModel.Add(HeaderModel, "gpt-4o")
	if err := Verify(publicKey, duplicateModel, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields, now, 5*time.Minute); err == nil {
		t.Fatal("expected duplicate model headers to fail verification")
	}
}

func TestSignAndVerifyRequestUpstream(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_700_000_000, 0).UTC()
	signer := NewSigner(privateKey, "demo-key")
	signer.now = func() time.Time { return now }
	requestFields := []Field{
		mustField(t, "model", `"gpt-test"`),
		mustField(t, "messages", `[{"role":"user","text":"hello"}]`),
		mustField(t, "stream", `true`),
	}
	observation := RequestUpstreamObservation{
		Domain:                 "API.Example.com",
		CertificateFingerprint: "AABBCC",
		RequestPath:            "/v1/chat/completions",
		RequestFields:          requestFields,
		Challenge:              "customer_challenge_123",
		ResponseStatus:         http.StatusOK,
		ResponseContentType:    "text/event-stream",
	}
	header := make(http.Header)
	if err := signer.SignRequestUpstream(header, observation); err != nil {
		t.Fatal(err)
	}
	observation.Domain = "api.example.com"
	observation.CertificateFingerprint = "aabbcc"
	if err := VerifyRequestUpstream(publicKey, header, observation, now, 5*time.Minute); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if got, want := header.Get(HeaderProfile), RequestUpstreamProfile; got != want {
		t.Fatalf("profile = %q, want %q", got, want)
	}
	if got, want := header.Get(HeaderSignedFields), "tls_certificate_sha256,domain,request.path,request.body.model,request.body.messages,request.body.stream,response.status,response.content_type,challenge"; got != want {
		t.Fatalf("signed fields = %q, want %q", got, want)
	}
	if got := header.Get(HeaderChallenge); got != observation.Challenge {
		t.Fatalf("challenge = %q", got)
	}
	if got := header.Get(HeaderResponseStatus); got != "200" {
		t.Fatalf("response status = %q", got)
	}
	if got := header.Get(HeaderResponseContentType); got != "text/event-stream" {
		t.Fatalf("response content type = %q", got)
	}

	tamperedChallenge := observation
	tamperedChallenge.Challenge = "different_challenge_123"
	if err := VerifyRequestUpstream(publicKey, header, tamperedChallenge, now, 5*time.Minute); err == nil {
		t.Fatal("expected changed challenge to fail verification")
	}
	tamperedStatus := observation
	tamperedStatus.ResponseStatus = http.StatusAccepted
	if err := VerifyRequestUpstream(publicKey, header, tamperedStatus, now, 5*time.Minute); err == nil {
		t.Fatal("expected changed response status to fail verification")
	}
	tamperedFields := observation
	tamperedFields.RequestFields = append([]Field(nil), requestFields...)
	tamperedFields.RequestFields[2] = mustField(t, "stream", `false`)
	if err := VerifyRequestUpstream(publicKey, header, tamperedFields, now, 5*time.Minute); err == nil {
		t.Fatal("expected changed request field to fail verification")
	}
}

func TestSignRequestUpstreamRejectsInvalidChallenge(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(privateKey, "demo-key")
	observation := RequestUpstreamObservation{
		Domain:                 "api.example.com",
		CertificateFingerprint: "aabbcc",
		RequestPath:            "/v1/chat/completions",
		RequestFields:          []Field{mustField(t, "stream", `true`)},
		Challenge:              "contains spaces",
		ResponseStatus:         http.StatusOK,
		ResponseContentType:    "text/event-stream",
	}
	if err := signer.SignRequestUpstream(make(http.Header), observation); err == nil {
		t.Fatal("expected invalid challenge to be rejected")
	}
}

func TestSignRejectsNonStringOrUnsafeModelHeader(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewSigner(privateKey, "demo-key")
	responseFields := []Field{mustField(t, "message", `"world"`)}
	for name, value := range map[string]string{
		"non-string":  `123`,
		"newline":     `"model\nname"`,
		"outer space": `" model "`,
	} {
		t.Run(name, func(t *testing.T) {
			requestFields := []Field{mustField(t, "model", value)}
			if err := signer.Sign(make(http.Header), "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields); err == nil {
				t.Fatal("expected model value to be rejected")
			}
		})
	}
}

func TestVerifyRejectsChangedFields(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	signer := NewSigner(privateKey, "demo-key")
	header := make(http.Header)
	requestFields := []Field{mustField(t, "prompt", `"hello"`)}
	responseFields := []Field{mustField(t, "message", `"world"`)}
	if err := signer.Sign(header, "api.example.com", "aabbcc", "/v1/demo", requestFields, responseFields); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		domain, fingerprint, path     string
		requestFields, responseFields []Field
	}{
		"domain":       {"other.example.com", "aabbcc", "/v1/demo", requestFields, responseFields},
		"certificate":  {"api.example.com", "deadbeef", "/v1/demo", requestFields, responseFields},
		"request path": {"api.example.com", "aabbcc", "/v1/other", requestFields, responseFields},
		"request value": {"api.example.com", "aabbcc", "/v1/demo",
			[]Field{mustField(t, "prompt", `"changed"`)}, responseFields},
		"response value": {"api.example.com", "aabbcc", "/v1/demo", requestFields,
			[]Field{mustField(t, "message", `"changed"`)}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Verify(publicKey, header, test.domain, test.fingerprint, test.path, test.requestFields, test.responseFields, now, 5*time.Minute); err == nil {
				t.Fatal("expected verification failure")
			}
		})
	}
}

func TestNewFieldCanonicalizesObjects(t *testing.T) {
	field := mustField(t, "payload", `{ "z": 1, "a": { "b": true } }`)
	if got, want := string(field.Value), `{"a":{"b":true},"z":1}`; got != want {
		t.Fatalf("canonical value = %s, want %s", got, want)
	}
}

func TestNewFieldUsesJCSPrimitiveSerialization(t *testing.T) {
	field := mustField(t, "payload", `{
		"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
		"string": "\u20ac$\u000F\nA'B\"\\\\\"/"
	}`)
	want := `{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	if got := string(field.Value); got != want {
		t.Fatalf("canonical value = %s, want %s", got, want)
	}
}

func TestNewFieldRejectsDuplicateObjectKeys(t *testing.T) {
	if _, err := NewField("payload", []byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate object key to be rejected")
	}
}

func TestNewFieldRejectsValuesOutsideIJSON(t *testing.T) {
	tests := map[string]string{
		"unsafe integer":     `9007199254740992`,
		"unpaired surrogate": `"\ud800\ud800"`,
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewField("payload", []byte(value)); err == nil {
				t.Fatal("expected non-I-JSON value to be rejected")
			}
		})
	}
}

func TestCanonicalPayloadUsesJCSPropertyOrder(t *testing.T) {
	claims := Claims{
		Version:              Version,
		Profile:              Profile,
		KeyID:                "HEADER_KEY_ID",
		TLSCertificateSHA256: "LOWERCASE_HEX",
		Domain:               "api.openai.com",
		RequestPath:          "/v1/demo",
		RequestFields:        []Field{{Name: "prompt", Value: json.RawMessage(`"ACTUAL_PROMPT"`)}},
		ResponseFields:       []Field{{Name: "message", Value: json.RawMessage(`"ACTUAL_MESSAGE"`)}},
		Timestamp:            1_700_000_000,
		Nonce:                "HEADER_NONCE",
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"domain":"api.openai.com","key_id":"HEADER_KEY_ID","nonce":"HEADER_NONCE","profile":"llm-conversation-text-v1","request_fields":[{"name":"prompt","value":"ACTUAL_PROMPT"}],"request_path":"/v1/demo","response_fields":[{"name":"message","value":"ACTUAL_MESSAGE"}],"timestamp":1700000000,"tls_certificate_sha256":"LOWERCASE_HEX","version":"trusted-ai-proxy-v1"}`
	if got := string(payload); got != want {
		t.Fatalf("canonical payload = %s, want %s", got, want)
	}
}

func TestCanonicalRequestUpstreamPayloadUsesSeparateProfile(t *testing.T) {
	claims := Claims{
		Version:              Version,
		Profile:              RequestUpstreamProfile,
		KeyID:                "HEADER_KEY_ID",
		TLSCertificateSHA256: "LOWERCASE_HEX",
		Domain:               "api.openai.com",
		RequestPath:          "/v1/chat/completions",
		RequestFields:        []Field{{Name: "stream", Value: json.RawMessage(`true`)}},
		ResponseFields:       []Field{},
		Timestamp:            1_700_000_000,
		Nonce:                "HEADER_NONCE",
		Challenge:            "customer_challenge_123",
		ResponseStatus:       200,
		ResponseContentType:  "text/event-stream",
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"challenge":"customer_challenge_123","domain":"api.openai.com","key_id":"HEADER_KEY_ID","nonce":"HEADER_NONCE","profile":"llm-request-upstream-v1","request_fields":[{"name":"stream","value":true}],"request_path":"/v1/chat/completions","response_content_type":"text/event-stream","response_fields":[],"response_status":200,"timestamp":1700000000,"tls_certificate_sha256":"LOWERCASE_HEX","version":"trusted-ai-proxy-v1"}`
	if got := string(payload); got != want {
		t.Fatalf("canonical payload = %s, want %s", got, want)
	}
}

func mustField(t *testing.T, path, value string) Field {
	t.Helper()
	field, err := NewField(path, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return field
}
