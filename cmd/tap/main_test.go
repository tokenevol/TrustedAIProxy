package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tap/internal/proofcache"
)

func TestLoadProxyConfig(t *testing.T) {
	path := writeConfig(t, `{
		"paths":{"/openai/deployments/{deployment}/chat/completions":{"extractor":"openai-chat-conversation-v1"}}
	}`)
	config, err := loadProxyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := config.PathRules.Match("/openai/deployments/production/chat/completions")
	if !ok {
		t.Fatal("expected template path to match")
	}
	if got := rule.Extractor; got != "openai-chat-conversation-v1" {
		t.Fatalf("extractor = %q", got)
	}
}

func TestRepositorySigningRulesLoad(t *testing.T) {
	config, err := loadProxyConfig(filepath.Join("..", "..", "signing-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := config.PathRules.Len(), 9; got != want {
		t.Fatalf("repository signing rule count = %d, want %d", got, want)
	}
}

type fakeTokenProvider struct {
	nonces []string
}

func (p *fakeTokenProvider) Audience() string { return "tap-test" }

func (p *fakeTokenProvider) Token(_ context.Context, nonces []string) (string, error) {
	p.nonces = append([]string(nil), nonces...)
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	return "header." + payload + ".signature", nil
}

func testProofCache(t *testing.T, publicKey ed25519.PublicKey, provider *fakeTokenProvider) *proofcache.Cache {
	t.Helper()
	proofs, err := proofcache.New(provider, publicKey, "demo-key")
	if err != nil {
		t.Fatal(err)
	}
	return proofs
}

func TestConfidentialAttestationBindsChallengeAndKey(t *testing.T) {
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	provider := &fakeTokenProvider{}
	handler := metadataHandler(publicKey, "demo-key", testProofCache(t, publicKey, provider), nil)
	request := httptest.NewRequest(http.MethodGet, "/.well-known/confidential-attestation?nonce=customer_challenge_123", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(provider.nonces) != 2 || provider.nonces[0] != "customer_challenge_123" {
		t.Fatalf("token nonces = %v", provider.nonces)
	}
	var result struct {
		AttestationKey struct {
			BindingNonce string `json:"binding_nonce"`
		} `json:"attestation_key"`
		MITMCA json.RawMessage `json:"mitm_ca"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.AttestationKey.BindingNonce != provider.nonces[1] {
		t.Fatal("returned key binding does not match token nonce")
	}
	if result.MITMCA != nil {
		t.Fatal("customer attestation package exposed the internal MITM CA")
	}
}

func TestMetadataDoesNotExposeInternalMITMCA(t *testing.T) {
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	handler := metadataHandler(publicKey, "demo-key", testProofCache(t, publicKey, &fakeTokenProvider{}), nil)
	request := httptest.NewRequest(http.MethodGet, "/ca.pem", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestValidProofReference(t *testing.T) {
	for _, proofRef := range []string{
		"proof-abcdefghijklmnopqrstuvwx",
		"proof-0123456789_-ABCDEFGHIJKL",
	} {
		if !validProofReference(proofRef) {
			t.Fatalf("valid proof reference rejected: %q", proofRef)
		}
	}
	for _, proofRef := range []string{"", "proof-short", "key-abcdefghijklmnopqrstuvwx", "proof-abcdefghijklmnopqrstuvw!"} {
		if validProofReference(proofRef) {
			t.Fatalf("invalid proof reference accepted: %q", proofRef)
		}
	}
}

func TestPostgresDSNSecretRejectsDirectConfiguration(t *testing.T) {
	t.Setenv(postgresDSNSecretVersionEnv, "projects/example-project/secrets/postgres-dsn/versions/1")
	t.Setenv("TAP_PG_DSN", "postgres://legacy")
	if _, configured, err := openPostgresProofStore(context.Background()); err == nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
}

func TestPostgresDSNSecretRejectsBothBrandPrefixes(t *testing.T) {
	t.Setenv(postgresDSNSecretVersionEnv, "projects/example-project/secrets/postgres-dsn/versions/1")
	t.Setenv(legacyPostgresDSNSecretVersionEnv, "projects/example-project/secrets/postgres-dsn/versions/2")
	if _, configured, err := openPostgresProofStore(context.Background()); err == nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
}

func TestLoadProxyConfigRejectsUnsafeEntries(t *testing.T) {
	tests := map[string]string{
		"empty paths":           `{"paths":{}}`,
		"invalid path":          `{"paths":{"v1?x=1":{"extractor":"openai-chat-conversation-v1"}}}`,
		"missing extractor":     `{"paths":{"/v1":{}}}`,
		"unknown extractor":     `{"paths":{"/v1":{"extractor":"unknown-v1"}}}`,
		"legacy field rules":    `{"paths":{"/v1":{"request_fields":["a"],"response_fields":["b"]}}}`,
		"unknown field":         `{"paths":{"/v1":{"extractor":"openai-chat-conversation-v1"}},"extra":true}`,
		"legacy domains":        `{"domains":["api.example.com"],"paths":{"/v1":{"extractor":"openai-chat-conversation-v1"}}}`,
		"invalid template":      `{"paths":{"/users/prefix-{name}":{"extractor":"openai-chat-conversation-v1"}}}`,
		"conflicting templates": `{"paths":{"/users/{id}":{"extractor":"openai-chat-conversation-v1"},"/users/{name}":{"extractor":"openai-chat-conversation-v1"}}}`,
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadProxyConfig(writeConfig(t, config)); err == nil {
				t.Fatal("expected config to be rejected")
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing-rules.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
