package proofcache

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"tap/internal/attestation"
)

type fakeStore struct {
	mu      sync.Mutex
	bundles map[string]Bundle
}

type failingStore struct{ err error }

func (s failingStore) Find(context.Context, string, string) (Bundle, error) {
	return Bundle{}, ErrProofNotFound
}

func (s failingStore) Put(context.Context, Bundle) (Bundle, error) {
	return Bundle{}, s.err
}

func newFakeStore() *fakeStore {
	return &fakeStore{bundles: make(map[string]Bundle)}
}

func proofStoreKey(proofRef, challenge string) string { return proofRef + "\x00" + challenge }

func (s *fakeStore) Find(_ context.Context, proofRef, challenge string) (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, ok := s.bundles[proofStoreKey(proofRef, challenge)]
	if !ok {
		return Bundle{}, ErrProofNotFound
	}
	return bundle, nil
}

func (s *fakeStore) Put(_ context.Context, bundle Bundle) (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := proofStoreKey(bundle.ProofRef, bundle.ChallengeNonce)
	if existing, ok := s.bundles[key]; ok {
		return existing, nil
	}
	s.bundles[key] = bundle
	return bundle, nil
}

type fakeProvider struct {
	calls  int
	nonces [][]string
}

type failingProvider struct{ err error }

func (p failingProvider) Audience() string { return "test-audience" }
func (p failingProvider) Token(context.Context, []string) (string, error) {
	return "", p.err
}

func (p *fakeProvider) Audience() string { return "test-audience" }
func (p *fakeProvider) Token(_ context.Context, nonces []string) (string, error) {
	p.calls++
	p.nonces = append(p.nonces, append([]string(nil), nonces...))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	return "header." + payload + ".signature", nil
}

func TestPreflightBindsFreshStartupChallengeWithoutPersistence(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	store := newFakeStore()
	cache, err := New(provider, publicKey, "replica-key", store)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || len(provider.nonces) != 1 || len(provider.nonces[0]) != 2 {
		t.Fatalf("provider calls/nonces = %d/%v", provider.calls, provider.nonces)
	}
	challenge := provider.nonces[0][0]
	if !strings.HasPrefix(challenge, "startup_") || attestation.ValidateChallenge(challenge) != nil {
		t.Fatalf("invalid startup challenge %q", challenge)
	}
	if provider.nonces[0][1] != cache.binding {
		t.Fatal("startup attestation did not bind the cache public key")
	}
	if len(store.bundles) != 0 {
		t.Fatal("startup preflight must not persist a server-generated challenge")
	}
}

func TestPreflightFailsClosedWhenAttestationIsUnavailable(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("launcher unavailable")
	cache, err := New(failingProvider{err: want}, publicKey, "replica-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Preflight(context.Background()); !errors.Is(err, want) {
		t.Fatalf("preflight error = %v, want %v", err, want)
	}
}

func TestIssueWithoutStoreDoesNotCacheAndUsesShortReference(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}
	cache, err := New(provider, publicKey, "replica-key")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.Issue(context.Background(), "customer-challenge")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Issue(context.Background(), "customer-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 2 {
		t.Fatalf("provider calls = %d, want 2 without a proof store", provider.calls)
	}
	if first.ProofRef == "" || first.ProofRef != second.ProofRef || len(first.ProofRef) > 64 {
		t.Fatalf("unexpected proof reference: %q", first.ProofRef)
	}
	if first.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("proof expiry = %d", first.ExpiresAt)
	}
	header := make(http.Header)
	cache.Apply(header)
	if header.Get(attestation.HeaderProofReference) != first.ProofRef {
		t.Fatal("response proof reference does not match issued proof")
	}
}

func TestIssueLoadsPersistedProofAfterRestart(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeStore()
	firstProvider := &fakeProvider{}
	firstCache, err := New(firstProvider, publicKey, "replica-key", store)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := firstCache.Issue(context.Background(), "persistent-challenge")
	if err != nil {
		t.Fatal(err)
	}

	secondProvider := &fakeProvider{}
	secondCache, err := New(secondProvider, publicKey, "changed-label", store)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := secondCache.Issue(context.Background(), "persistent-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if secondProvider.calls != 0 {
		t.Fatalf("provider called %d times while persisted proof existed", secondProvider.calls)
	}
	if restored != issued {
		t.Fatalf("restored proof differs from issued proof: %#v != %#v", restored, issued)
	}
	restoredAgain, err := secondCache.Issue(context.Background(), "persistent-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if restoredAgain != issued {
		t.Fatalf("reloaded historical proof differs from issued proof: %#v != %#v", restoredAgain, issued)
	}
}

func TestFindHistoricalProofByReference(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeStore()
	oldCache, err := New(&fakeProvider{}, publicKey, "old-key", store)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := oldCache.Issue(context.Background(), "historical-challenge")
	if err != nil {
		t.Fatal(err)
	}

	newPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentCache, err := New(&fakeProvider{}, newPublicKey, "new-key", store)
	if err != nil {
		t.Fatal(err)
	}
	found, err := currentCache.Find(context.Background(), issued.ProofRef, issued.ChallengeNonce)
	if err != nil {
		t.Fatal(err)
	}
	if found != issued {
		t.Fatalf("historical proof differs from issued proof: %#v != %#v", found, issued)
	}
}

func TestIssueDoesNotReturnUnpersistedProof(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := New(&fakeProvider{}, publicKey, "replica-key", failingStore{err: fmt.Errorf("database unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Issue(context.Background(), "durability-challenge"); err == nil {
		t.Fatal("expected proof issuance to fail when persistence fails")
	}
}
