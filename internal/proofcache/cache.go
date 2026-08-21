// Package proofcache manages the relatively large Confidential Space proof
// packages. The proxy returns the package only from the attestation endpoint;
// business responses carry the short, stable proof reference instead.
package proofcache

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tap/internal/attestation"
)

var ErrProofNotFound = errors.New("attestation proof not found")

type TokenProvider interface {
	Audience() string
	Token(context.Context, []string) (string, error)
}

// Store persists complete proof bundles. Implementations must treat the
// (proof_ref, challenge_nonce) pair as immutable so an archived proof can
// never be silently replaced by a newer attestation token.
type Store interface {
	Find(context.Context, string, string) (Bundle, error)
	Put(context.Context, Bundle) (Bundle, error)
}

type Bundle struct {
	TokenType        string `json:"token_type"`
	AttestationToken string `json:"attestation_token"`
	Audience         string `json:"audience"`
	KeyID            string `json:"key_id"`
	ChallengeNonce   string `json:"challenge_nonce"`
	ProofRef         string `json:"proof_ref"`
	ExpiresAt        int64  `json:"expires_at"`
	AttestationKey   struct {
		Algorithm    string `json:"algorithm"`
		PublicKey    string `json:"public_key"`
		BindingNonce string `json:"binding_nonce"`
	} `json:"attestation_key"`
}

type Cache struct {
	provider  TokenProvider
	publicKey ed25519.PublicKey
	keyID     string
	proofRef  string
	binding   string
	store     Store
}

func New(provider TokenProvider, publicKey ed25519.PublicKey, keyID string, stores ...Store) (*Cache, error) {
	if provider == nil {
		return nil, errors.New("attestation token provider is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("attestation public key is invalid")
	}
	if keyID == "" {
		keyID = attestation.PublicKeyID(publicKey)
	}
	if len(stores) > 1 {
		return nil, errors.New("at most one proof store may be configured")
	}
	var store Store
	if len(stores) == 1 {
		if stores[0] == nil {
			return nil, errors.New("proof store is nil")
		}
		store = stores[0]
	}
	digest := sha256.Sum256(publicKey)
	return &Cache{
		provider:  provider,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		keyID:     keyID,
		proofRef:  "proof-" + base64.RawURLEncoding.EncodeToString(digest[:18]),
		binding:   bindingNonce(publicKey),
		store:     store,
	}, nil
}

func (c *Cache) KeyID() string    { return c.keyID }
func (c *Cache) ProofRef() string { return c.proofRef }

// Preflight proves that the current workload can obtain a fresh Google
// attestation token bound to this cache's public key. The server-generated
// challenge is deliberately discarded: customers must still request a proof
// using their own challenge before trusting the key.
func (c *Cache) Preflight(ctx context.Context) error {
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate startup attestation challenge: %w", err)
	}
	challenge := "startup_" + base64.RawURLEncoding.EncodeToString(random)
	if _, _, err := c.requestToken(ctx, challenge); err != nil {
		return fmt.Errorf("obtain startup workload attestation: %w", err)
	}
	return nil
}

func (c *Cache) Issue(ctx context.Context, challenge string) (Bundle, error) {
	if strings.TrimSpace(challenge) == "" {
		return Bundle{}, errors.New("challenge is required")
	}
	if c.store != nil {
		bundle, err := c.store.Find(ctx, c.proofRef, challenge)
		if err == nil {
			return bundle, nil
		}
		if !errors.Is(err, ErrProofNotFound) {
			return Bundle{}, fmt.Errorf("load persisted attestation proof: %w", err)
		}
	}
	token, expiresAt, err := c.requestToken(ctx, challenge)
	if err != nil {
		return Bundle{}, err
	}
	bundle := c.bundle(challenge, token, expiresAt)
	if c.store != nil {
		bundle, err = c.store.Put(ctx, bundle)
		if err != nil {
			return Bundle{}, fmt.Errorf("persist attestation proof: %w", err)
		}
	}
	return bundle, nil
}

func (c *Cache) requestToken(ctx context.Context, challenge string) (string, time.Time, error) {
	token, err := c.provider.Token(ctx, []string{challenge, c.binding})
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt, err := tokenExpiry(token)
	if err != nil {
		return "", time.Time{}, err
	}
	if !expiresAt.After(time.Now()) {
		return "", time.Time{}, errors.New("attestation token is already expired")
	}
	return token, expiresAt, nil
}

// Find returns an already-issued proof, including an expired historical
// proof. It never asks the attestation provider to mint a new token.
func (c *Cache) Find(ctx context.Context, proofRef, challenge string) (Bundle, error) {
	if strings.TrimSpace(proofRef) == "" || strings.TrimSpace(challenge) == "" {
		return Bundle{}, ErrProofNotFound
	}
	if c.store == nil {
		return Bundle{}, ErrProofNotFound
	}
	bundle, err := c.store.Find(ctx, proofRef, challenge)
	if err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (c *Cache) Apply(header http.Header) {
	header.Set(attestation.HeaderProofReference, c.proofRef)
}

func (c *Cache) bundle(challenge, token string, expiresAt time.Time) Bundle {
	return Bundle{
		TokenType:        "OIDC",
		AttestationToken: token,
		Audience:         c.provider.Audience(),
		KeyID:            c.keyID,
		ChallengeNonce:   challenge,
		ProofRef:         c.proofRef,
		ExpiresAt:        expiresAt.Unix(),
		AttestationKey: struct {
			Algorithm    string `json:"algorithm"`
			PublicKey    string `json:"public_key"`
			BindingNonce string `json:"binding_nonce"`
		}{
			Algorithm:    attestation.Algorithm,
			PublicKey:    base64.RawURLEncoding.EncodeToString(c.publicKey),
			BindingNonce: c.binding,
		},
	}
}

func bindingNonce(publicKey ed25519.PublicKey) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("attestation-ed25519-public-key-v1"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func tokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("attestation token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode attestation token claims: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, errors.New("attestation token has no valid exp claim")
	}
	return time.Unix(claims.Exp, 0), nil
}
