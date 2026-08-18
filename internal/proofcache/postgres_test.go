package proofcache

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestPostgresStoreIntegration(t *testing.T) {
	dsn := os.Getenv("TAP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TAP_TEST_POSTGRES_DSN is not set")
	}
	clearPostgresEnvironment(t)
	t.Setenv(postgresDSNEnv, dsn)
	store, configured, err := OpenPostgresFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !configured {
		t.Fatal("PostgreSQL should be configured")
	}

	bundle := Bundle{
		TokenType:        "OIDC",
		AttestationToken: "header.payload.signature",
		Audience:         "integration-audience",
		KeyID:            "integration-key",
		ChallengeNonce:   "integration-challenge",
		ProofRef:         "proof-integration-test",
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
	}
	bundle.AttestationKey.Algorithm = "ed25519"
	bundle.AttestationKey.PublicKey = "integration-public-key"
	bundle.AttestationKey.BindingNonce = "integration-binding"

	persisted, err := store.Put(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	found, err := store.Find(context.Background(), bundle.ProofRef, bundle.ChallengeNonce)
	if err != nil {
		t.Fatal(err)
	}
	if persisted != bundle || found != bundle {
		t.Fatalf("persisted=%#v found=%#v want=%#v", persisted, found, bundle)
	}

	replacement := bundle
	replacement.AttestationToken = "different.token.signature"
	unchanged, err := store.Put(context.Background(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != bundle {
		t.Fatalf("immutable proof was overwritten: %#v", unchanged)
	}

	now := time.Now()
	replica := Replica{
		ProofRef:      bundle.ProofRef,
		KeyID:         bundle.KeyID,
		InstanceName:  "integration-replica",
		LastHeartbeat: now,
	}
	if err := store.RegisterReplica(context.Background(), replica); err != nil {
		t.Fatal(err)
	}
	foundReplica, err := store.FindReplica(context.Background(), replica.ProofRef)
	if err != nil {
		t.Fatal(err)
	}
	if foundReplica.InstanceName != replica.InstanceName || foundReplica.KeyID != replica.KeyID {
		t.Fatalf("replica=%#v want=%#v", foundReplica, replica)
	}

	routedChallenge := fmt.Sprintf("integration-routed-%d", now.UnixNano())
	if err := store.EnqueueRequest(context.Background(), ProofRequest{
		ProofRef:       replica.ProofRef,
		ChallengeNonce: routedChallenge,
		ExpiresAt:      now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimRequests(context.Background(), replica.ProofRef, now, now.Add(time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].ChallengeNonce != routedChallenge {
		t.Fatalf("claimed requests = %#v", claimed)
	}
	if err := store.CompleteRequest(context.Background(), replica.ProofRef, routedChallenge); err != nil {
		t.Fatal(err)
	}
	completed, err := store.FindRequest(context.Background(), replica.ProofRef, routedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != RequestComplete {
		t.Fatalf("request status = %q", completed.Status)
	}
	if err := store.DeleteExpiredRequests(context.Background(), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindRequest(context.Background(), replica.ProofRef, routedChallenge); !errors.Is(err, ErrProofNotFound) {
		t.Fatalf("expired request lookup error = %v", err)
	}
}

func TestPostgresDSNFromEnvironmentFields(t *testing.T) {
	clearPostgresEnvironment(t)
	t.Setenv(postgresHostEnv, "db.internal")
	t.Setenv(postgresUserEnv, "proxy user")
	t.Setenv(postgresPasswordEnv, "secret:/?#")
	t.Setenv(postgresDatabaseEnv, "tap")

	dsn, configured, err := postgresDSNFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !configured {
		t.Fatal("PostgreSQL should be configured")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "db.internal:5432" || parsed.Path != "/tap" {
		t.Fatalf("unexpected PostgreSQL URL: %s", parsed.Redacted())
	}
	if parsed.Query().Get("sslmode") != "require" {
		t.Fatalf("sslmode = %q", parsed.Query().Get("sslmode"))
	}
	password, ok := parsed.User.Password()
	if parsed.User.Username() != "proxy user" || !ok || password != "secret:/?#" {
		t.Fatal("PostgreSQL credentials were not encoded correctly")
	}
}

func TestPostgresDSNEnvironmentTakesPrecedence(t *testing.T) {
	clearPostgresEnvironment(t)
	t.Setenv(postgresDSNEnv, "postgres://user:password@db.example/proofs?sslmode=verify-full")
	t.Setenv(postgresHostEnv, "ignored.example")

	dsn, configured, err := postgresDSNFromEnv()
	if err != nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
	if dsn != "postgres://user:password@db.example/proofs?sslmode=verify-full" {
		t.Fatalf("dsn = %q", dsn)
	}
}

func TestLegacyPostgresEnvironmentRemainsSupported(t *testing.T) {
	clearPostgresEnvironment(t)
	want := "postgres://legacy:password@db.example/proofs?sslmode=require"
	t.Setenv(legacyPostgresDSNEnv, want)

	dsn, configured, err := postgresDSNFromEnv()
	if err != nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
	if dsn != want {
		t.Fatalf("dsn = %q, want %q", dsn, want)
	}
}

func TestPostgresEnvironmentRejectsMixedPrefixes(t *testing.T) {
	clearPostgresEnvironment(t)
	t.Setenv(postgresHostEnv, "tap-db.internal")
	t.Setenv(legacyPostgresUserEnv, "legacy-user")

	if _, configured, err := postgresDSNFromEnv(); err == nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
}

func TestPostgresDSNFromSecret(t *testing.T) {
	want := "postgres://tap:secret%3D%2Bvalue@db.internal/proofs?sslmode=require"
	dsn, configured, err := postgresDSNFromSecret(want)
	if err != nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
	if dsn != want {
		t.Fatalf("dsn = %q, want %q", dsn, want)
	}
}

func TestPostgresDSNFromSecretRejectsUnsafeContent(t *testing.T) {
	for _, dsn := range []string{"", " \t", "postgres://db\n"} {
		if _, configured, err := postgresDSNFromSecret(dsn); err == nil || !configured {
			t.Fatalf("dsn=%q configured=%v err=%v", dsn, configured, err)
		}
	}
}

func TestPostgresEnvironmentIsOptional(t *testing.T) {
	clearPostgresEnvironment(t)
	if dsn, configured, err := postgresDSNFromEnv(); err != nil || configured || dsn != "" {
		t.Fatalf("dsn=%q configured=%v err=%v", dsn, configured, err)
	}
}

func TestPostgresEnvironmentRejectsPartialConfiguration(t *testing.T) {
	clearPostgresEnvironment(t)
	t.Setenv(postgresHostEnv, "db.internal")

	if _, configured, err := postgresDSNFromEnv(); err == nil || !configured {
		t.Fatalf("configured=%v err=%v", configured, err)
	}
}

func clearPostgresEnvironment(t *testing.T) {
	t.Helper()
	names := []string{
		postgresDSNEnv, postgresHostEnv, postgresPortEnv, postgresUserEnv,
		postgresPasswordEnv, postgresDatabaseEnv, postgresSSLModeEnv,
		legacyPostgresDSNEnv, legacyPostgresHostEnv, legacyPostgresPortEnv,
		legacyPostgresUserEnv, legacyPostgresPasswordEnv,
		legacyPostgresDatabaseEnv, legacyPostgresSSLModeEnv,
	}
	for _, name := range names {
		value, existed := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		name := name
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}
