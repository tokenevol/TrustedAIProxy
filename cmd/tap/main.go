package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tap/internal/attestation"
	"tap/internal/gcpattestation"
	"tap/internal/gcpsecret"
	"tap/internal/mitmproxy"
	"tap/internal/proofcache"
)

const (
	postgresDSNSecretVersionEnv       = "TAP_PG_DSN_SECRET_VERSION"
	legacyPostgresDSNSecretVersionEnv = "TRUSTED_PROXY_PG_DSN_SECRET_VERSION"
)

func main() {
	var (
		listen              = flag.String("listen", ":8080", "HTTP/HTTPS proxy listen address")
		configFile          = flag.String("config", "signing-rules.json", "JSON signing rules file")
		caCertFile          = flag.String("ca-cert", "mitm-ca.pem", "MITM CA certificate PEM file")
		caKeyFile           = flag.String("ca-key", "mitm-ca-key.pem", "MITM CA private key PEM file")
		generateMITMCA      = flag.Bool("generate-mitm-ca", false, "create the MITM CA files when absent (local development only)")
		signingKey          = flag.String("signing-key", "attestation-key.pem", "Ed25519 attestation private key PEM file")
		keyID               = flag.String("key-id", "", "attestation public key identifier (defaults to a replica public-key digest)")
		maxJSONBody         = flag.Int64("max-json-bytes", mitmproxy.DefaultMaxJSONBytes, "maximum JSON body size to inspect")
		verbose             = flag.Bool("verbose", false, "enable goproxy request logs")
		attestationSocket   = flag.String("attestation-socket", gcpattestation.DefaultSocketPath, "Confidential Space launcher Unix socket")
		attestationAudience = flag.String("attestation-audience", "tap/customer/v1", "Google attestation token audience")
	)
	flag.Parse()
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyConfig, err := loadProxyConfig(*configFile)
	if err != nil {
		log.Fatalf("load proxy config: %v", err)
	}
	if *maxJSONBody <= 0 {
		log.Fatal("-max-json-bytes must be positive")
	}
	var ca tls.Certificate
	if *generateMITMCA {
		ca, err = mitmproxy.LoadOrCreateCA(*caCertFile, *caKeyFile)
	} else {
		ca, err = mitmproxy.LoadCA(*caCertFile, *caKeyFile)
	}
	if err != nil {
		log.Fatalf("load internal MITM CA: %v (provision a stable CA, or use -generate-mitm-ca for local development)", err)
	}
	privateKey, err := loadOrCreateSigningKey(*signingKey)
	if err != nil {
		log.Fatalf("load attestation signing key: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if *keyID == "" {
		*keyID = attestation.PublicKeyID(publicKey)
	}
	if err := validateKeyID(*keyID); err != nil {
		log.Fatal(err)
	}
	googleAttestation := gcpattestation.New(*attestationSocket, *attestationAudience)
	databaseContext, cancelDatabase := context.WithTimeout(context.Background(), 10*time.Second)
	proofStore, databaseConfigured, err := openPostgresProofStore(databaseContext)
	cancelDatabase()
	if err != nil {
		log.Fatalf("initialize PostgreSQL proof store: %v", err)
	}
	var proofs *proofcache.Cache
	var proofRouter *proofcache.Router
	if databaseConfigured {
		proofs, err = proofcache.New(googleAttestation, publicKey, *keyID, proofStore)
		log.Printf("PostgreSQL proof persistence is enabled")
	} else {
		proofs, err = proofcache.New(googleAttestation, publicKey, *keyID)
		log.Printf("PostgreSQL proof persistence is not configured; historical proof lookup is disabled")
	}
	if err != nil {
		log.Fatalf("initialize attestation proof cache: %v", err)
	}
	if databaseConfigured {
		instanceName, err := os.Hostname()
		if err != nil || strings.TrimSpace(instanceName) == "" {
			log.Fatalf("determine attestation replica name: %v", err)
		}
		routerOptions := proofcache.DefaultRouterOptions()
		routerOptions.Logf = log.Printf
		proofRouter, err = proofcache.NewRouter(proofs, proofStore, instanceName, routerOptions)
		if err != nil {
			log.Fatalf("initialize attestation proof router: %v", err)
		}
		if err := proofRouter.Start(runContext); err != nil {
			log.Fatalf("start attestation proof router: %v", err)
		}
		log.Printf("registered attestation proof owner %s for replica %s", proofs.ProofRef(), instanceName)
	}

	proxy := mitmproxy.New(mitmproxy.Config{
		CA:             ca,
		Signer:         attestation.NewSigner(privateKey, *keyID),
		PathRules:      proxyConfig.PathRules,
		MaxJSONBytes:   *maxJSONBody,
		Verbose:        *verbose,
		ProofReference: proofs.ProofRef(),
	})
	proxy.NonproxyHandler = metadataHandler(publicKey, *keyID, proofs, proofRouter)

	server := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Printf("loaded %d path rules from %s", proxyConfig.PathRules.Len(), *configFile)
	log.Printf("internal proxy listening on %s; internal clients must trust CA certificate %s", *listen, *caCertFile)
	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)
		<-runContext.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if proofRouter != nil {
			if err := proofRouter.Drain(shutdownContext); err != nil && !errors.Is(err, proofcache.ErrReplicaNotFound) {
				log.Printf("mark attestation replica draining: %v", err)
			}
		}
		if err := server.Shutdown(shutdownContext); err != nil {
			log.Printf("shut down proxy server: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	if runContext.Err() != nil {
		<-shutdownComplete
	}
}

func openPostgresProofStore(ctx context.Context) (*proofcache.PostgresStore, bool, error) {
	secretVersion := strings.TrimSpace(os.Getenv(postgresDSNSecretVersionEnv))
	legacySecretVersion := strings.TrimSpace(os.Getenv(legacyPostgresDSNSecretVersionEnv))
	if secretVersion != "" && legacySecretVersion != "" {
		return nil, true, fmt.Errorf("%s cannot be combined with deprecated %s", postgresDSNSecretVersionEnv, legacyPostgresDSNSecretVersionEnv)
	}
	if secretVersion == "" {
		secretVersion = legacySecretVersion
	}
	if secretVersion == "" {
		return proofcache.OpenPostgresFromEnv(ctx)
	}
	directEnvironment := []string{
		"TAP_PG_DSN", "TAP_PG_HOST", "TAP_PG_PORT",
		"TAP_PG_USER", "TAP_PG_PASSWORD",
		"TAP_PG_DATABASE", "TAP_PG_SSLMODE",
		"TRUSTED_PROXY_PG_DSN", "TRUSTED_PROXY_PG_HOST", "TRUSTED_PROXY_PG_PORT",
		"TRUSTED_PROXY_PG_USER", "TRUSTED_PROXY_PG_PASSWORD",
		"TRUSTED_PROXY_PG_DATABASE", "TRUSTED_PROXY_PG_SSLMODE",
	}
	for _, name := range directEnvironment {
		if os.Getenv(name) != "" {
			return nil, true, fmt.Errorf("%s cannot be combined with %s", postgresDSNSecretVersionEnv, name)
		}
	}
	dsn, err := gcpsecret.AccessFixedVersion(ctx, secretVersion)
	if err != nil {
		return nil, true, fmt.Errorf("load PostgreSQL DSN: %w", err)
	}
	return proofcache.OpenPostgresFromDSN(ctx, dsn)
}

func metadataHandler(publicKey ed25519.PublicKey, keyID string, proofs *proofcache.Cache, proofRouter *proofcache.Router) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/http-attestation-key", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The key and proof reference identify one replica. Never let a shared
		// HTTP cache serve one replica's metadata for another replica.
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key_id":     keyID,
			"algorithm":  attestation.Algorithm,
			"public_key": base64.RawURLEncoding.EncodeToString(publicKey),
			"proof_ref":  proofs.ProofRef(),
		})
	})
	mux.HandleFunc("GET /.well-known/confidential-attestation", func(w http.ResponseWriter, request *http.Request) {
		proofRef := request.URL.Query().Get("proof_ref")
		challenge := request.URL.Query().Get("nonce")
		if attestation.ValidateChallenge(challenge) != nil {
			http.Error(w, "nonce must be 10-74 URL-safe ASCII characters", http.StatusBadRequest)
			return
		}
		if proofRef != "" && !validProofReference(proofRef) {
			http.Error(w, "proof_ref is malformed", http.StatusBadRequest)
			return
		}
		var bundle proofcache.Bundle
		var err error
		if proofRef == "" || proofRef == proofs.ProofRef() {
			bundle, err = proofs.Issue(request.Context(), challenge)
		} else if proofRouter != nil {
			bundle, err = proofRouter.Resolve(request.Context(), proofRef, challenge)
		} else {
			bundle, err = proofs.Find(request.Context(), proofRef, challenge)
		}
		if errors.Is(err, proofcache.ErrProofNotFound) {
			http.Error(w, "attestation proof was not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, proofcache.ErrProofOwnerUnavailable) {
			http.Error(w, "attestation proof owner is unavailable", http.StatusGone)
			return
		}
		if err != nil {
			log.Printf("load or issue confidential attestation: %v", err)
			http.Error(w, "confidential attestation is unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(bundle)
	})
	return mux
}

func validProofReference(proofRef string) bool {
	const prefix = "proof-"
	if !strings.HasPrefix(proofRef, prefix) || len(proofRef) != len(prefix)+24 {
		return false
	}
	for _, character := range proofRef[len(prefix):] {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

type proxyConfig struct {
	Paths map[string]mitmproxy.PathRule `json:"paths"`
}

type proxyRuntimeConfig struct {
	PathRules *mitmproxy.CompiledPathRules
}

func loadProxyConfig(path string) (proxyRuntimeConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return proxyRuntimeConfig{}, err
	}
	defer file.Close()
	var config proxyConfig
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return proxyRuntimeConfig{}, fmt.Errorf("decode JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return proxyRuntimeConfig{}, err
	}
	if len(config.Paths) == 0 {
		return proxyRuntimeConfig{}, errors.New("paths must contain at least one signing rule")
	}
	compiledPathRules, err := mitmproxy.CompilePathRules(config.Paths)
	if err != nil {
		return proxyRuntimeConfig{}, err
	}
	for path, rule := range config.Paths {
		if !mitmproxy.IsSupportedExtractor(rule.Extractor) {
			return proxyRuntimeConfig{}, fmt.Errorf("paths[%q].extractor %q is not supported", path, rule.Extractor)
		}
	}
	return proxyRuntimeConfig{PathRules: compiledPathRules}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after proxy config JSON object")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func validateKeyID(keyID string) error {
	if keyID == "" || len(keyID) > 128 {
		return errors.New("-key-id must contain 1 to 128 characters")
	}
	for _, character := range keyID {
		if character < 0x21 || character > 0x7e || character == ',' {
			return errors.New("-key-id may only contain visible ASCII characters except comma")
		}
	}
	return nil
}

func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}
		log.Printf("created attestation signing key %s", path)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid signing key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return key, nil
}
