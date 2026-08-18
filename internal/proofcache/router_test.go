package proofcache

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryRoutingStore struct {
	*fakeStore
	routeMu  sync.Mutex
	replicas map[string]Replica
	requests map[string]ProofRequest
}

func newMemoryRoutingStore() *memoryRoutingStore {
	return &memoryRoutingStore{
		fakeStore: newFakeStore(),
		replicas:  make(map[string]Replica),
		requests:  make(map[string]ProofRequest),
	}
}

func (s *memoryRoutingStore) RegisterReplica(_ context.Context, replica Replica) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.replicas[replica.ProofRef] = replica
	return nil
}

func (s *memoryRoutingStore) HeartbeatReplica(_ context.Context, proofRef, instanceName string, now time.Time) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	replica, ok := s.replicas[proofRef]
	if !ok || replica.InstanceName != instanceName {
		return ErrReplicaNotFound
	}
	replica.LastHeartbeat = now
	replica.Draining = false
	s.replicas[proofRef] = replica
	return nil
}

func (s *memoryRoutingStore) SetReplicaDraining(_ context.Context, proofRef, instanceName string, draining bool) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	replica, ok := s.replicas[proofRef]
	if !ok || replica.InstanceName != instanceName {
		return ErrReplicaNotFound
	}
	replica.Draining = draining
	s.replicas[proofRef] = replica
	return nil
}

func (s *memoryRoutingStore) FindReplica(_ context.Context, proofRef string) (Replica, error) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	replica, ok := s.replicas[proofRef]
	if !ok {
		return Replica{}, ErrReplicaNotFound
	}
	return replica, nil
}

func (s *memoryRoutingStore) EnqueueRequest(_ context.Context, request ProofRequest) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	key := proofStoreKey(request.ProofRef, request.ChallengeNonce)
	if _, ok := s.requests[key]; !ok {
		s.requests[key] = request
	}
	return nil
}

func (s *memoryRoutingStore) ClaimRequests(_ context.Context, proofRef string, now, _ time.Time, limit int) ([]ProofRequest, error) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	claimed := make([]ProofRequest, 0, limit)
	for key, request := range s.requests {
		if len(claimed) == limit {
			break
		}
		if request.ProofRef != proofRef || request.Status != RequestPending || !request.ExpiresAt.After(now) {
			continue
		}
		request.Status = RequestProcessing
		s.requests[key] = request
		claimed = append(claimed, request)
	}
	return claimed, nil
}

func (s *memoryRoutingStore) CompleteRequest(_ context.Context, proofRef, challenge string) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	key := proofStoreKey(proofRef, challenge)
	request := s.requests[key]
	request.Status = RequestComplete
	s.requests[key] = request
	return nil
}

func (s *memoryRoutingStore) FailRequest(_ context.Context, proofRef, challenge, message string) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	key := proofStoreKey(proofRef, challenge)
	request := s.requests[key]
	request.Status = RequestFailed
	request.Error = message
	s.requests[key] = request
	return nil
}

func (s *memoryRoutingStore) FindRequest(_ context.Context, proofRef, challenge string) (ProofRequest, error) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	request, ok := s.requests[proofStoreKey(proofRef, challenge)]
	if !ok {
		return ProofRequest{}, ErrProofNotFound
	}
	return request, nil
}

func (s *memoryRoutingStore) DeleteExpiredRequests(_ context.Context, now time.Time) error {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	for key, request := range s.requests {
		if !request.ExpiresAt.After(now) {
			delete(s.requests, key)
		}
	}
	return nil
}

func testRouterOptions() RouterOptions {
	options := DefaultRouterOptions()
	options.HeartbeatInterval = 10 * time.Millisecond
	options.StaleAfter = 100 * time.Millisecond
	options.PollInterval = 2 * time.Millisecond
	options.RequestTimeout = time.Second
	options.RequestTTL = time.Second
	options.LeaseDuration = 100 * time.Millisecond
	return options
}

func TestRouterIssuesProofOnOwningReplica(t *testing.T) {
	store := newMemoryRoutingStore()
	firstPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secondPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstProvider := &fakeProvider{}
	firstCache, err := New(firstProvider, firstPublicKey, "first-key", store)
	if err != nil {
		t.Fatal(err)
	}
	secondProvider := &fakeProvider{}
	secondCache, err := New(secondProvider, secondPublicKey, "second-key", store)
	if err != nil {
		t.Fatal(err)
	}
	firstRouter, err := NewRouter(firstCache, store, "tap-01", testRouterOptions())
	if err != nil {
		t.Fatal(err)
	}
	secondRouter, err := NewRouter(secondCache, store, "tap-02", testRouterOptions())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := firstRouter.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := secondRouter.Start(ctx); err != nil {
		t.Fatal(err)
	}

	bundle, err := secondRouter.Resolve(ctx, firstCache.ProofRef(), "routed-customer-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ProofRef != firstCache.ProofRef() {
		t.Fatalf("proof ref = %q, want %q", bundle.ProofRef, firstCache.ProofRef())
	}
	if firstProvider.calls != 1 || secondProvider.calls != 0 {
		t.Fatalf("provider calls: first=%d second=%d", firstProvider.calls, secondProvider.calls)
	}
}

func TestRouterRejectsUnknownOrStaleOwner(t *testing.T) {
	store := newMemoryRoutingStore()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := New(&fakeProvider{}, publicKey, "current-key", store)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(cache, store, "tap-01", testRouterOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Resolve(context.Background(), "proof-unknown", "customer-challenge"); !errors.Is(err, ErrProofNotFound) {
		t.Fatalf("unknown owner error = %v", err)
	}
	staleProofRef := "proof-stale"
	if err := store.RegisterReplica(context.Background(), Replica{
		ProofRef:      staleProofRef,
		KeyID:         "stale-key",
		InstanceName:  "tap-old",
		LastHeartbeat: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := router.Resolve(context.Background(), staleProofRef, "customer-challenge"); !errors.Is(err, ErrProofOwnerUnavailable) {
		t.Fatalf("stale owner error = %v", err)
	}
	drainingProofRef := "proof-draining"
	if err := store.RegisterReplica(context.Background(), Replica{
		ProofRef:      drainingProofRef,
		KeyID:         "draining-key",
		InstanceName:  "tap-draining",
		LastHeartbeat: time.Now(),
		Draining:      true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := router.Resolve(context.Background(), drainingProofRef, "customer-challenge"); !errors.Is(err, ErrProofOwnerUnavailable) {
		t.Fatalf("draining owner error = %v", err)
	}
}
