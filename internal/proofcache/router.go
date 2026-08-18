package proofcache

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrReplicaNotFound       = errors.New("attestation replica not found")
	ErrProofOwnerUnavailable = errors.New("attestation proof owner is unavailable")
	ErrProofRequestFailed    = errors.New("attestation proof request failed")
	ErrProofRequestTimeout   = errors.New("attestation proof request timed out")
)

const (
	RequestPending    = "pending"
	RequestProcessing = "processing"
	RequestComplete   = "complete"
	RequestFailed     = "failed"
)

type Replica struct {
	ProofRef      string
	KeyID         string
	InstanceName  string
	LastHeartbeat time.Time
	Draining      bool
}

type ProofRequest struct {
	ProofRef       string
	ChallengeNonce string
	Status         string
	Error          string
	ExpiresAt      time.Time
}

type RoutingStore interface {
	Store
	RegisterReplica(context.Context, Replica) error
	HeartbeatReplica(context.Context, string, string, time.Time) error
	SetReplicaDraining(context.Context, string, string, bool) error
	FindReplica(context.Context, string) (Replica, error)
	EnqueueRequest(context.Context, ProofRequest) error
	ClaimRequests(context.Context, string, time.Time, time.Time, int) ([]ProofRequest, error)
	CompleteRequest(context.Context, string, string) error
	FailRequest(context.Context, string, string, string) error
	FindRequest(context.Context, string, string) (ProofRequest, error)
	DeleteExpiredRequests(context.Context, time.Time) error
}

type RouterOptions struct {
	HeartbeatInterval time.Duration
	StaleAfter        time.Duration
	PollInterval      time.Duration
	RequestTimeout    time.Duration
	RequestTTL        time.Duration
	LeaseDuration     time.Duration
	BatchSize         int
	Logf              func(string, ...any)
}

func DefaultRouterOptions() RouterOptions {
	return RouterOptions{
		HeartbeatInterval: 10 * time.Second,
		StaleAfter:        35 * time.Second,
		PollInterval:      200 * time.Millisecond,
		RequestTimeout:    15 * time.Second,
		RequestTTL:        30 * time.Second,
		LeaseDuration:     20 * time.Second,
		// Attestation token issuance is intentionally serialized per owner. This
		// also avoids claiming more work than can finish within one lease.
		BatchSize: 1,
	}
}

type Router struct {
	cache        *Cache
	store        RoutingStore
	instanceName string
	options      RouterOptions
}

func NewRouter(cache *Cache, store RoutingStore, instanceName string, options RouterOptions) (*Router, error) {
	if cache == nil {
		return nil, errors.New("proof cache is required")
	}
	if store == nil {
		return nil, errors.New("routing store is required")
	}
	if instanceName == "" {
		return nil, errors.New("replica instance name is required")
	}
	if options.HeartbeatInterval <= 0 || options.StaleAfter <= 0 || options.PollInterval <= 0 ||
		options.RequestTimeout <= 0 || options.RequestTTL <= 0 || options.LeaseDuration <= 0 || options.BatchSize <= 0 {
		return nil, errors.New("router durations and batch size must be positive")
	}
	if options.StaleAfter <= options.HeartbeatInterval {
		return nil, errors.New("router stale interval must exceed heartbeat interval")
	}
	return &Router{cache: cache, store: store, instanceName: instanceName, options: options}, nil
}

func (r *Router) Start(ctx context.Context) error {
	now := time.Now()
	if err := r.store.RegisterReplica(ctx, Replica{
		ProofRef:      r.cache.ProofRef(),
		KeyID:         r.cache.KeyID(),
		InstanceName:  r.instanceName,
		LastHeartbeat: now,
	}); err != nil {
		return fmt.Errorf("register attestation replica: %w", err)
	}
	go r.run(ctx)
	return nil
}

func (r *Router) Drain(ctx context.Context) error {
	return r.store.SetReplicaDraining(ctx, r.cache.ProofRef(), r.instanceName, true)
}

func (r *Router) Resolve(ctx context.Context, proofRef, challenge string) (Bundle, error) {
	if proofRef == r.cache.ProofRef() {
		return r.cache.Issue(ctx, challenge)
	}
	if bundle, err := r.store.Find(ctx, proofRef, challenge); err == nil {
		return bundle, nil
	} else if !errors.Is(err, ErrProofNotFound) {
		return Bundle{}, fmt.Errorf("load routed attestation proof: %w", err)
	}

	replica, err := r.store.FindReplica(ctx, proofRef)
	if errors.Is(err, ErrReplicaNotFound) {
		return Bundle{}, ErrProofNotFound
	}
	if err != nil {
		return Bundle{}, fmt.Errorf("find attestation proof owner: %w", err)
	}
	now := time.Now()
	if replica.Draining || now.Sub(replica.LastHeartbeat) > r.options.StaleAfter {
		return Bundle{}, ErrProofOwnerUnavailable
	}

	request := ProofRequest{
		ProofRef:       proofRef,
		ChallengeNonce: challenge,
		Status:         RequestPending,
		ExpiresAt:      now.Add(r.options.RequestTTL),
	}
	if err := r.store.EnqueueRequest(ctx, request); err != nil {
		return Bundle{}, fmt.Errorf("enqueue attestation proof request: %w", err)
	}

	waitContext, cancel := context.WithTimeout(ctx, r.options.RequestTimeout)
	defer cancel()
	ticker := time.NewTicker(r.options.PollInterval)
	defer ticker.Stop()
	for {
		if bundle, err := r.store.Find(waitContext, proofRef, challenge); err == nil {
			return bundle, nil
		} else if !errors.Is(err, ErrProofNotFound) {
			return Bundle{}, fmt.Errorf("load completed attestation proof: %w", err)
		}
		queued, err := r.store.FindRequest(waitContext, proofRef, challenge)
		if err != nil && !errors.Is(err, ErrProofNotFound) {
			return Bundle{}, fmt.Errorf("load attestation proof request: %w", err)
		}
		if err == nil && queued.Status == RequestFailed {
			return Bundle{}, fmt.Errorf("%w: %s", ErrProofRequestFailed, queued.Error)
		}
		select {
		case <-waitContext.Done():
			if errors.Is(waitContext.Err(), context.DeadlineExceeded) {
				return Bundle{}, ErrProofRequestTimeout
			}
			return Bundle{}, waitContext.Err()
		case <-ticker.C:
		}
	}
}

func (r *Router) run(ctx context.Context) {
	heartbeat := time.NewTicker(r.options.HeartbeatInterval)
	poll := time.NewTicker(r.options.PollInterval)
	defer heartbeat.Stop()
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			drainContext, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = r.Drain(drainContext)
			cancel()
			return
		case now := <-heartbeat.C:
			if err := r.store.HeartbeatReplica(ctx, r.cache.ProofRef(), r.instanceName, now); err != nil {
				r.logf("heartbeat attestation replica: %v", err)
			}
			if err := r.store.DeleteExpiredRequests(ctx, now); err != nil {
				r.logf("delete expired attestation proof requests: %v", err)
			}
		case now := <-poll.C:
			r.processPending(ctx, now)
		}
	}
}

func (r *Router) processPending(ctx context.Context, now time.Time) {
	requests, err := r.store.ClaimRequests(
		ctx,
		r.cache.ProofRef(),
		now,
		now.Add(r.options.LeaseDuration),
		r.options.BatchSize,
	)
	if err != nil {
		r.logf("claim attestation proof requests: %v", err)
		return
	}
	for _, request := range requests {
		issueContext, cancel := context.WithTimeout(ctx, r.options.RequestTimeout)
		_, issueErr := r.cache.Issue(issueContext, request.ChallengeNonce)
		cancel()
		if issueErr != nil {
			if err := r.store.FailRequest(ctx, request.ProofRef, request.ChallengeNonce, issueErr.Error()); err != nil {
				r.logf("record failed attestation proof request: %v", err)
			}
			continue
		}
		if err := r.store.CompleteRequest(ctx, request.ProofRef, request.ChallengeNonce); err != nil {
			r.logf("complete attestation proof request: %v", err)
		}
	}
}

func (r *Router) logf(format string, args ...any) {
	if r.options.Logf != nil {
		r.options.Logf(format, args...)
	}
}
