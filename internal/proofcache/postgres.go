package proofcache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const (
	postgresDSNEnv      = "TAP_PG_DSN"
	postgresHostEnv     = "TAP_PG_HOST"
	postgresPortEnv     = "TAP_PG_PORT"
	postgresUserEnv     = "TAP_PG_USER"
	postgresPasswordEnv = "TAP_PG_PASSWORD"
	postgresDatabaseEnv = "TAP_PG_DATABASE"
	postgresSSLModeEnv  = "TAP_PG_SSLMODE"

	legacyPostgresDSNEnv      = "TRUSTED_PROXY_PG_DSN"
	legacyPostgresHostEnv     = "TRUSTED_PROXY_PG_HOST"
	legacyPostgresPortEnv     = "TRUSTED_PROXY_PG_PORT"
	legacyPostgresUserEnv     = "TRUSTED_PROXY_PG_USER"
	legacyPostgresPasswordEnv = "TRUSTED_PROXY_PG_PASSWORD"
	legacyPostgresDatabaseEnv = "TRUSTED_PROXY_PG_DATABASE"
	legacyPostgresSSLModeEnv  = "TRUSTED_PROXY_PG_SSLMODE"
)

type postgresEnvironment struct {
	dsn, host, port, user, password, database, sslMode string
}

var (
	tapPostgresEnvironment = postgresEnvironment{
		dsn: postgresDSNEnv, host: postgresHostEnv, port: postgresPortEnv,
		user: postgresUserEnv, password: postgresPasswordEnv,
		database: postgresDatabaseEnv, sslMode: postgresSSLModeEnv,
	}
	legacyPostgresEnvironment = postgresEnvironment{
		dsn: legacyPostgresDSNEnv, host: legacyPostgresHostEnv, port: legacyPostgresPortEnv,
		user: legacyPostgresUserEnv, password: legacyPostgresPasswordEnv,
		database: legacyPostgresDatabaseEnv, sslMode: legacyPostgresSSLModeEnv,
	}
)

type proofRecord struct {
	ID               uint64    `gorm:"primaryKey"`
	ProofRef         string    `gorm:"size:64;not null;uniqueIndex:idx_proof_challenge"`
	ChallengeNonce   string    `gorm:"size:74;not null;uniqueIndex:idx_proof_challenge"`
	TokenType        string    `gorm:"size:16;not null"`
	AttestationToken string    `gorm:"type:text;not null"`
	Audience         string    `gorm:"type:text;not null"`
	KeyID            string    `gorm:"size:128;not null"`
	Algorithm        string    `gorm:"size:32;not null"`
	PublicKey        string    `gorm:"size:64;not null"`
	BindingNonce     string    `gorm:"size:64;not null"`
	ExpiresAt        time.Time `gorm:"not null;index"`
	CreatedAt        time.Time `gorm:"not null"`
}

func (proofRecord) TableName() string { return "attestation_proofs" }

type replicaRecord struct {
	ProofRef      string    `gorm:"size:64;primaryKey"`
	KeyID         string    `gorm:"size:128;not null"`
	InstanceName  string    `gorm:"type:text;not null"`
	LastHeartbeat time.Time `gorm:"not null;index"`
	Draining      bool      `gorm:"not null;default:false"`
	CreatedAt     time.Time `gorm:"not null"`
	UpdatedAt     time.Time `gorm:"not null"`
}

func (replicaRecord) TableName() string { return "attestation_replicas" }

type proofRequestRecord struct {
	ProofRef       string     `gorm:"size:64;primaryKey"`
	ChallengeNonce string     `gorm:"size:74;primaryKey"`
	Status         string     `gorm:"size:16;not null;index"`
	Error          string     `gorm:"type:text"`
	RequestedAt    time.Time  `gorm:"not null;index"`
	ExpiresAt      time.Time  `gorm:"not null;index"`
	LeaseUntil     *time.Time `gorm:"index"`
	Attempts       uint       `gorm:"not null;default:0"`
	CompletedAt    *time.Time
	UpdatedAt      time.Time `gorm:"not null"`
}

func (proofRequestRecord) TableName() string { return "attestation_requests" }

type PostgresStore struct {
	db *gorm.DB
}

// OpenPostgresFromEnv opens and migrates the proof database when PostgreSQL
// environment variables are present. It returns configured=false when none
// are set, preserving the non-persistent mode.
func OpenPostgresFromEnv(ctx context.Context) (*PostgresStore, bool, error) {
	dsn, configured, err := postgresDSNFromEnv()
	return openPostgres(ctx, dsn, configured, err)
}

// OpenPostgresFromDSN opens PostgreSQL using a DSN obtained from a secret
// provider. The DSN is passed directly to the driver and is never copied into
// the process environment.
func OpenPostgresFromDSN(ctx context.Context, dsn string) (*PostgresStore, bool, error) {
	dsn, configured, err := postgresDSNFromSecret(dsn)
	return openPostgres(ctx, dsn, configured, err)
}

func openPostgres(ctx context.Context, dsn string, configured bool, configErr error) (*PostgresStore, bool, error) {
	if configErr != nil || !configured {
		return nil, configured, configErr
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, true, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, true, fmt.Errorf("access PostgreSQL connection pool: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, true, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	if err := db.WithContext(ctx).AutoMigrate(&proofRecord{}, &replicaRecord{}, &proofRequestRecord{}); err != nil {
		_ = sqlDB.Close()
		return nil, true, fmt.Errorf("migrate PostgreSQL attestation tables: %w", err)
	}
	return &PostgresStore{db: db}, true, nil
}

func (s *PostgresStore) Find(ctx context.Context, proofRef, challenge string) (Bundle, error) {
	var record proofRecord
	err := s.db.WithContext(ctx).
		Where("proof_ref = ? AND challenge_nonce = ?", proofRef, challenge).
		Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Bundle{}, ErrProofNotFound
	}
	if err != nil {
		return Bundle{}, err
	}
	return record.bundle(), nil
}

func (s *PostgresStore) Put(ctx context.Context, bundle Bundle) (Bundle, error) {
	record := recordFromBundle(bundle)
	result := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "proof_ref"}, {Name: "challenge_nonce"}},
		DoNothing: true,
	}).Create(&record)
	if result.Error != nil {
		return Bundle{}, result.Error
	}
	return s.Find(ctx, bundle.ProofRef, bundle.ChallengeNonce)
}

func (s *PostgresStore) RegisterReplica(ctx context.Context, replica Replica) error {
	record := replicaRecord{
		ProofRef:      replica.ProofRef,
		KeyID:         replica.KeyID,
		InstanceName:  replica.InstanceName,
		LastHeartbeat: replica.LastHeartbeat,
		Draining:      replica.Draining,
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "proof_ref"}},
		DoUpdates: clause.Assignments(map[string]any{
			"key_id":         record.KeyID,
			"instance_name":  record.InstanceName,
			"last_heartbeat": record.LastHeartbeat,
			"draining":       record.Draining,
			"updated_at":     time.Now(),
		}),
	}).Create(&record).Error
}

func (s *PostgresStore) HeartbeatReplica(ctx context.Context, proofRef, instanceName string, now time.Time) error {
	result := s.db.WithContext(ctx).Model(&replicaRecord{}).
		Where("proof_ref = ? AND instance_name = ?", proofRef, instanceName).
		Updates(map[string]any{"last_heartbeat": now, "draining": false, "updated_at": now})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrReplicaNotFound
	}
	return nil
}

func (s *PostgresStore) SetReplicaDraining(ctx context.Context, proofRef, instanceName string, draining bool) error {
	result := s.db.WithContext(ctx).Model(&replicaRecord{}).
		Where("proof_ref = ? AND instance_name = ?", proofRef, instanceName).
		Updates(map[string]any{"draining": draining, "updated_at": time.Now()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrReplicaNotFound
	}
	return nil
}

func (s *PostgresStore) FindReplica(ctx context.Context, proofRef string) (Replica, error) {
	var record replicaRecord
	err := s.db.WithContext(ctx).Where("proof_ref = ?", proofRef).Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Replica{}, ErrReplicaNotFound
	}
	if err != nil {
		return Replica{}, err
	}
	return Replica{
		ProofRef:      record.ProofRef,
		KeyID:         record.KeyID,
		InstanceName:  record.InstanceName,
		LastHeartbeat: record.LastHeartbeat,
		Draining:      record.Draining,
	}, nil
}

func (s *PostgresStore) EnqueueRequest(ctx context.Context, request ProofRequest) error {
	record := proofRequestRecord{
		ProofRef:       request.ProofRef,
		ChallengeNonce: request.ChallengeNonce,
		Status:         RequestPending,
		RequestedAt:    time.Now(),
		ExpiresAt:      request.ExpiresAt,
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "proof_ref"}, {Name: "challenge_nonce"}},
		DoNothing: true,
	}).Create(&record).Error
}

func (s *PostgresStore) ClaimRequests(ctx context.Context, proofRef string, now, leaseUntil time.Time, limit int) ([]ProofRequest, error) {
	var records []proofRequestRecord
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"proof_ref = ? AND expires_at > ? AND (status = ? OR (status = ? AND lease_until < ?))",
				proofRef, now, RequestPending, RequestProcessing, now,
			).
			Order("requested_at ASC").
			Limit(limit).
			Find(&records).Error; err != nil {
			return err
		}
		for index := range records {
			records[index].Status = RequestProcessing
			records[index].LeaseUntil = &leaseUntil
			records[index].Attempts++
			if err := tx.Model(&proofRequestRecord{}).
				Where("proof_ref = ? AND challenge_nonce = ?", records[index].ProofRef, records[index].ChallengeNonce).
				Updates(map[string]any{
					"status":      RequestProcessing,
					"lease_until": leaseUntil,
					"attempts":    records[index].Attempts,
					"updated_at":  now,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	requests := make([]ProofRequest, 0, len(records))
	for _, record := range records {
		requests = append(requests, proofRequestFromRecord(record))
	}
	return requests, nil
}

func (s *PostgresStore) CompleteRequest(ctx context.Context, proofRef, challenge string) error {
	now := time.Now()
	return s.db.WithContext(ctx).Model(&proofRequestRecord{}).
		Where("proof_ref = ? AND challenge_nonce = ?", proofRef, challenge).
		Updates(map[string]any{
			"status":       RequestComplete,
			"error":        "",
			"lease_until":  nil,
			"completed_at": now,
			"updated_at":   now,
		}).Error
}

func (s *PostgresStore) FailRequest(ctx context.Context, proofRef, challenge, message string) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	return s.db.WithContext(ctx).Model(&proofRequestRecord{}).
		Where("proof_ref = ? AND challenge_nonce = ?", proofRef, challenge).
		Updates(map[string]any{
			"status":      RequestFailed,
			"error":       message,
			"lease_until": nil,
			"updated_at":  time.Now(),
		}).Error
}

func (s *PostgresStore) FindRequest(ctx context.Context, proofRef, challenge string) (ProofRequest, error) {
	var record proofRequestRecord
	err := s.db.WithContext(ctx).
		Where("proof_ref = ? AND challenge_nonce = ?", proofRef, challenge).
		Take(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ProofRequest{}, ErrProofNotFound
	}
	if err != nil {
		return ProofRequest{}, err
	}
	return proofRequestFromRecord(record), nil
}

func (s *PostgresStore) DeleteExpiredRequests(ctx context.Context, now time.Time) error {
	return s.db.WithContext(ctx).
		Where("expires_at <= ?", now).
		Delete(&proofRequestRecord{}).Error
}

func proofRequestFromRecord(record proofRequestRecord) ProofRequest {
	return ProofRequest{
		ProofRef:       record.ProofRef,
		ChallengeNonce: record.ChallengeNonce,
		Status:         record.Status,
		Error:          record.Error,
		ExpiresAt:      record.ExpiresAt,
	}
}

func recordFromBundle(bundle Bundle) proofRecord {
	return proofRecord{
		ProofRef:         bundle.ProofRef,
		ChallengeNonce:   bundle.ChallengeNonce,
		TokenType:        bundle.TokenType,
		AttestationToken: bundle.AttestationToken,
		Audience:         bundle.Audience,
		KeyID:            bundle.KeyID,
		Algorithm:        bundle.AttestationKey.Algorithm,
		PublicKey:        bundle.AttestationKey.PublicKey,
		BindingNonce:     bundle.AttestationKey.BindingNonce,
		ExpiresAt:        time.Unix(bundle.ExpiresAt, 0),
	}
}

func (r proofRecord) bundle() Bundle {
	bundle := Bundle{
		TokenType:        r.TokenType,
		AttestationToken: r.AttestationToken,
		Audience:         r.Audience,
		KeyID:            r.KeyID,
		ChallengeNonce:   r.ChallengeNonce,
		ProofRef:         r.ProofRef,
		ExpiresAt:        r.ExpiresAt.Unix(),
	}
	bundle.AttestationKey.Algorithm = r.Algorithm
	bundle.AttestationKey.PublicKey = r.PublicKey
	bundle.AttestationKey.BindingNonce = r.BindingNonce
	return bundle
}

func postgresDSNFromEnv() (string, bool, error) {
	return postgresDSNFromEnvironment()
}

func postgresDSNFromSecret(dsn string) (string, bool, error) {
	if strings.TrimSpace(dsn) == "" {
		return "", true, fmt.Errorf("PostgreSQL DSN secret is empty")
	}
	if strings.ContainsAny(dsn, "\x00\r\n") {
		return "", true, fmt.Errorf("PostgreSQL DSN secret must not contain NUL or line-break characters")
	}
	return dsn, true, nil
}

func postgresDSNFromEnvironment() (string, bool, error) {
	tapConfigured := postgresEnvironmentConfigured(tapPostgresEnvironment)
	legacyConfigured := postgresEnvironmentConfigured(legacyPostgresEnvironment)
	if tapConfigured && legacyConfigured {
		return "", true, fmt.Errorf("TAP_PG_* and deprecated TRUSTED_PROXY_PG_* variables cannot be combined")
	}
	if legacyConfigured {
		return postgresDSNFromEnvironmentNames(legacyPostgresEnvironment)
	}
	return postgresDSNFromEnvironmentNames(tapPostgresEnvironment)
}

func postgresEnvironmentConfigured(names postgresEnvironment) bool {
	for _, name := range []string{names.dsn, names.host, names.port, names.user, names.password, names.database, names.sslMode} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

func postgresDSNFromEnvironmentNames(names postgresEnvironment) (string, bool, error) {
	if dsn := strings.TrimSpace(os.Getenv(names.dsn)); dsn != "" {
		return dsn, true, nil
	}
	envNames := []string{
		names.host, names.port, names.user, names.password, names.database, names.sslMode,
	}
	configured := false
	for _, name := range envNames {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			configured = true
			break
		}
	}
	if !configured {
		return "", false, nil
	}
	host := strings.TrimSpace(os.Getenv(names.host))
	user := strings.TrimSpace(os.Getenv(names.user))
	database := strings.TrimSpace(os.Getenv(names.database))
	if host == "" || user == "" || database == "" {
		return "", true, fmt.Errorf("%s, %s, and %s are required when PostgreSQL persistence is configured", names.host, names.user, names.database)
	}
	port := strings.TrimSpace(os.Getenv(names.port))
	if port == "" {
		port = "5432"
	}
	sslMode := strings.TrimSpace(os.Getenv(names.sslMode))
	if sslMode == "" {
		sslMode = "require"
	}
	connectionURL := &url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(host, port),
		Path:   database,
	}
	password := os.Getenv(names.password)
	if password == "" {
		connectionURL.User = url.User(user)
	} else {
		connectionURL.User = url.UserPassword(user, password)
	}
	query := connectionURL.Query()
	query.Set("sslmode", sslMode)
	connectionURL.RawQuery = query.Encode()
	return connectionURL.String(), true, nil
}
