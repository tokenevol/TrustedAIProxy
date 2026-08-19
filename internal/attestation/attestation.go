package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	HeaderAlgorithm              = "X-Attestation-Algorithm"
	HeaderProfile                = "X-Attestation-Profile"
	HeaderKeyID                  = "X-Attestation-Key-Id"
	HeaderDomain                 = "X-Attestation-Domain"
	HeaderRequestPath            = "X-Attestation-Path"
	HeaderModel                  = "X-Attestation-Model"
	HeaderCertificateFingerprint = "X-Attestation-Certificate-SHA256"
	HeaderTimestamp              = "X-Attestation-Timestamp"
	HeaderNonce                  = "X-Attestation-Nonce"
	HeaderSignedFields           = "X-Attestation-Signed-Fields"
	HeaderSignature              = "X-Attestation-Signature"
	HeaderProofReference         = "X-Attestation-Proof-Ref"
	HeaderChallenge              = "X-Attestation-Challenge"
	HeaderResponseStatus         = "X-Attestation-Response-Status"
	HeaderResponseContentType    = "X-Attestation-Response-Content-Type"
	Algorithm                    = "ed25519"
	Version                      = "trusted-ai-proxy-v1"
	Profile                      = "llm-conversation-text-v1"
	RequestUpstreamProfile       = "llm-request-upstream-v1"
	maxIJSONSafeInteger          = int64(1<<53 - 1)
)

// PublicKeyID gives each independently generated replica key a stable label.
// The label is only a lookup key; customers must still validate the
// Confidential Space proof bound to the corresponding public key.
func PublicKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519-" + base64.RawURLEncoding.EncodeToString(digest[:18])
}

// Field binds a stable semantic field name to its canonical JSON value.
type Field struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// TextMessage is the protocol-independent representation used by the
// llm-conversation-text-v1 profile. Text block boundaries are intentionally
// collapsed inside a message, while message roles, ordering, and boundaries
// remain covered by the signature.
type TextMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// NewField canonicalizes a semantic field value according to RFC 8785 (JCS).
func NewField(name string, rawValue []byte) (Field, error) {
	if strings.TrimSpace(name) == "" {
		return Field{}, errors.New("semantic field name must not be empty")
	}
	if !utf8.ValidString(name) {
		return Field{}, errors.New("semantic field name must be valid UTF-8")
	}
	canonical, err := canonicalizeJSONValue(rawValue)
	if err != nil {
		return Field{}, fmt.Errorf("canonicalize semantic field %q as JCS: %w", name, err)
	}
	return Field{Name: name, Value: canonical}, nil
}

// Claims is the deterministic semantic text object signed by the proxy.
type Claims struct {
	Version              string  `json:"version"`
	Profile              string  `json:"profile"`
	KeyID                string  `json:"key_id"`
	TLSCertificateSHA256 string  `json:"tls_certificate_sha256"`
	Domain               string  `json:"domain"`
	RequestPath          string  `json:"request_path"`
	RequestFields        []Field `json:"request_fields"`
	ResponseFields       []Field `json:"response_fields"`
	Timestamp            int64   `json:"timestamp"`
	Nonce                string  `json:"nonce"`
	Challenge            string  `json:"challenge,omitempty"`
	ResponseStatus       int     `json:"response_status,omitempty"`
	ResponseContentType  string  `json:"response_content_type,omitempty"`
}

// RequestUpstreamObservation is the request and upstream response metadata
// covered by llm-request-upstream-v1. It deliberately contains no response
// body fields: callers must treat the streamed response body as unverified.
type RequestUpstreamObservation struct {
	Domain                 string
	CertificateFingerprint string
	RequestPath            string
	RequestFields          []Field
	Challenge              string
	ResponseStatus         int
	ResponseContentType    string
}

type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
	now        func() time.Time
}

func NewSigner(privateKey ed25519.PrivateKey, keyID string) *Signer {
	return &Signer{privateKey: privateKey, keyID: keyID, now: time.Now}
}

func (s *Signer) Sign(header http.Header, domain, certificateFingerprint, requestPath string, requestFields, responseFields []Field) error {
	if err := validateFields(requestFields, responseFields, true); err != nil {
		return err
	}
	if !validHeaderValue(requestPath) {
		return errors.New("request path contains characters that are unsafe in an HTTP header")
	}
	model, hasModel, err := modelHeader(requestFields)
	if err != nil {
		return err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("create nonce: %w", err)
	}
	claims := Claims{
		Version:              Version,
		Profile:              Profile,
		KeyID:                s.keyID,
		TLSCertificateSHA256: strings.ToLower(certificateFingerprint),
		Domain:               strings.ToLower(domain),
		RequestPath:          requestPath,
		RequestFields:        requestFields,
		ResponseFields:       responseFields,
		Timestamp:            s.now().UTC().Unix(),
		Nonce:                base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(s.privateKey, payload)

	header.Set(HeaderAlgorithm, Algorithm)
	header.Set(HeaderProfile, claims.Profile)
	header.Set(HeaderKeyID, claims.KeyID)
	header.Set(HeaderDomain, claims.Domain)
	header.Set(HeaderRequestPath, claims.RequestPath)
	header.Del(HeaderModel)
	if hasModel {
		header.Set(HeaderModel, model)
	}
	header.Set(HeaderCertificateFingerprint, claims.TLSCertificateSHA256)
	header.Set(HeaderTimestamp, strconv.FormatInt(claims.Timestamp, 10))
	header.Set(HeaderNonce, claims.Nonce)
	header.Set(HeaderSignedFields, signedFields(requestFields, responseFields))
	header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(signature))
	header.Del(HeaderChallenge)
	header.Del(HeaderResponseStatus)
	header.Del(HeaderResponseContentType)
	return nil
}

// SignRequestUpstream signs the normalized request and the verified upstream
// TLS/response metadata before a streaming response body is forwarded.
func (s *Signer) SignRequestUpstream(header http.Header, observation RequestUpstreamObservation) error {
	if err := validateFields(observation.RequestFields, nil, false); err != nil {
		return err
	}
	if err := ValidateChallenge(observation.Challenge); err != nil {
		return err
	}
	if observation.ResponseStatus < 100 || observation.ResponseStatus > 599 {
		return errors.New("response status must be between 100 and 599")
	}
	if !validHeaderValue(observation.ResponseContentType) || observation.ResponseContentType == "" {
		return errors.New("response content type is invalid")
	}
	if !validHeaderValue(observation.RequestPath) {
		return errors.New("request path contains characters that are unsafe in an HTTP header")
	}
	model, hasModel, err := modelHeader(observation.RequestFields)
	if err != nil {
		return err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("create nonce: %w", err)
	}
	claims := Claims{
		Version:              Version,
		Profile:              RequestUpstreamProfile,
		KeyID:                s.keyID,
		TLSCertificateSHA256: strings.ToLower(observation.CertificateFingerprint),
		Domain:               strings.ToLower(observation.Domain),
		RequestPath:          observation.RequestPath,
		RequestFields:        observation.RequestFields,
		ResponseFields:       []Field{},
		Timestamp:            s.now().UTC().Unix(),
		Nonce:                base64.RawURLEncoding.EncodeToString(nonceBytes),
		Challenge:            observation.Challenge,
		ResponseStatus:       observation.ResponseStatus,
		ResponseContentType:  observation.ResponseContentType,
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(s.privateKey, payload)

	header.Set(HeaderAlgorithm, Algorithm)
	header.Set(HeaderProfile, claims.Profile)
	header.Set(HeaderKeyID, claims.KeyID)
	header.Set(HeaderDomain, claims.Domain)
	header.Set(HeaderRequestPath, claims.RequestPath)
	header.Del(HeaderModel)
	if hasModel {
		header.Set(HeaderModel, model)
	}
	header.Set(HeaderCertificateFingerprint, claims.TLSCertificateSHA256)
	header.Set(HeaderTimestamp, strconv.FormatInt(claims.Timestamp, 10))
	header.Set(HeaderNonce, claims.Nonce)
	header.Set(HeaderChallenge, claims.Challenge)
	header.Set(HeaderResponseStatus, strconv.Itoa(claims.ResponseStatus))
	header.Set(HeaderResponseContentType, claims.ResponseContentType)
	header.Set(HeaderSignedFields, requestUpstreamSignedFields(observation.RequestFields))
	header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func CanonicalPayload(claims Claims) ([]byte, error) {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"version", claims.Version},
		{"profile", claims.Profile},
		{"key_id", claims.KeyID},
		{"tls_certificate_sha256", claims.TLSCertificateSHA256},
		{"domain", claims.Domain},
		{"request_path", claims.RequestPath},
		{"nonce", claims.Nonce},
	} {
		if !utf8.ValidString(field.value) {
			return nil, fmt.Errorf("claim %s must be valid UTF-8", field.name)
		}
	}
	if claims.Timestamp < -maxIJSONSafeInteger || claims.Timestamp > maxIJSONSafeInteger {
		return nil, errors.New("claim timestamp exceeds the I-JSON safe integer range")
	}
	if claims.Challenge != "" {
		if err := ValidateChallenge(claims.Challenge); err != nil {
			return nil, err
		}
	}
	if claims.ResponseStatus != 0 && (claims.ResponseStatus < 100 || claims.ResponseStatus > 599) {
		return nil, errors.New("claim response status must be between 100 and 599")
	}
	if claims.ResponseContentType != "" && !validHeaderValue(claims.ResponseContentType) {
		return nil, errors.New("claim response content type is invalid")
	}

	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("encode claims as JSON: %w", err)
	}
	payload, err := jcs.Transform(encoded)
	if err != nil {
		return nil, fmt.Errorf("canonicalize claims as JCS: %w", err)
	}
	return payload, nil
}

// canonicalizeJSONValue applies JCS to any JSON value. Wrapping the value in
// an array lets the canonicalizer handle scalars and composite values through
// the same parser while preserving the value's JSON type.
func canonicalizeJSONValue(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON must be valid UTF-8")
	}
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON")
	}
	if err := validateUnicodeScalarEscapes(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := validateIJSONNumbers(value); err != nil {
		return nil, err
	}

	wrapper := make([]byte, 0, len(raw)+2)
	wrapper = append(wrapper, '[')
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, ']')
	canonical, err := jcs.Transform(wrapper)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), canonical[1:len(canonical)-1]...), nil
}

func validateIJSONNumbers(value any) error {
	switch value := value.(type) {
	case json.Number:
		text := value.String()
		if strings.ContainsAny(text, ".eE") {
			return nil
		}
		integer, err := strconv.ParseInt(text, 10, 64)
		if err != nil || integer < -maxIJSONSafeInteger || integer > maxIJSONSafeInteger {
			return fmt.Errorf("JSON integer %q exceeds the I-JSON safe integer range", text)
		}
	case []any:
		for _, item := range value {
			if err := validateIJSONNumbers(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range value {
			if err := validateIJSONNumbers(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateUnicodeScalarEscapes rejects unpaired UTF-16 surrogates. The
// standard JSON decoder replaces them with U+FFFD, which would silently change
// the signed value and violate the I-JSON input requirements used by JCS.
func validateUnicodeScalarEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw); i++ {
			switch raw[i] {
			case '"':
				goto endString
			case '\\':
				i++
				if raw[i] != 'u' {
					continue
				}
				codeUnit, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
				if err != nil {
					return err
				}
				i += 4
				if codeUnit >= 0xd800 && codeUnit <= 0xdbff {
					if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
						return errors.New("JSON string contains an unpaired high surrogate")
					}
					lowSurrogate, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
					if err != nil || lowSurrogate < 0xdc00 || lowSurrogate > 0xdfff {
						return errors.New("JSON string contains an unpaired high surrogate")
					}
					i += 6
				} else if codeUnit >= 0xdc00 && codeUnit <= 0xdfff {
					return errors.New("JSON string contains an unpaired low surrogate")
				}
			}
		}
	endString:
	}
	return nil
}

func Verify(publicKey ed25519.PublicKey, header http.Header, expectedDomain, expectedFingerprint, requestPath string, requestFields, responseFields []Field, now time.Time, maxAge time.Duration) error {
	if err := validateFields(requestFields, responseFields, true); err != nil {
		return err
	}
	if header.Get(HeaderAlgorithm) != Algorithm {
		return fmt.Errorf("unsupported algorithm %q", header.Get(HeaderAlgorithm))
	}
	if header.Get(HeaderProfile) != Profile {
		return fmt.Errorf("unsupported attestation profile %q", header.Get(HeaderProfile))
	}
	if expected := signedFields(requestFields, responseFields); header.Get(HeaderSignedFields) != expected {
		return fmt.Errorf("unexpected signed fields %q", header.Get(HeaderSignedFields))
	}
	if expectedDomain == "" || !strings.EqualFold(header.Get(HeaderDomain), expectedDomain) {
		return fmt.Errorf("domain mismatch: got %q, expected %q", header.Get(HeaderDomain), expectedDomain)
	}
	pathHeader, validPathHeader := singleHeader(header, HeaderRequestPath)
	if !validPathHeader || pathHeader != requestPath {
		return fmt.Errorf("request path mismatch: got %q, expected %q", pathHeader, requestPath)
	}
	expectedModel, hasModel, err := modelHeader(requestFields)
	if err != nil {
		return err
	}
	if hasModel {
		modelValue, validModelHeader := singleHeader(header, HeaderModel)
		if !validModelHeader || modelValue != expectedModel {
			return fmt.Errorf("model mismatch: got %q, expected %q", modelValue, expectedModel)
		}
	} else if hasHeader(header, HeaderModel) {
		return fmt.Errorf("unexpected model header %q", header.Get(HeaderModel))
	}
	if expectedFingerprint != "" && !strings.EqualFold(header.Get(HeaderCertificateFingerprint), expectedFingerprint) {
		return fmt.Errorf("certificate fingerprint mismatch")
	}
	timestamp, err := strconv.ParseInt(header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	age := now.UTC().Sub(time.Unix(timestamp, 0))
	if age < -30*time.Second || age > maxAge {
		return fmt.Errorf("attestation timestamp outside allowed window: age %s", age.Round(time.Second))
	}
	claims := Claims{
		Version:              Version,
		Profile:              Profile,
		KeyID:                header.Get(HeaderKeyID),
		TLSCertificateSHA256: strings.ToLower(header.Get(HeaderCertificateFingerprint)),
		Domain:               strings.ToLower(expectedDomain),
		RequestPath:          requestPath,
		RequestFields:        requestFields,
		ResponseFields:       responseFields,
		Timestamp:            timestamp,
		Nonce:                header.Get(HeaderNonce),
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(header.Get(HeaderSignature))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// VerifyRequestUpstream verifies llm-request-upstream-v1. A successful result
// authenticates only the request and upstream response metadata in observation;
// it makes no claim about the streaming response body.
func VerifyRequestUpstream(publicKey ed25519.PublicKey, header http.Header, observation RequestUpstreamObservation, now time.Time, maxAge time.Duration) error {
	if err := validateFields(observation.RequestFields, nil, false); err != nil {
		return err
	}
	if err := ValidateChallenge(observation.Challenge); err != nil {
		return err
	}
	if header.Get(HeaderAlgorithm) != Algorithm {
		return fmt.Errorf("unsupported algorithm %q", header.Get(HeaderAlgorithm))
	}
	if header.Get(HeaderProfile) != RequestUpstreamProfile {
		return fmt.Errorf("unsupported attestation profile %q", header.Get(HeaderProfile))
	}
	if expected := requestUpstreamSignedFields(observation.RequestFields); header.Get(HeaderSignedFields) != expected {
		return fmt.Errorf("unexpected signed fields %q", header.Get(HeaderSignedFields))
	}
	if observation.Domain == "" || !strings.EqualFold(header.Get(HeaderDomain), observation.Domain) {
		return fmt.Errorf("domain mismatch: got %q, expected %q", header.Get(HeaderDomain), observation.Domain)
	}
	pathHeader, validPathHeader := singleHeader(header, HeaderRequestPath)
	if !validPathHeader || pathHeader != observation.RequestPath {
		return fmt.Errorf("request path mismatch: got %q, expected %q", pathHeader, observation.RequestPath)
	}
	expectedModel, hasModel, err := modelHeader(observation.RequestFields)
	if err != nil {
		return err
	}
	if hasModel {
		modelValue, validModelHeader := singleHeader(header, HeaderModel)
		if !validModelHeader || modelValue != expectedModel {
			return fmt.Errorf("model mismatch: got %q, expected %q", modelValue, expectedModel)
		}
	} else if hasHeader(header, HeaderModel) {
		return fmt.Errorf("unexpected model header %q", header.Get(HeaderModel))
	}
	if observation.CertificateFingerprint != "" && !strings.EqualFold(header.Get(HeaderCertificateFingerprint), observation.CertificateFingerprint) {
		return errors.New("certificate fingerprint mismatch")
	}
	challenge, validChallengeHeader := singleHeader(header, HeaderChallenge)
	if !validChallengeHeader || challenge != observation.Challenge {
		return fmt.Errorf("challenge mismatch: got %q", challenge)
	}
	statusText, validStatusHeader := singleHeader(header, HeaderResponseStatus)
	status, err := strconv.Atoi(statusText)
	if !validStatusHeader || err != nil || status != observation.ResponseStatus {
		return fmt.Errorf("response status mismatch: got %q, expected %d", statusText, observation.ResponseStatus)
	}
	contentType, validContentTypeHeader := singleHeader(header, HeaderResponseContentType)
	if !validContentTypeHeader || contentType != observation.ResponseContentType {
		return fmt.Errorf("response content type mismatch: got %q, expected %q", contentType, observation.ResponseContentType)
	}
	timestamp, err := strconv.ParseInt(header.Get(HeaderTimestamp), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	age := now.UTC().Sub(time.Unix(timestamp, 0))
	if age < -30*time.Second || age > maxAge {
		return fmt.Errorf("attestation timestamp outside allowed window: age %s", age.Round(time.Second))
	}
	claims := Claims{
		Version:              Version,
		Profile:              RequestUpstreamProfile,
		KeyID:                header.Get(HeaderKeyID),
		TLSCertificateSHA256: strings.ToLower(header.Get(HeaderCertificateFingerprint)),
		Domain:               strings.ToLower(observation.Domain),
		RequestPath:          observation.RequestPath,
		RequestFields:        observation.RequestFields,
		ResponseFields:       []Field{},
		Timestamp:            timestamp,
		Nonce:                header.Get(HeaderNonce),
		Challenge:            observation.Challenge,
		ResponseStatus:       observation.ResponseStatus,
		ResponseContentType:  observation.ResponseContentType,
	}
	payload, err := CanonicalPayload(claims)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(header.Get(HeaderSignature))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// ValidateChallenge applies the public challenge syntax shared by business
// request attestations and Confidential Space proof requests.
func ValidateChallenge(challenge string) error {
	if len(challenge) < 10 || len(challenge) > 74 {
		return errors.New("challenge must contain 10 to 74 URL-safe ASCII characters")
	}
	for _, character := range challenge {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return errors.New("challenge must contain only URL-safe ASCII characters")
		}
	}
	return nil
}

func modelHeader(requestFields []Field) (string, bool, error) {
	for _, field := range requestFields {
		if field.Name != "model" {
			continue
		}
		var model string
		if err := json.Unmarshal(field.Value, &model); err != nil {
			return "", false, errors.New("request field model must be a JSON string to expose X-Attestation-Model")
		}
		if !validHeaderValue(model) {
			return "", false, errors.New("request field model contains characters that are unsafe in an HTTP header")
		}
		return model, true, nil
	}
	return "", false, nil
}

func validHeaderValue(value string) bool {
	if strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' || character >= 0x20 && character != 0x7f {
			continue
		}
		return false
	}
	return true
}

func hasHeader(header http.Header, name string) bool {
	_, ok := header[http.CanonicalHeaderKey(name)]
	return ok
}

func singleHeader(header http.Header, name string) (string, bool) {
	values, ok := header[http.CanonicalHeaderKey(name)]
	if !ok || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func signedFields(requestFields, responseFields []Field) string {
	fields := []string{"tls_certificate_sha256", "domain", "request.path"}
	for _, field := range requestFields {
		fields = append(fields, "request.body."+field.Name)
	}
	for _, field := range responseFields {
		fields = append(fields, "response.body."+field.Name)
	}
	return strings.Join(fields, ",")
}

func requestUpstreamSignedFields(requestFields []Field) string {
	fields := []string{"tls_certificate_sha256", "domain", "request.path"}
	for _, field := range requestFields {
		fields = append(fields, "request.body."+field.Name)
	}
	fields = append(fields, "response.status", "response.content_type", "challenge")
	return strings.Join(fields, ",")
}

func validateFields(requestFields, responseFields []Field, requireResponse bool) error {
	if len(requestFields) == 0 || (requireResponse && len(responseFields) == 0) {
		return errors.New("required request or response fields must not be empty")
	}
	seen := make(map[string]struct{}, len(requestFields)+len(responseFields))
	for _, group := range []struct {
		name   string
		fields []Field
	}{{"request", requestFields}, {"response", responseFields}} {
		for _, field := range group.fields {
			if strings.TrimSpace(field.Name) == "" || !utf8.ValidString(field.Name) || strings.ContainsAny(field.Name, ",\r\n") {
				return fmt.Errorf("invalid %s semantic field name %q", group.name, field.Name)
			}
			key := group.name + "\x00" + field.Name
			if _, ok := seen[key]; ok {
				return fmt.Errorf("duplicate %s semantic field name %q", group.name, field.Name)
			}
			seen[key] = struct{}{}
			if _, err := canonicalizeJSONValue(field.Value); err != nil {
				return fmt.Errorf("invalid JCS value for %s semantic field %q: %w", group.name, field.Name, err)
			}
		}
	}
	return nil
}
