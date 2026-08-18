package gcpsecret

import (
	"hash/crc32"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

func TestFixedSecretVersionName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{name: "projects/example-project/secrets/postgres-password/versions/1", valid: true},
		{name: "projects/123456789/secrets/postgres_password/versions/42", valid: true},
		{name: "projects/example-project/secrets/postgres-password/versions/latest", valid: false},
		{name: "projects/example-project/secrets/postgres-password", valid: false},
		{name: "postgres-password", valid: false},
	}
	for _, test := range tests {
		if got := fixedVersionName.MatchString(test.name); got != test.valid {
			t.Errorf("fixedVersionName.MatchString(%q) = %v, want %v", test.name, got, test.valid)
		}
	}
}

func TestTextFromPayload(t *testing.T) {
	data := []byte("postgres://user:password=+value@db.internal/proofs")
	checksum := int64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
	text, err := textFromPayload(&secretmanagerpb.SecretPayload{
		Data:       data,
		DataCrc32C: &checksum,
	})
	if err != nil {
		t.Fatal(err)
	}
	if text != string(data) {
		t.Fatalf("text = %q", text)
	}
}

func TestTextFromPayloadRejectsInvalidContent(t *testing.T) {
	badChecksum := int64(1)
	tests := []*secretmanagerpb.SecretPayload{
		nil,
		{},
		{Data: []byte("postgres://db\n")},
		{Data: []byte("postgres://db"), DataCrc32C: &badChecksum},
	}
	for _, payload := range tests {
		if _, err := textFromPayload(payload); err == nil {
			t.Fatalf("textFromPayload(%v) succeeded", payload)
		}
	}
}
