// Package gcpsecret securely reads fixed Secret Manager versions using the
// workload's Application Default Credentials.
package gcpsecret

import (
	"context"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

var fixedVersionName = regexp.MustCompile(`^projects/[^/]+/secrets/[^/]+/versions/[1-9][0-9]*$`)

// AccessFixedVersion returns a secret payload from an explicitly numbered
// version. Aliases such as "latest" are rejected so a rollout is reproducible
// and a rotation cannot unexpectedly break a running deployment.
func AccessFixedVersion(ctx context.Context, name string) (string, error) {
	if !fixedVersionName.MatchString(name) {
		return "", fmt.Errorf("secret version must use projects/PROJECT/secrets/SECRET/versions/NUMBER")
	}
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("create Secret Manager client: %w", err)
	}
	defer client.Close()

	response, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name})
	if err != nil {
		return "", fmt.Errorf("access Secret Manager version: %w", err)
	}
	return textFromPayload(response.Payload)
}

func textFromPayload(payload *secretmanagerpb.SecretPayload) (string, error) {
	if payload == nil || len(payload.Data) == 0 {
		return "", fmt.Errorf("Secret Manager version contains an empty payload")
	}
	if payload.DataCrc32C != nil {
		checksum := int64(crc32.Checksum(payload.Data, crc32.MakeTable(crc32.Castagnoli)))
		if checksum != *payload.DataCrc32C {
			return "", fmt.Errorf("Secret Manager payload checksum mismatch")
		}
	}
	text := string(payload.Data)
	if strings.ContainsAny(text, "\x00\r\n") {
		return "", fmt.Errorf("Secret Manager payload must not contain NUL or line-break characters")
	}
	return text, nil
}
