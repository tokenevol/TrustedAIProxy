package mitmproxy

import (
	"path/filepath"
	"testing"
)

func TestLoadCAReusesProvisionedCA(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	created, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Leaf.Equal(loaded.Leaf) {
		t.Fatal("LoadCA did not return the provisioned CA certificate")
	}
}

func TestLoadCADoesNotGenerateMissingCA(t *testing.T) {
	directory := t.TempDir()
	if _, err := LoadCA(filepath.Join(directory, "ca.pem"), filepath.Join(directory, "ca-key.pem")); err == nil {
		t.Fatal("expected missing production CA to fail")
	}
}
