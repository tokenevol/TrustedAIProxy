package main

import "testing"

func TestNormalizedDomain(t *testing.T) {
	if got := normalizedDomain("https://API.Example.com:8443/v1"); got != "api.example.com" {
		t.Fatalf("normalized domain = %q", got)
	}
}
