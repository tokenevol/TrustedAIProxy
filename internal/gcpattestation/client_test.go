package gcpattestation

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestTokenUsesLauncherSocketAndBindsNonces(t *testing.T) {
	socketPath := fmt.Sprintf("/tmp/teeserver-%d.sock", time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Audience != "tap-test" || request.TokenType != "OIDC" {
			t.Errorf("unexpected request: %+v", request)
		}
		if len(request.Nonces) != 2 || request.Nonces[0] != "customer-challenge" || request.Nonces[1] != "public-key-binding" {
			t.Errorf("unexpected nonces: %v", request.Nonces)
		}
		_, _ = w.Write([]byte("header.payload.signature"))
	})}
	go server.Serve(listener)
	defer server.Close()

	client := New(socketPath, "tap-test")
	token, err := client.Token(context.Background(), []string{"customer-challenge", "public-key-binding"})
	if err != nil {
		t.Fatal(err)
	}
	if token != "header.payload.signature" {
		t.Fatalf("token = %q", token)
	}
}
