package chains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdate_IndexJSONRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			json.NewEncoder(w).Encode([]string{"demo-ssrf-rce.yaml", "broken.yaml"})
		case "/demo-ssrf-rce.yaml":
			w.Write([]byte(validChain))
		case "/broken.yaml":
			w.Write([]byte("id:\nlinks: []\n")) // invalid → must be skipped
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	dest := t.TempDir()
	written, err := Update(context.Background(), srv.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || written[0] != "demo-ssrf-rce" {
		t.Fatalf("expected only the valid chain written, got %v", written)
	}
	if _, err := os.Stat(filepath.Join(dest, "demo-ssrf-rce.yaml")); err != nil {
		t.Errorf("valid chain not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "broken.yaml")); err == nil {
		t.Error("invalid chain must NOT be written")
	}
}
