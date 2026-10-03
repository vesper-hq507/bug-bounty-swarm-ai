package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/clientcode"
)

func TestReadBoundedArtifactRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.js")
	if err := os.WriteFile(path, make([]byte, 33), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedArtifact(path, 32); err == nil {
		t.Fatal("oversized artifact must fail before analysis")
	}
}

func TestClientCodeAnalysisCanResolveRelativeRoutes(t *testing.T) {
	got, err := clientcode.Analyze("https://example.test/assets/app.js", []byte(`fetch('/api/me')`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Summary.Routes) != 1 || got.Summary.Routes[0] != "https://example.test/api/me" {
		t.Fatalf("routes = %#v", got.Summary.Routes)
	}
}
