package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
)

func TestParseGuideIdentities(t *testing.T) {
	got, err := parseGuideIdentities([]string{"user-a:user:vault-a", "anon:anonymous"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].SessionRef != "vault-a" || got[1].Role != identity.RoleAnonymous {
		t.Fatalf("identities = %+v", got)
	}
}

func TestParseGuideIdentitiesRequiresSessionRef(t *testing.T) {
	if _, err := parseGuideIdentities([]string{"user-a:user"}); err == nil {
		t.Fatal("authenticated identity without session reference must fail")
	}
}

func TestReadAttackSurfaceRequiresTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "surface.json")
	if err := os.WriteFile(path, []byte("{\"endpoints\":[]}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAttackSurface(path); err == nil {
		t.Fatal("surface without target must fail")
	}
}

func TestParseGuideFailures(t *testing.T) {
	got := parseGuideFailures([]string{"browser=timeout", "nuclei"})
	if len(got) != 2 || got[0].Reason != "timeout" || got[1].Reason == "" {
		t.Fatalf("failures = %+v", got)
	}
}
