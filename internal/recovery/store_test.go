package recovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestFileStoreRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recovery")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	cp, err := NewCheckpoint(Checkpoint{
		CampaignID: id, Phase: "execute", PolicyVersion: "policy-v1",
		CompletedActionIDs: []string{"step-1"},
		CleanupActionIDs: []uuid.UUID{uuid.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cp); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntegrityHash != cp.IntegrityHash || got.Phase != "execute" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	info, err := os.Stat(filepath.Join(root, id.String()+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %o, want 600", info.Mode().Perm())
	}
}
