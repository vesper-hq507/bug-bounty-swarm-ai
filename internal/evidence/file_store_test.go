package evidence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestFileStoreRoundTripAndPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "evidence")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	campaignID := uuid.New()
	findingID := uuid.New()
	rec, err := New(Input{
		CampaignID: campaignID, FindingID: findingID,
		ActionID: "action-1", DecisionID: "decision-1",
		PolicyVersion: "policy-1", ActorID: "user-a",
		ResponseExcerpt: "Authorization: Bearer secret-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(rec); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntegrityHash != rec.IntegrityHash || got.ResponseExcerpt == "" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.ResponseExcerpt == "Authorization: Bearer secret-value" {
		t.Fatal("secret was persisted without redaction")
	}
	info, err := os.Stat(filepath.Join(root, rec.ID.String()+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %o, want 600", info.Mode().Perm())
	}
	if len(store.ForCampaign(campaignID)) != 1 || len(store.ForFinding(findingID)) != 1 {
		t.Fatal("campaign/finding lookup failed")
	}
}

func TestFileStoreRejectsTamperedRecord(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := New(Input{
		CampaignID: uuid.New(), ActionID: "a", DecisionID: "d",
		PolicyVersion: "p", ActorID: "i",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.ActorID = "tampered"
	if err := store.Add(rec); err == nil {
		t.Fatal("tampered record must be rejected")
	}
}
