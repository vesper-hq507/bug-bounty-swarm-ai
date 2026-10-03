package blackboard

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/provenance"
	"github.com/google/uuid"
)

func TestSecureBoardRequiresBoundWriterAndRejectsImpersonation(t *testing.T) {
	keys, err := provenance.NewFileKeyring(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	base := NewMemoryBoard(nil)
	board, err := NewSecureBoard(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	campaignID := uuid.New()
	f := Finding{CampaignID: campaignID, AgentName: "classifier", Type: TypeCVEMatch, Target: "example.test"}

	if _, err := board.Write(context.Background(), f); err == nil {
		t.Fatal("unbound write must fail")
	}
	if _, err := board.Writer("recon").Write(context.Background(), f); err == nil {
		t.Fatal("recon writer must not impersonate classifier")
	}
	if _, err := board.Writer("classifier").Write(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	got, err := board.Query(context.Background(), Predicate{Types: []FindingType{TypeCVEMatch}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].ProvenanceSignature) == 0 || len(got[0].ProvenancePublicKey) == 0 {
		t.Fatalf("signed findings = %+v", got)
	}
}

func TestSecureBoardRejectsTamperedStoredFinding(t *testing.T) {
	keys, err := provenance.NewFileKeyring(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	base := NewMemoryBoard(nil)
	board, err := NewSecureBoard(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	campaignID := uuid.New()
	if _, err := board.Writer("recon").Write(context.Background(), Finding{
		CampaignID: campaignID,
		Type: TypeSubdomain,
		Target: "a.example.test",
		Data: []byte(`{"subdomain":"a.example.test"}`),
	}); err != nil {
		t.Fatal(err)
	}

	base.mu.Lock()
	base.findings[0].Data = []byte(`{"subdomain":"evil.example.test"}`)
	base.mu.Unlock()

	if _, err := board.Query(context.Background(), Predicate{}); err == nil {
		t.Fatal("tampered finding must fail verified query")
	}
}

func TestSecureBoardKeyringSurvivesRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "keys")
	first, err := provenance.NewFileKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := provenance.NewFileKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	pub1, err := first.PublicKey("exploit")
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := second.PublicKey("exploit")
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) != string(pub2) {
		t.Fatal("persisted keyring did not derive stable agent key")
	}
}
