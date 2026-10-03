package provenance

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyringPersistsStableDistinctAgentKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "keys")
	first, err := NewFileKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	recon1, err := first.PublicKey("recon")
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := first.PublicKey("classifier")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(recon1, classifier) {
		t.Fatal("different agent names must derive different keys")
	}

	second, err := NewFileKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	recon2, err := second.PublicKey("recon")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recon1, recon2) {
		t.Fatal("re-opened keyring changed the recon public key")
	}

	info, err := os.Stat(filepath.Join(root, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key mode = %o, want 600", info.Mode().Perm())
	}
}
