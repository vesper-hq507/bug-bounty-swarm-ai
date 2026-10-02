package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMonitorSnapshotRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMonitorSnapshot(path); err == nil {
		t.Fatal("malformed snapshot JSON must fail")
	}
}

func TestWriteJSONFileUsesPrivateMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := writeJSONFile(path, map[string]string{"ok": "yes"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}
