package monitor

import (
	"path/filepath"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "monitor"))
	if err != nil {
		t.Fatal(err)
	}
	before, ok, err := store.Load("https://example.test")
	if err != nil || ok || before.Target != "" {
		t.Fatalf("empty load = %+v ok=%v err=%v", before, ok, err)
	}
	want := Snapshot{Target: "https://example.test", Subdomains: []string{"api.example.test"}}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Load(want.Target)
	if err != nil || !ok {
		t.Fatalf("load err=%v ok=%v", err, ok)
	}
	if got.Target != want.Target || len(got.Subdomains) != 1 {
		t.Fatalf("snapshot = %+v", got)
	}
}
