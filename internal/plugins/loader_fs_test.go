package plugins

import (
	"testing"
	"testing/fstest"
)

func fsWithPlaybooks() fstest.MapFS {
	good := []byte("name: Demo\nphases:\n  - name: p1\n    tools:\n      - name: httpx\n")
	bad := []byte("name: \nphases: []\n") // invalid: no name, no phases
	return fstest.MapFS{
		"demo.yaml":       {Data: good},
		"broken.yaml":     {Data: bad},
		"notes.txt":       {Data: []byte("ignore me")},
		"sub/nested.yaml": {Data: good},
	}
}

func TestLoadPlaybookFS(t *testing.T) {
	fsys := fsWithPlaybooks()
	pb, err := LoadPlaybookFS(fsys, "demo")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if pb.Name != "Demo" {
		t.Errorf("name = %q", pb.Name)
	}
	// name with .yaml suffix also works
	if _, err := LoadPlaybookFS(fsys, "demo.yaml"); err != nil {
		t.Errorf("suffix form: %v", err)
	}
	if _, err := LoadPlaybookFS(fsys, "missing"); err == nil {
		t.Error("expected error for missing playbook")
	}
}

func TestDiscoverPlaybooksFS_SkipsInvalidAndNonYAML(t *testing.T) {
	pbs, err := DiscoverPlaybooksFS(fsWithPlaybooks())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// demo.yaml + sub/nested.yaml are valid; broken.yaml + notes.txt excluded.
	if len(pbs) != 2 {
		t.Fatalf("expected 2 valid playbooks, got %d", len(pbs))
	}
}
