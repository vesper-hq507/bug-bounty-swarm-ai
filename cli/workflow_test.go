package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadWorkflowEventsRequiresNonEmptyTrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trace.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWorkflowEvents(path); err == nil {
		t.Fatal("empty workflow trace must fail")
	}
}

func TestReadWorkflowRulesAllowsEmptyPath(t *testing.T) {
	rules, err := readWorkflowRules("")
	if err != nil {
		t.Fatal(err)
	}
	if rules != nil {
		t.Fatalf("rules = %+v, want nil", rules)
	}
}
