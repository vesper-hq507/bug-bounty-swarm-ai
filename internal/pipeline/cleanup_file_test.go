package pipeline

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestFileCleanupRegistryPersistsAndRunsReverseOrder(t *testing.T) {
	var ran []string
	root := filepath.Join(t.TempDir(), "cleanup")
	reg, err := NewFileCleanupRegistry(root, func(_ context.Context, cmd string) error {
		ran = append(ran, cmd)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	campaignID := uuid.New()
	if err := reg.Register(context.Background(), campaignID, "cleanup-first", "first"); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(context.Background(), campaignID, "cleanup-second", "second"); err != nil {
		t.Fatal(err)
	}

	reg2, err := NewFileCleanupRegistry(root, func(_ context.Context, cmd string) error {
		ran = append(ran, cmd)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reg2.PendingCleanup(context.Background(), campaignID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	rep := reg2.RunCleanup(context.Background(), campaignID)
	if rep.TotalCount != 2 || len(rep.Executed) != 2 || len(rep.Failed) != 0 {
		t.Fatalf("cleanup report = %+v", rep)
	}
	if len(ran) != 2 || ran[0] != "cleanup-second" || ran[1] != "cleanup-first" {
		t.Fatalf("cleanup order = %#v", ran)
	}
	pending, err = reg2.PendingCleanup(context.Background(), campaignID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after cleanup = %d", len(pending))
	}
}
