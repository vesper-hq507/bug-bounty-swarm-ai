package recon

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

func TestMergeClientAssetsDeduplicatesByURL(t *testing.T) {
	existing := []pipeline.ClientAssetRecord{{URL: "https://example.test/app.js", Kind: "javascript"}}
	discovered := []pipeline.ClientAssetRecord{
		{URL: "https://example.test/app.js", Kind: "javascript"},
		{URL: "https://example.test/chunk.js", Kind: "javascript"},
	}
	got := mergeClientAssets(existing, discovered)
	if len(got) != 2 {
		t.Fatalf("assets = %+v", got)
	}
	if got[1].URL != "https://example.test/chunk.js" {
		t.Fatalf("second asset = %+v", got[1])
	}
}
