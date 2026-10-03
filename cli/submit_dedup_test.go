package cli

import (
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/hackerone"
)

func TestPriorCorpusPrefersRichOwnedReportAndDeduplicatesSources(t *testing.T) {
	var corpus priorCorpus
	owned := hackerone.Report{
		ID: "42",
		Title: "Object authorization weakness",
		State: "resolved",
		Program: "acme",
		VulnerabilityInformation: "GET https://api.example.test/api/invoices/123?invoice_id=123 HTTP/1.1",
		WeaknessExternalID: "CWE-639",
		AssetIdentifier: "https://api.example.test",
	}
	corpus.add("own", &owned)
	public := hackerone.Report{ID: "42", Title: owned.Title, Program: "acme"}
	corpus.add("public", &public)

	if len(corpus.Similarity) != 1 || len(corpus.Structured) != 1 {
		t.Fatalf("corpus = %+v", corpus)
	}
	if corpus.structuredCount() != 1 || corpus.Structured[0].Fingerprint == nil {
		t.Fatalf("rich prior was not structurally fingerprinted: %+v", corpus.Structured)
	}
	if corpus.Similarity[0].Target != "https://api.example.test" {
		t.Fatalf("title-similarity target = %q", corpus.Similarity[0].Target)
	}
}

func TestPriorCorpusKeepsSparseHistoryForTitleFallback(t *testing.T) {
	var corpus priorCorpus
	sparse := hackerone.Report{ID: "7", Title: "Reflected XSS in search", State: "resolved", Program: "acme"}
	corpus.add("public", &sparse)
	if len(corpus.Structured) != 1 || corpus.Structured[0].Fingerprint != nil {
		t.Fatalf("sparse prior should retain title fallback only: %+v", corpus.Structured)
	}
	if corpus.structuredCount() != 0 {
		t.Fatalf("structured count = %d", corpus.structuredCount())
	}
}
