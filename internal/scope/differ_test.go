package scope

import "testing"

func TestCompare_FindsAddsAndRemoves(t *testing.T) {
	prev := ScopeDefinition{
		AllowedDomains:    []string{"api.acme.corp", "www.acme.corp"},
		AllowedCIDRs:      []string{"10.0.0.0/24"},
		AllowedSourceCode: []string{"https://github.com/acme/old"},
		ExcludedDomains:   []string{"old.acme.corp"},
		SourceCodeInstructions: map[string]string{
			"https://github.com/acme/old": "old instruction",
		},
	}
	cur := ScopeDefinition{
		AllowedDomains:    []string{"api.acme.corp", "shop.acme.corp"}, // -www, +shop
		AllowedCIDRs:      []string{"10.0.0.0/24", "10.0.1.0/24"},      // +10.0.1.0/24
		AllowedSourceCode: []string{"https://github.com/acme/new"},       // -old, +new
		ExcludedDomains:   []string{"new.acme.corp"},
		SourceCodeInstructions: map[string]string{
			"https://github.com/acme/new": "new instruction",
		},
	}
	d := Compare(prev, cur)
	if len(d.AddedDomains) != 1 || d.AddedDomains[0] != "shop.acme.corp" {
		t.Errorf("added domains: %v", d.AddedDomains)
	}
	if len(d.RemovedDomains) != 1 || d.RemovedDomains[0] != "www.acme.corp" {
		t.Errorf("removed domains: %v", d.RemovedDomains)
	}
	if len(d.AddedCIDRs) != 1 || d.AddedCIDRs[0] != "10.0.1.0/24" {
		t.Errorf("added cidrs: %v", d.AddedCIDRs)
	}
	if len(d.AddedExcludedDomains) != 1 || d.AddedExcludedDomains[0] != "new.acme.corp" {
		t.Errorf("added exclusions: %v", d.AddedExcludedDomains)
	}
	if len(d.RemovedExcludedDomains) != 1 || d.RemovedExcludedDomains[0] != "old.acme.corp" {
		t.Errorf("removed exclusions: %v", d.RemovedExcludedDomains)
	}
	if len(d.AddedSourceCode) != 1 || d.AddedSourceCode[0] != "https://github.com/acme/new" {
		t.Errorf("added source code: %v", d.AddedSourceCode)
	}
	if len(d.RemovedSourceCode) != 1 || d.RemovedSourceCode[0] != "https://github.com/acme/old" {
		t.Errorf("removed source code: %v", d.RemovedSourceCode)
	}
	if !d.HasChanges() {
		t.Error("HasChanges should be true")
	}
}


func TestCompare_DetectsSourceInstructionChange(t *testing.T) {
	url := "https://github.com/circlefin/malachite"
	prev := ScopeDefinition{
		AllowedSourceCode: []string{url},
		SourceCodeInstructions: map[string]string{url: "code/crates only"},
	}
	cur := ScopeDefinition{
		AllowedSourceCode: []string{url},
		SourceCodeInstructions: map[string]string{url: "code/crates only; exclude starknet and tests"},
	}
	d := Compare(prev, cur)
	if len(d.ChangedSourceCodeInstructions) != 1 || d.ChangedSourceCodeInstructions[0] != url {
		t.Fatalf("instruction changes: %v", d.ChangedSourceCodeInstructions)
	}
	if !d.HasChanges() {
		t.Fatal("instruction change must count as scope change")
	}
}

func TestCompare_Identical(t *testing.T) {
	a := ScopeDefinition{AllowedDomains: []string{"x.com", "y.com"}}
	d := Compare(a, a)
	if d.HasChanges() {
		t.Fatalf("identical scopes should report no changes; got %+v", d)
	}
}

func TestCompare_OutputIsSorted(t *testing.T) {
	prev := ScopeDefinition{AllowedDomains: []string{}}
	cur := ScopeDefinition{AllowedDomains: []string{"z.com", "a.com", "m.com"}}
	d := Compare(prev, cur)
	if d.AddedDomains[0] != "a.com" || d.AddedDomains[2] != "z.com" {
		t.Fatalf("output not sorted: %v", d.AddedDomains)
	}
}
