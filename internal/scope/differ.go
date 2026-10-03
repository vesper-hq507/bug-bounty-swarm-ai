package scope

import "sort"

// Diff summarizes additions + removals + unchanged between two scopes.
// Callers decide how to render — JSON, colored terminal, SARIF, etc.
type Diff struct {
	AddedDomains                  []string `json:"added_domains"`
	RemovedDomains                []string `json:"removed_domains"`
	AddedExcludedDomains          []string `json:"added_excluded_domains"`
	RemovedExcludedDomains        []string `json:"removed_excluded_domains"`
	AddedCIDRs                    []string `json:"added_cidrs"`
	RemovedCIDRs                  []string `json:"removed_cidrs"`
	AddedSourceCode               []string `json:"added_source_code"`
	RemovedSourceCode             []string `json:"removed_source_code"`
	ChangedSourceCodeInstructions []string `json:"changed_source_code_instructions"`
	Unchanged                     int      `json:"unchanged_count"`
}

// HasChanges is true when either side is non-empty — useful for exit codes.
func (d Diff) HasChanges() bool {
	return len(d.AddedDomains) > 0 || len(d.RemovedDomains) > 0 ||
		len(d.AddedExcludedDomains) > 0 || len(d.RemovedExcludedDomains) > 0 ||
		len(d.AddedCIDRs) > 0 || len(d.RemovedCIDRs) > 0 ||
		len(d.AddedSourceCode) > 0 || len(d.RemovedSourceCode) > 0 ||
		len(d.ChangedSourceCodeInstructions) > 0
}

// Compare returns a Diff describing what changed from prev to cur.
func Compare(prev, cur ScopeDefinition) Diff {
	d := Diff{
		AddedDomains:           setDiff(cur.AllowedDomains, prev.AllowedDomains),
		RemovedDomains:         setDiff(prev.AllowedDomains, cur.AllowedDomains),
		AddedExcludedDomains:   setDiff(cur.ExcludedDomains, prev.ExcludedDomains),
		RemovedExcludedDomains: setDiff(prev.ExcludedDomains, cur.ExcludedDomains),
		AddedCIDRs:             setDiff(cur.AllowedCIDRs, prev.AllowedCIDRs),
		RemovedCIDRs:           setDiff(prev.AllowedCIDRs, cur.AllowedCIDRs),
		AddedSourceCode:        setDiff(cur.AllowedSourceCode, prev.AllowedSourceCode),
		RemovedSourceCode:      setDiff(prev.AllowedSourceCode, cur.AllowedSourceCode),
	}
	d.ChangedSourceCodeInstructions = changedInstructions(prev.SourceCodeInstructions, cur.SourceCodeInstructions)
	d.Unchanged = len(cur.AllowedDomains) + len(cur.ExcludedDomains) + len(cur.AllowedCIDRs) + len(cur.AllowedSourceCode) -
		len(d.AddedDomains) - len(d.AddedExcludedDomains) - len(d.AddedCIDRs) - len(d.AddedSourceCode)
	return d
}

// setDiff returns elements of a that are not in b, sorted for stable output.
func setDiff(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, x := range b {
		bSet[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, in := bSet[x]; !in {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}


func changedInstructions(prev, cur map[string]string) []string {
	var out []string
	for key, current := range cur {
		previous, ok := prev[key]
		if ok && previous != current {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}
