package chains

import (
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/plugins"
)

// ToPlaybook compiles an exploit chain into the executable playbook model so it
// runs on the same tested engine (tools → findings → report), while remaining a
// distinct concept at the product surface. It becomes: fingerprint → CVE detect
// → one safe-verify phase per link → report.
func (c *ExploitChain) ToPlaybook() *plugins.Playbook {
	var phases []plugins.Phase

	// Fingerprint the product/version — gates everything else.
	phases = append(phases, plugins.Phase{
		Name: "fingerprint",
		Tools: []plugins.ToolConfig{{
			Name:    "httpx",
			Options: map[string]any{"follow_redirects": true, "status_code": true, "paths": c.Fingerprint.Paths},
		}},
		PostAnalysis: c.fingerprintGuidance(),
	})

	// CVE detection via nuclei, tagged by the chain's CVE ids.
	tags := make([]string, 0, len(c.CVEs))
	for _, cve := range c.CVEs {
		tags = append(tags, strings.ToLower(cve))
	}
	phases = append(phases, plugins.Phase{
		Name: "cve_detect",
		Tools: []plugins.ToolConfig{{
			Name:    "nuclei",
			Options: map[string]any{"severity": []string{"critical", "high"}, "tags": tags},
		}},
		PostAnalysis: fmt.Sprintf("Run nuclei for %s if templates exist; treat a match as high-confidence "+
			"corroboration. If no template exists yet, do NOT downgrade a positive fingerprint — the safe "+
			"verification below is authoritative.", strings.Join(c.CVEs, ", ")),
	})

	// One safe-verification phase per link.
	for i, link := range c.Links {
		phases = append(phases, plugins.Phase{
			Name:         fmt.Sprintf("verify_link_%d", i+1),
			Tools:        []plugins.ToolConfig{{Name: "httpx", Options: map[string]any{"status_code": true}}},
			PostAnalysis: c.linkGuidance(i, link),
		})
	}

	// Report the full chain.
	phases = append(phases, plugins.Phase{
		Name:         "report",
		Tools:        []plugins.ToolConfig{{Name: "httpx", Options: map[string]any{"status_code": true}}},
		PostAnalysis: c.reportGuidance(),
	})

	return &plugins.Playbook{
		Name:        c.Name,
		Description: c.Description,
		Author:      plugins.PlaybookAuthor{Name: "Armur AI", GitHub: "Armur-Ai"},
		Version:     "1.0.0",
		Tags:        c.Tags,
		Phases:      phases,
	}
}

func (c *ExploitChain) fingerprintGuidance() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Confirm the target is %s", c.Product)
	if c.Affected != "" {
		fmt.Fprintf(&b, " in the affected range (%s)", c.Affected)
	}
	b.WriteString(". Signals:")
	for _, s := range c.Fingerprint.Signals {
		fmt.Fprintf(&b, "\n  - %s", s)
	}
	if c.Fingerprint.Notes != "" {
		fmt.Fprintf(&b, "\n%s", c.Fingerprint.Notes)
	}
	b.WriteString("\nIf it is not this product/version, stop and report 'not affected' — do not proceed.")
	return b.String()
}

func (c *ExploitChain) linkGuidance(i int, link Link) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Chain link %d/%d: %s", i+1, len(c.Links), link.Name)
	if link.CVE != "" {
		fmt.Fprintf(&b, " (%s)", link.CVE)
	}
	if link.Enables != "" {
		fmt.Fprintf(&b, "\nEnables: %s", link.Enables)
	}
	fmt.Fprintf(&b, "\nSAFE verification (non-weaponized — confirm, never detonate):\n%s", strings.TrimSpace(link.Verify))
	return b.String()
}

func (c *ExploitChain) reportGuidance() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Report the exploit chain %q against %s.\n", c.Name, c.Product)
	fmt.Fprintf(&b, "CVEs: %s  ·  CVSS: %.1f  ·  Severity: %s\n", strings.Join(c.CVEs, ", "), c.CVSS, c.Severity)
	b.WriteString("Include: which links were confirmed reachable, the fingerprint evidence, and the full ")
	b.WriteString("chained path (link → link → outcome). Do NOT include a working exploit payload.\n")
	if c.Remediation != "" {
		fmt.Fprintf(&b, "Remediation: %s", strings.TrimSpace(c.Remediation))
	}
	return b.String()
}
