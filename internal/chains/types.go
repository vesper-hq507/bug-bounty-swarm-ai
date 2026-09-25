// Package chains defines exploit chains: named, versioned, CVE-tied attacks
// where one vulnerability enables the next (e.g. SSRF → unauthenticated RCE).
//
// An exploit chain is a distinct concept from a playbook (a tool-orchestration
// workflow) and from a kill chain (the runtime composition of findings into a
// narrative). The swarm fingerprints the target, SAFELY verifies each link
// (non-weaponized — confirm reachability/impact, never detonate), and reports
// the full path with CVEs, CVSS, and remediation.
package chains

// ExploitChain is one named exploit chain in the library.
type ExploitChain struct {
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description" json:"description"`
	CVEs        []string    `yaml:"cves" json:"cves"`
	Product     string      `yaml:"product" json:"product"`
	Affected    string      `yaml:"affected,omitempty" json:"affected,omitempty"`
	CVSS        float64     `yaml:"cvss,omitempty" json:"cvss,omitempty"`
	Severity    string      `yaml:"severity,omitempty" json:"severity,omitempty"`
	Tags        []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
	References  []string    `yaml:"references,omitempty" json:"references,omitempty"`
	Fingerprint Fingerprint `yaml:"fingerprint" json:"fingerprint"`
	Links       []Link      `yaml:"links" json:"links"`
	Remediation string      `yaml:"remediation,omitempty" json:"remediation,omitempty"`
}

// Fingerprint describes how to confirm the target is the affected product/version
// before any verification runs — cheap, safe, and it gates the rest of the chain.
type Fingerprint struct {
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`     // paths to probe (httpx)
	Signals []string `yaml:"signals,omitempty" json:"signals,omitempty"` // response cues that confirm the product/version
	Notes   string   `yaml:"notes,omitempty" json:"notes,omitempty"`     // free-text fingerprinting guidance
}

// Link is one step of the chain: a single vulnerability that enables the next.
// Verify is SAFE, non-weaponized guidance the swarm follows to confirm the link
// is present/reachable without exploiting it destructively.
type Link struct {
	Name   string `yaml:"name" json:"name"`
	CVE    string `yaml:"cve,omitempty" json:"cve,omitempty"`
	Enables string `yaml:"enables,omitempty" json:"enables,omitempty"` // what this link unlocks (the next link / outcome)
	Verify string `yaml:"verify" json:"verify"`                       // safe verification guidance (non-weaponized)
}
