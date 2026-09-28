package attackgraph

import (
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// EntryID and objectiveID are the fixed synthetic endpoints of a built graph.
const EntryID = "entry"
const objectiveID = "objective"

// BuildFromFindings turns a campaign's classified findings into an attack graph:
// an unauthenticated entry, a node per finding (typed by attack class, weighted
// by exploitability), edges from entry into each finding, edges between findings
// that enable one another, and edges from impactful findings (privesc/RCE) to
// the declared objective. ShortestPath(EntryID, objectiveID) then yields the
// most-likely path to impact. objectiveLabel names the crown jewel.
func BuildFromFindings(findings []pipeline.ClassifiedFinding, objectiveLabel string) *Graph {
	if objectiveLabel == "" {
		objectiveLabel = "full compromise"
	}
	g := New()
	g.AddNode(Node{ID: EntryID, Type: NodeEntry, Label: "unauthenticated attacker"})
	g.AddNode(Node{ID: objectiveID, Type: NodeObjective, Label: objectiveLabel})

	kind := make([]string, len(findings))
	ids := make([]string, len(findings))
	for i, f := range findings {
		id := "f:" + shortID(f, i)
		ids[i] = id
		k := classifyFinding(f)
		kind[i] = k
		g.AddNode(Node{ID: id, Type: nodeTypeFor(k), Label: f.Title,
			Meta: map[string]string{"class": k, "severity": string(f.Severity), "cves": strings.Join(f.CVEIDs, ",")}})
		exp := exploitability(f)
		// entry can attempt every finding directly
		g.AddEdge(Edge{From: EntryID, To: id, Type: edgeTypeFor(k), Exploitability: exp, Detail: f.Title})
		// impactful findings reach the objective
		if grantsImpact(k) {
			g.AddEdge(Edge{From: id, To: objectiveID, Type: EdgeEscalates, Exploitability: exp, Detail: f.Title})
		}
		// SSRF → cloud metadata (IMDS) → stolen cloud credentials → objective:
		// model the cloud-credential-theft chain as a shared capability node.
		if k == "ssrf" {
			const cc = "cap:cloud-creds"
			g.AddNode(Node{ID: cc, Type: NodeCapability, Label: "cloud credentials (IMDS)"})
			g.AddEdge(Edge{From: id, To: cc, Type: EdgeLeaks, Exploitability: exp * 0.8, Detail: "SSRF → metadata service"})
			g.AddEdge(Edge{From: cc, To: objectiveID, Type: EdgeEscalates, Exploitability: 0.9, Detail: "assume role / access cloud"})
		}
	}
	// findings that enable one another (leak → cred → privesc, etc.)
	for i := range findings {
		for j := range findings {
			if i == j {
				continue
			}
			if enables(kind[i], kind[j]) {
				exp := minf(exploitability(findings[i]), exploitability(findings[j]))
				g.AddEdge(Edge{From: ids[i], To: ids[j], Type: EdgeEscalates, Exploitability: exp})
			}
		}
	}
	return g
}

// classifyFinding maps a finding to an attack class from its category + title.
func classifyFinding(f pipeline.ClassifiedFinding) string {
	t := strings.ToLower(f.AttackCategory + " " + f.Title + " " + f.Description)
	switch {
	case has(t, "rce", "remote code", "command injection", "deserial", "webshell"):
		return "rce"
	case has(t, "bfla", "privilege", "privesc", "admin", "role"):
		return "privesc"
	case has(t, "bola", "idor", "object-level", "object level"):
		return "bola"
	case has(t, "jwt", "token", "auth bypass", "authentication", "session", "credential", "cred"):
		return "cred"
	case has(t, "ssrf", "metadata"):
		return "ssrf"
	case has(t, "leak", "exposure", "exposed", "verbose", "disclosure", "secret", "sqli", "injection"):
		return "leak"
	default:
		return "recon"
	}
}

func nodeTypeFor(kind string) NodeType {
	switch kind {
	case "cred":
		return NodeIdentity
	case "leak", "ssrf":
		return NodeSecret
	case "bola":
		return NodeObjectRef
	case "rce", "privesc":
		return NodeCapability
	default:
		return NodeEndpoint
	}
}

func edgeTypeFor(kind string) EdgeType {
	switch kind {
	case "cred":
		return EdgeAuthAs
	case "leak", "ssrf":
		return EdgeLeaks
	case "rce", "privesc":
		return EdgeEscalates
	default:
		return EdgeExploits
	}
}

// grantsImpact reports whether a class reaches the crown jewel on its own.
func grantsImpact(kind string) bool { return kind == "rce" || kind == "privesc" }

// enables encodes which class feeds which (a → b).
func enables(a, b string) bool {
	bridges := map[string][]string{
		"leak": {"cred", "ssrf", "rce"},
		"ssrf": {"cred", "rce"},
		"cred": {"bola", "privesc", "rce"},
		"bola": {"privesc"},
	}
	for _, x := range bridges[a] {
		if x == b {
			return true
		}
	}
	return false
}

// exploitability derives an edge weight from CVSS + confidence.
func exploitability(f pipeline.ClassifiedFinding) float64 {
	p := f.CVSSScore / 10.0
	if p <= 0 {
		p = 0.3 // unknown severity → modest prior
	}
	switch strings.ToLower(string(f.Confidence)) {
	case "high":
		// keep
	case "low":
		p *= 0.5
	default: // medium/unknown
		p *= 0.75
	}
	if p < 0.05 {
		p = 0.05
	}
	if p > 0.98 {
		p = 0.98
	}
	return p
}

func has(s string, kws ...string) bool {
	for _, k := range kws {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func shortID(f pipeline.ClassifiedFinding, i int) string {
	s := f.ID.String()
	if len(s) >= 8 {
		return s[:8]
	}
	return fmt.Sprintf("%d", i)
}

// ObjectiveID returns the id of the objective node in a built graph.
func ObjectiveID() string { return objectiveID }
