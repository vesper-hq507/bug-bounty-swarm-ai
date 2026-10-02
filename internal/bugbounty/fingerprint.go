package bugbounty

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

type FindingFingerprint struct {
	Program             string   `json:"program,omitempty"`
	Asset               string   `json:"asset,omitempty"`
	Endpoint            string   `json:"endpoint,omitempty"`
	Method              string   `json:"method,omitempty"`
	CWE                 string   `json:"cwe,omitempty"`
	Parameter           string   `json:"parameter,omitempty"`
	RootCause           string   `json:"root_cause,omitempty"`
	AffectedRoles       []string `json:"affected_roles,omitempty"`
	EvidenceFingerprint string   `json:"evidence_fingerprint,omitempty"`
	CVEIDs              []string `json:"cve_ids,omitempty"`
}

type FingerprintMatch struct {
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

var parameterPattern = regexp.MustCompile("(?i)(?:parameter|param)\\s+['\"]?([a-zA-Z0-9_.-]+)")

func FingerprintReportFinding(program string, finding pipeline.ReportFinding) FindingFingerprint {
	fp := FindingFingerprint{
		Program:             strings.ToLower(strings.TrimSpace(program)),
		CWE:                 strings.ToUpper(strings.TrimSpace(finding.CWE)),
		RootCause:           normalizeRootCause(finding.Title),
		EvidenceFingerprint: evidenceFingerprint(finding.Evidence),
	}
	if len(finding.AffectedComponents) > 0 {
		fp.Asset, fp.Endpoint = assetAndEndpoint(finding.AffectedComponents[0])
	}
	if finding.Reproduce != nil && finding.Reproduce.HTTPRequest != "" {
		fp.Method, fp.Endpoint = parseHTTPRequestLine(finding.Reproduce.HTTPRequest, fp.Endpoint)
	}
	if m := parameterPattern.FindStringSubmatch(finding.Title); len(m) == 2 {
		fp.Parameter = strings.ToLower(m[1])
	}
	return fp
}

func FingerprintClassifiedFinding(program string, finding pipeline.ClassifiedFinding) FindingFingerprint {
	asset, endpoint := assetAndEndpoint(finding.Target)
	return FindingFingerprint{
		Program:   strings.ToLower(strings.TrimSpace(program)),
		Asset:     asset,
		Endpoint:  endpoint,
		RootCause: normalizeRootCause(finding.Title + " " + finding.AttackCategory),
		CVEIDs:    sortedLower(finding.CVEIDs),
	}
}

func CompareFingerprints(a, b FindingFingerprint) FingerprintMatch {
	var score, total float64
	var reasons []string
	compare := func(weight float64, left, right, label string) {
		if left == "" || right == "" {
			return
		}
		total += weight
		if strings.EqualFold(left, right) {
			score += weight
			reasons = append(reasons, label)
		}
	}
	compare(0.10, a.Program, b.Program, "same program")
	compare(0.15, a.Asset, b.Asset, "same asset")
	compare(0.20, a.Endpoint, b.Endpoint, "same endpoint")
	compare(0.10, a.Method, b.Method, "same HTTP method")
	compare(0.15, a.CWE, b.CWE, "same CWE")
	compare(0.10, a.Parameter, b.Parameter, "same parameter")
	compare(0.10, a.RootCause, b.RootCause, "same root-cause signature")
	compare(0.20, a.EvidenceFingerprint, b.EvidenceFingerprint, "same evidence fingerprint")

	if overlapAny(a.CVEIDs, b.CVEIDs) {
		total += 0.35
		score += 0.35
		reasons = append(reasons, "same CVE")
	}
	if overlapAny(a.AffectedRoles, b.AffectedRoles) {
		total += 0.05
		score += 0.05
		reasons = append(reasons, "overlapping affected roles")
	}
	if total == 0 {
		return FingerprintMatch{}
	}
	return FingerprintMatch{Score: score / total, Reasons: reasons}
}

func assetAndEndpoint(raw string) (asset, endpoint string) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		return strings.ToLower(u.Host), u.EscapedPath()
	}
	if raw == "" {
		return "", ""
	}
	return strings.ToLower(raw), ""
}

func parseHTTPRequestLine(raw, fallbackPath string) (method, endpoint string) {
	line, _, _ := strings.Cut(raw, "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", fallbackPath
	}
	method = strings.ToUpper(fields[0])
	path := fields[1]
	if u, err := url.Parse(path); err == nil && u.Path != "" {
		path = u.EscapedPath()
	}
	return method, path
}

func evidenceFingerprint(evidence []pipeline.Evidence) string {
	if len(evidence) == 0 {
		return ""
	}
	parts := make([]string, 0, len(evidence))
	for i := range evidence {
		e := &evidence[i]
		switch {
		case e.RecordID != "" && e.IntegrityHash != "":
			parts = append(parts, e.RecordID+":"+e.IntegrityHash)
		case e.IntegrityHash != "":
			parts = append(parts, e.IntegrityHash)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func normalizeRootCause(s string) string {
	words := strings.Fields(strings.ToLower(s))
	out := make([]string, 0, len(words))
	for _, word := range words {
		word = strings.Trim(word, ".,:;()[]{}'\"")
		if len(word) < 3 {
			continue
		}
		out = append(out, word)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return strings.Join(out, " ")
}

func sortedLower(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func overlapAny(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, value := range a {
		set[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range b {
		if _, ok := set[strings.ToLower(value)]; ok {
			return true
		}
	}
	return false
}
