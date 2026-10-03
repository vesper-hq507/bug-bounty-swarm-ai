package bugbounty

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// HistoricalReportFingerprintInput is the normalized metadata available from a
// prior platform report. VulnerabilityInformation is used transiently to derive
// routing/request clues and should not be copied into submission manifests.
type HistoricalReportFingerprintInput struct {
	Program                  string
	Title                    string
	VulnerabilityInformation string
	WeaknessName             string
	WeaknessExternalID       string
	AssetIdentifier          string
}

var (
	historicalRequestLine = regexp.MustCompile(`(?mi)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)`)
	historicalAbsoluteURL = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	historicalCWE         = regexp.MustCompile(`(?i)\bCWE[-_:\s]*(\d{1,5})\b`)
	historicalCVE         = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

// FingerprintHistoricalReport derives structured duplicate metadata without
// persisting a prior report's full narrative.
func FingerprintHistoricalReport(in HistoricalReportFingerprintInput) FindingFingerprint {
	fp := FindingFingerprint{
		Program:   strings.ToLower(strings.TrimSpace(in.Program)),
		RootCause: normalizeRootCause(in.Title + " " + in.WeaknessName),
	}
	fp.Asset, fp.Endpoint = assetAndEndpoint(in.AssetIdentifier)
	fp.CWE = normalizeHistoricalCWE(in.WeaknessExternalID + " " + in.WeaknessName)

	text := strings.TrimSpace(in.Title + "\n" + in.VulnerabilityInformation)
	if request := historicalRequestLine.FindStringSubmatch(in.VulnerabilityInformation); len(request) == 3 {
		fp.Method, fp.Endpoint = parseHTTPRequestLine(request[1]+" "+request[2], fp.Endpoint)
		if fp.Parameter == "" {
			fp.Parameter = firstQueryParameter(request[2])
		}
	}
	if absolute := historicalAbsoluteURL.FindString(text); absolute != "" {
		asset, endpoint := assetAndEndpoint(strings.TrimRight(absolute, ".,);]"))
		if fp.Asset == "" {
			fp.Asset = asset
		}
		if fp.Endpoint == "" {
			fp.Endpoint = endpoint
		}
		if fp.Parameter == "" {
			fp.Parameter = firstQueryParameter(absolute)
		}
	}
	if m := parameterPattern.FindStringSubmatch(text); len(m) == 2 {
		fp.Parameter = strings.ToLower(m[1])
	}

	cves := historicalCVE.FindAllString(text, -1)
	fp.CVEIDs = sortedLower(uniqueStrings(cves))
	return fp
}

// HistoricalFingerprintInformative prevents sparse report history (for
// example, only a title and program) from being treated as a strong structured
// duplicate. Sparse entries remain eligible for the legacy title fallback.
func HistoricalFingerprintInformative(fp FindingFingerprint) bool {
	score := 0
	if fp.Asset != "" {
		score++
	}
	if fp.Endpoint != "" {
		score++
	}
	if fp.Method != "" {
		score++
	}
	if fp.CWE != "" {
		score++
	}
	if fp.Parameter != "" {
		score++
	}
	if len(fp.CVEIDs) > 0 {
		score += 2
	}
	return score >= 2
}

func normalizeHistoricalCWE(raw string) string {
	m := historicalCWE.FindStringSubmatch(raw)
	if len(m) != 2 {
		return ""
	}
	return "CWE-" + m[1]
}

func firstQueryParameter(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(u.Query()))
	for key := range u.Query() {
		if key != "" {
			keys = append(keys, strings.ToLower(key))
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
