package scope

import (
	"regexp"
	"strings"
)

var commandURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// CommandTargets returns unique network targets embedded in a command. URLs are
// preferred so downstream policy can enforce path restrictions; bare hosts/IPs
// outside URL spans are returned as-is.
func CommandTargets(cmd string) []string {
	urls := commandURLPattern.FindAllStringIndex(cmd, -1)
	insideURL := func(pos int) bool {
		for _, loc := range urls {
			if pos >= loc[0] && pos < loc[1] {
				return true
			}
		}
		return false
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimRight(strings.TrimSpace(v), ".,);]")
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	for _, loc := range urls {
		add(cmd[loc[0]:loc[1]])
	}
	for _, loc := range ipAndDomainPattern.FindAllStringIndex(cmd, -1) {
		if insideURL(loc[0]) {
			continue
		}
		match := cmd[loc[0]:loc[1]]
		if isCommonNonTarget(match) {
			continue
		}
		if loc[0] > 0 && cmd[loc[0]-1] == '@' {
			continue
		}
		add(match)
	}
	return out
}
