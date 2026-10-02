package tools

import (
	"fmt"
	"math"
	"sort"
)

// programMaxRPS returns the normalized program-level request cap propagated by
// the coordinator. Zero means no rate constraint was imported.
func programMaxRPS(opts Options) float64 {
	v, ok := opts["program_max_rps"]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

// programRequiredHeaders returns stable "Name: Value" strings for CLI adapters.
func programRequiredHeaders(opts Options) []string {
	raw, ok := opts["program_required_headers"].(map[string]string)
	if !ok || len(raw) == 0 {
		return nil
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" || raw[k] == "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s", k, raw[k]))
	}
	return out
}

// projectDiscoveryPolicyArgs maps the program policy to the common
// ProjectDiscovery -rl/-rlm and -H flags. Rounding is always downward so the
// generated rate never exceeds the program maximum.
func projectDiscoveryPolicyArgs(opts Options) []string {
	var args []string
	if rate := programMaxRPS(opts); rate > 0 {
		if rate >= 1 {
			args = append(args, "-rl", fmt.Sprintf("%d", maxPolicyInt(1, int(math.Floor(rate)))))
		} else {
			perMinute := maxPolicyInt(1, int(math.Floor(rate*60)))
			args = append(args, "-rlm", fmt.Sprintf("%d", perMinute))
		}
	}
	for _, h := range programRequiredHeaders(opts) {
		args = append(args, "-H", h)
	}
	return args
}

func integerRPS(opts Options) (int, error) {
	rate := programMaxRPS(opts)
	if rate <= 0 {
		return 0, nil
	}
	if rate < 1 {
		return 0, fmt.Errorf("program rate %.4f req/s is below this adapter's minimum safe granularity", rate)
	}
	return maxPolicyInt(1, int(math.Floor(rate))), nil
}

func maxPolicyInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
