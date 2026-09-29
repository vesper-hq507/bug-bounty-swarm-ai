package poc

import (
	"regexp"
	"strings"
)

// has reports whether s contains any of the keywords (case handled by caller).
func has(s string, kws ...string) bool {
	for _, k := range kws {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// dangerous matches destructive / disruptive constructs that must never appear
// in a proof-of-concept. A PoC proves a bug; it never breaks things.
// Case-insensitive where it matters.
var dangerous = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b`), // rm -rf / -fr
	regexp.MustCompile(`(?i)\brmdir\b`),
	regexp.MustCompile(`(?i)shutil\.rmtree`),
	regexp.MustCompile(`(?i)\bos\.(remove|unlink|rmdir)\b`),
	regexp.MustCompile(`(?i)\b(DROP|TRUNCATE)\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
	regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
	regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
	regexp.MustCompile(`(?i)\bmkfs\b|\bdd\s+if=`),
	regexp.MustCompile(`(?i)\b(shutdown|reboot|halt|poweroff)\b`),
	regexp.MustCompile(`:\(\)\s*\{`),                                      // fork bomb :(){ :|:& };:
	regexp.MustCompile(`(?i)fork\s*bomb`),                                 //
	regexp.MustCompile(`(?i)while\s+true\s*:\s*$`),                        // bare infinite loop (DoS)
	regexp.MustCompile(`(?i)\bopen\s*\([^)]*['"]w`),                       // opening a file for writing (on target/local fs)
	regexp.MustCompile(`(?i)/etc/shadow|id_rsa|\.aws/credentials|\.ssh/`), // sensitive-file targets
	regexp.MustCompile(`(?i)metadata[^\n]*iam|/latest/meta-data/iam`),     // cloud credential paths
}

// SafetyIssue names a rejected pattern for reporting/repair.
type SafetyIssue = string

// safetyScan returns the dangerous patterns found in a script. Empty means the
// script passed. This is defence-in-depth behind the prompt — generated code is
// never trusted on the model's word alone.
func safetyScan(script string) []SafetyIssue {
	var hits []SafetyIssue
	for _, re := range dangerous {
		if re.MatchString(script) {
			hits = append(hits, re.String())
		}
	}
	return hits
}
