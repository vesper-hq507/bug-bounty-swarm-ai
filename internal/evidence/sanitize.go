package evidence

import (
	"net/http"
	"regexp"
	"strings"
)

var secretHeaderNames = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"proxy-authorization": {},
}

var bearerPattern = regexp.MustCompile("(?i)bearer\\s+[a-z0-9._~+/=-]+")
var jsonSecretPattern = regexp.MustCompile("(?i)(\\\"(?:password|token|access_token|refresh_token|secret|api_key)\\\"\\s*:\\s*\\\")([^\\\"]*)(\\\")")

func SanitizeHeaders(h http.Header) (map[string]string, []Redaction) {
	out := make(map[string]string, len(h))
	var redactions []Redaction
	for k, vals := range h {
		if _, sensitive := secretHeaderNames[strings.ToLower(k)]; sensitive {
			out[k] = "[REDACTED]"
			redactions = append(redactions, Redaction{Field: k, Reason: "sensitive header"})
			continue
		}
		out[k] = strings.Join(vals, ", ")
	}
	return out, redactions
}

func SanitizeText(s string) (string, []Redaction) {
	if s == "" {
		return "", nil
	}
	var redactions []Redaction
	if bearerPattern.MatchString(s) {
		s = bearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
		redactions = append(redactions, Redaction{Field: "authorization", Reason: "bearer token"})
	}
	if jsonSecretPattern.MatchString(s) {
		s = jsonSecretPattern.ReplaceAllString(s, "$1[REDACTED]$3")
		redactions = append(redactions, Redaction{Field: "json-secret", Reason: "sensitive field"})
	}
	return s, redactions
}
