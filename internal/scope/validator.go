package scope

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	apperrors "github.com/Armur-Ai/Pentest-Swarm-AI/internal/errors"
)

// ScopeDefinition defines what targets are allowed.
type ScopeDefinition struct {
	AllowedCIDRs           []string          `json:"allowed_cidrs"            yaml:"allowed_cidrs"`
	AllowedDomains         []string          `json:"allowed_domains"          yaml:"allowed_domains"`
	AllowedSourceCode      []string          `json:"allowed_source_code"      yaml:"allowed_source_code,omitempty"`
	SourceCodeInstructions map[string]string `json:"source_code_instructions" yaml:"source_code_instructions,omitempty"`
	AllowedPorts           []int             `json:"allowed_ports"            yaml:"allowed_ports,omitempty"` // empty means all ports allowed
	ExcludedCIDRs          []string          `json:"excluded_cidrs"           yaml:"excluded_cidrs,omitempty"`
	ExcludedDomains        []string          `json:"excluded_domains"         yaml:"excluded_domains,omitempty"`
}

// Validate checks whether a target (IP, domain, or URL) is within scope.
// Returns nil if in scope, ErrScopeViolation if not.
func Validate(target string, scope ScopeDefinition) error {
	if len(scope.AllowedCIDRs) == 0 && len(scope.AllowedDomains) == 0 {
		return &apperrors.ScopeViolationError{
			Target: target,
			Scope:  "<empty>",
			Detail: "scope has no allowed CIDRs or domains defined",
		}
	}

	// Try parsing as URL first
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err == nil {
			host := parsed.Hostname()
			return validateHost(host, scope)
		}
	}

	// Try as host:port
	if host, _, err := net.SplitHostPort(target); err == nil {
		return validateHost(host, scope)
	}

	// Plain IP or domain
	return validateHost(target, scope)
}

func validateHost(host string, scope ScopeDefinition) error {
	// Check if it's an IP
	ip := net.ParseIP(host)
	if ip != nil {
		return validateIP(ip, scope)
	}

	// It's a domain
	return validateDomain(host, scope)
}

func validateIP(ip net.IP, scope ScopeDefinition) error {
	// Check exclusions first
	for _, cidr := range scope.ExcludedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return &apperrors.ScopeViolationError{
				Target: ip.String(),
				Scope:  cidr,
				Detail: "IP is in excluded CIDR range",
			}
		}
	}

	// Check allowed CIDRs
	for _, cidr := range scope.AllowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return nil // in scope
		}
	}

	// Check if IP resolves to an allowed domain — but we don't do reverse DNS
	// to avoid complexity. IP must be in an allowed CIDR.
	return &apperrors.ScopeViolationError{
		Target: ip.String(),
		Scope:  strings.Join(scope.AllowedCIDRs, ", "),
		Detail: "IP is not in any allowed CIDR range",
	}
}

func validateDomain(domain string, scope ScopeDefinition) error {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, excluded := range scope.ExcludedDomains {
		if domainMatches(domain, excluded) {
			return &apperrors.ScopeViolationError{
				Target: domain,
				Scope:  excluded,
				Detail: "domain is explicitly excluded from program scope",
			}
		}
	}

	for _, allowed := range scope.AllowedDomains {
		if domainMatches(domain, allowed) {
			return nil
		}
	}

	return &apperrors.ScopeViolationError{
		Target: domain,
		Scope:  strings.Join(scope.AllowedDomains, ", "),
		Detail: "domain is not in any allowed domain scope",
	}
}

func domainMatches(domain, rule string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	rule = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule), "."))
	if domain == "" || rule == "" {
		return false
	}
	if domain == rule {
		return true
	}
	if strings.HasPrefix(rule, "*.") {
		return strings.HasSuffix(domain, rule[1:])
	}
	return strings.HasSuffix(domain, "."+rule)
}

// ValidateSourceCode checks an exact source-code repository target against the
// structured source-code scope. It never treats github.com itself as scope.
func ValidateSourceCode(target string, def ScopeDefinition) error {
	normalized, err := normalizeSourceCodeURL(target)
	if err != nil {
		return &apperrors.ScopeViolationError{
			Target: target,
			Scope:  strings.Join(def.AllowedSourceCode, ", "),
			Detail: err.Error(),
		}
	}
	for _, allowed := range def.AllowedSourceCode {
		candidate, err := normalizeSourceCodeURL(allowed)
		if err == nil && candidate == normalized {
			return nil
		}
	}
	return &apperrors.ScopeViolationError{
		Target: target,
		Scope:  strings.Join(def.AllowedSourceCode, ", "),
		Detail: "source-code repository is not an exact allowed source-code asset",
	}
}

// SourceCodeInstruction returns the program instruction associated with an
// exact source-code asset, if the platform supplied one.
func SourceCodeInstruction(target string, def ScopeDefinition) string {
	normalized, err := normalizeSourceCodeURL(target)
	if err != nil {
		return ""
	}
	for raw, instruction := range def.SourceCodeInstructions {
		candidate, err := normalizeSourceCodeURL(raw)
		if err == nil && candidate == normalized {
			return strings.TrimSpace(instruction)
		}
	}
	return ""
}

func normalizeSourceCodeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("source-code target must be an https repository URL")
	}
	host := strings.ToLower(u.Hostname())
	path := strings.TrimSuffix(strings.TrimSuffix(u.EscapedPath(), "/"), ".git")
	if host == "" || path == "" || path == "/" {
		return "", fmt.Errorf("source-code target must identify a repository")
	}
	return "https://" + host + path, nil
}

// ipAndDomainPattern matches IPs and domain-like strings in command text.
var ipAndDomainPattern = regexp.MustCompile(
	`(?:` +
		// IPv4
		`\b(?:\d{1,3}\.){3}\d{1,3}\b` +
		`|` +
		// Domain names (simplified but effective)
		`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b` +
		`)`,
)

// ValidateCommand extracts all IPs and domains from a command string and validates
// each against the scope. Returns ErrScopeViolation if any target is out of scope.
// This is called before every command execution — no exceptions.
func ValidateCommand(cmd string, scope ScopeDefinition) error {
	for _, loc := range ipAndDomainPattern.FindAllStringIndex(cmd, -1) {
		match := cmd[loc[0]:loc[1]]

		// Skip common non-target strings
		if isCommonNonTarget(match) {
			continue
		}

		// Skip the domain half of an email address (or URL userinfo): a match
		// immediately preceded by "@" is a payload value like the address in a
		// signup body — atk@example.com — not a host the command scans. The
		// actual request target (a tool's target arg, or httpreq's --url) is
		// validated on its own, so this only suppresses false positives on
		// data embedded in request bodies, never a real out-of-scope target.
		if loc[0] > 0 && cmd[loc[0]-1] == '@' {
			continue
		}

		if err := Validate(match, scope); err != nil {
			return fmt.Errorf("command contains out-of-scope target: %w", err)
		}
	}

	return nil
}

// isCommonNonTarget filters out strings that look like domains/IPs but aren't targets.
func isCommonNonTarget(s string) bool {
	s = strings.ToLower(s)

	nonTargets := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"github.com",
		"golang.org",
		"google.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"huggingface.co",
	}

	for _, nt := range nonTargets {
		if s == nt {
			return true
		}
	}

	// Skip common file extensions that look like domains
	fileExtensions := []string{".yaml", ".yml", ".json", ".xml", ".txt", ".log", ".conf", ".cfg"}
	for _, ext := range fileExtensions {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}

	return false
}
