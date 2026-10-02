package approval

import (
	"net/http"
	"net/url"
	"strings"
)

func ClassifyHTTP(explicit, method, rawURL string, race int) Capability {
	if race > 1 {
		return CapabilityConcurrency
	}
	if capability, err := ParseCapability(explicit); err == nil && capability != CapabilityObserve {
		return capability
	}

	path := strings.ToLower(rawURL)
	if u, err := url.Parse(rawURL); err == nil {
		path = strings.ToLower(u.Path)
	}
	if isUploadPath(path) {
		return CapabilityUpload
	}
	if isAccountChangePath(path) && mutatingMethod(method) {
		return CapabilityAccountChange
	}
	if mutatingMethod(method) {
		return CapabilityStateChange
	}
	if capability, err := ParseCapability(explicit); err == nil {
		return capability
	}
	return CapabilityObserve
}

func ClassifyExternal(explicit string, mutatesState bool) Capability {
	if capability, err := ParseCapability(explicit); err == nil {
		return capability
	}
	if mutatesState {
		return CapabilityStateChange
	}
	return CapabilityObserve
}

func mutatingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isUploadPath(path string) bool {
	for _, token := range []string{"/upload", "/uploads", "/attachment", "/attachments", "/import"} {
		if strings.Contains(path, token) {
			return true
		}
	}
	return false
}

func isAccountChangePath(path string) bool {
	for _, token := range []string{
		"/signup", "/register", "/password", "/account", "/profile",
		"/role", "/permission", "/invite", "/member", "/user",
	} {
		if strings.Contains(path, token) {
			return true
		}
	}
	return false
}
