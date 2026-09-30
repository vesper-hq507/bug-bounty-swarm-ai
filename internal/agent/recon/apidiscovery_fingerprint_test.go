package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Vamsi #6: an app that answers non-404 for everything (catch-all / SPA / WAF)
// must NOT be mis-fingerprinted as a known profile, and a well-behaved app that
// 404s on garbage but answers the signature route SHOULD match.
func TestApiProfile_NegativeControlGuardsFingerprint(t *testing.T) {
	prof := apiProfile{
		name:       "test",
		signatures: []signatureRoute{{method: "POST", path: "/identity/api/auth/login"}},
	}

	// Catch-all app: 401 for every path, including random garbage.
	catchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer catchAll.Close()
	if prof.matches(context.Background(), catchAll.URL, catchAll.Client()) {
		t.Error("a 401-on-everything app must not fingerprint as the profile (the #6 misfire)")
	}

	// Realistic app: 404 on unknown paths, 401 on the real signature route.
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/api/auth/login" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer real.Close()
	if !prof.matches(context.Background(), real.URL, real.Client()) {
		t.Error("app that 404s on garbage but answers the signature route should match")
	}

	// SPA-style app: 200 for everything (serves index.html) — must not match.
	spa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer spa.Close()
	if prof.matches(context.Background(), spa.URL, spa.Client()) {
		t.Error("a 200-on-everything SPA must not fingerprint as the profile")
	}
}
