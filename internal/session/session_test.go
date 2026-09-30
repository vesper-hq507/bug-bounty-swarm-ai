package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	h := ParseHeaders([]string{"X-Api-Key: abc", "malformed", ": nope", "Bad:"}, "sess=xyz", "tok123")
	if h["X-Api-Key"] != "abc" {
		t.Errorf("raw header lost: %v", h)
	}
	if h["Cookie"] != "sess=xyz" {
		t.Errorf("cookie lost: %v", h)
	}
	if h["Authorization"] != "Bearer tok123" {
		t.Errorf("bearer not normalized: %v", h)
	}
	if _, ok := h["Bad"]; ok {
		t.Errorf("malformed header should be dropped: %v", h)
	}
}

func TestParseHeaders_EmptyIsNil(t *testing.T) {
	if ParseHeaders(nil, "", "") != nil {
		t.Error("no inputs should yield nil")
	}
}

func TestParseHeaders_BearerPrefixKept(t *testing.T) {
	if h := ParseHeaders(nil, "", "Bearer already"); h["Authorization"] != "Bearer already" {
		t.Errorf("existing Bearer prefix double-added: %v", h)
	}
}

// Wrap injects session headers on every request through the client.
func TestSession_WrapInjectsHeaders(t *testing.T) {
	var gotAuth, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
	}))
	defer srv.Close()

	s := New(ParseHeaders(nil, "sid=1", "abc"))
	client := s.Wrap(srv.Client())
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer abc" {
		t.Errorf("Authorization not injected: %q", gotAuth)
	}
	if gotCookie != "sid=1" {
		t.Errorf("Cookie not injected: %q", gotCookie)
	}
}

// A nil/empty session returns the client unchanged (call sites wrap unconditionally).
func TestSession_WrapNilPassthrough(t *testing.T) {
	c := &http.Client{}
	if got := (*Session)(nil).Wrap(c); got != c {
		t.Error("nil session must return the same client")
	}
	if got := New(nil).Wrap(c); got != c {
		t.Error("empty session must return the same client")
	}
}

// Apply must not clobber a header the caller set explicitly.
func TestSession_ApplyDoesNotClobber(t *testing.T) {
	s := New(map[string]string{"Authorization": "Bearer session"})
	r, _ := http.NewRequest("GET", "http://x", nil)
	r.Header.Set("Authorization", "Bearer explicit")
	s.Apply(r)
	if r.Header.Get("Authorization") != "Bearer explicit" {
		t.Errorf("session clobbered an explicit header: %q", r.Header.Get("Authorization"))
	}
}
