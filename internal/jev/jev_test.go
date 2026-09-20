package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTruePositiveProbabilities(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var req sysOneRequest
		json.NewDecoder(r.Body).Decode(&req)
		ans := map[string]answer{}
		for id := range req.Questions {
			// echo a deterministic score: "real" ids high, "fp" ids low
			p := 0.9
			if id == "fp" {
				p = 0.1
			}
			ans[id] = answer{Type: "noul", Noul: p}
		}
		json.NewEncoder(w).Encode(sysOneResponse{Model: req.Model, Answers: ans})
	}))
	defer srv.Close()

	c := New("test-key", WithEndpoint(srv.URL))
	probs, err := c.TruePositiveProbabilities(context.Background(), "Target: crapi",
		map[string]string{"real": "JWT alg:none takeover", "fp": "missing security header"})
	if err != nil {
		t.Fatal(err)
	}
	if probs["real"] != 0.9 || probs["fp"] != 0.1 {
		t.Fatalf("unexpected probs: %v", probs)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth header = %q", gotAuth)
	}
}

func TestUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New("bad", WithEndpoint(srv.URL))
	if err := c.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected 401 error")
	}
}
