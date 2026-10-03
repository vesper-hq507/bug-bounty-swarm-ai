package hackerone

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateReportPostsRequiredHackerPayload(t *testing.T) {
	var got createReportEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/hackers/reports" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		user, token, ok := r.BasicAuth()
		if !ok || user != "researcher" || token != "token" {
			t.Fatalf("basic auth user=%q token=%q ok=%v", user, token, ok)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":12345,"attributes":{"title":"IDOR","state":"new"}}}`))
	}))
	defer srv.Close()

	client := NewClient(Config{APIUser: "researcher", APIToken: "token"})
	client.baseURL = srv.URL + "/v1"
	created, err := client.CreateReport(context.Background(), CreateReportInput{
		TeamHandle: "acme",
		Title: "IDOR",
		VulnerabilityInformation: "Steps and evidence",
		Impact: "Cross-account data exposure",
		SeverityRating: "high",
		WeaknessID: 639,
		StructuredScopeID: 77,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "12345" || created.Title != "IDOR" || created.State != "new" {
		t.Fatalf("created=%+v", created)
	}
	if got.Data.Type != "report" ||
		got.Data.Attributes.TeamHandle != "acme" ||
		got.Data.Attributes.Title != "IDOR" ||
		got.Data.Attributes.WeaknessID != 639 ||
		got.Data.Attributes.StructuredScopeID != 77 {
		t.Fatalf("payload=%+v", got)
	}
}

func TestCreateReportRejectsInvalidInputBeforeNetwork(t *testing.T) {
	client := NewClient(Config{APIUser: "researcher", APIToken: "token"})
	_, err := client.CreateReport(context.Background(), CreateReportInput{
		TeamHandle: "acme",
		Title: "title",
		VulnerabilityInformation: "details",
		Impact: "impact",
		SeverityRating: "impossible",
	})
	if err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateReportSurfacesBoundedAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "program does not accept reports", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	client := NewClient(Config{APIUser: "researcher", APIToken: "token"})
	client.baseURL = srv.URL
	_, err := client.CreateReport(context.Background(), CreateReportInput{
		TeamHandle: "acme",
		Title: "IDOR",
		VulnerabilityInformation: "details",
		Impact: "impact",
	})
	if err == nil || !strings.Contains(err.Error(), "422") {
		t.Fatalf("err=%v", err)
	}
}
