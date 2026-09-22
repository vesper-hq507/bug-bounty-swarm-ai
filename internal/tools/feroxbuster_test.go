package tools

import "testing"

func TestFeroxbusterTool_Name(t *testing.T) {
	if n := NewFeroxbusterTool().Name(); n != "feroxbuster" {
		t.Errorf("Name() = %q, want \"feroxbuster\"", n)
	}
}

func TestFeroxbusterTool_IsAvailable(t *testing.T) { _ = NewFeroxbusterTool().IsAvailable() }

// TestParseFeroxbusterJSON_ResponsesEmitted — feroxbuster's --json mode
// emits NDJSON interleaving config, response, and statistics records.
// The parser keeps only `response` records, one finding each.
func TestParseFeroxbusterJSON_ResponsesEmitted(t *testing.T) {
	input := []byte(`{"type":"configuration","wordlist":"common.txt"}
{"type":"response","url":"https://target.example.com/admin","path":"/admin","method":"GET","status":200,"content_length":1234,"line_count":42,"word_count":210}
{"type":"response","url":"https://target.example.com/login","path":"/login","method":"GET","status":301,"content_length":0,"line_count":0,"word_count":0}
{"type":"statistics","requests":4714,"status_200s":2}`)
	findings := parseFeroxbusterJSON(input)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f["tool"] != "feroxbuster" {
			t.Errorf("tool = %v", f["tool"])
		}
		if f["severity"] != "info" {
			t.Errorf("severity = %v, want \"info\"", f["severity"])
		}
	}
	if findings[0]["url"] != "https://target.example.com/admin" || findings[0]["status"] != 200 {
		t.Errorf("first finding shape wrong: %+v", findings[0])
	}
	if findings[0]["content_length"] != int64(1234) {
		t.Errorf("content_length not carried through: %+v", findings[0])
	}
	if findings[1]["path"] != "/login" || findings[1]["status"] != 301 {
		t.Errorf("second finding shape wrong: %+v", findings[1])
	}
}

// TestParseFeroxbusterJSON_NoResponses — a scan that found nothing still
// emits config/statistics records; the parser produces no findings.
func TestParseFeroxbusterJSON_NoResponses(t *testing.T) {
	input := []byte(`{"type":"configuration","wordlist":"common.txt"}
{"type":"statistics","requests":4714,"status_200s":0}`)
	if got := parseFeroxbusterJSON(input); len(got) != 0 {
		t.Errorf("no responses should produce no findings; got %d", len(got))
	}
}

func TestParseFeroxbusterJSON_MalformedReturnsNil(t *testing.T) {
	for _, c := range [][]byte{nil, []byte(""), []byte("{not json"), []byte("garbage")} {
		if got := parseFeroxbusterJSON(c); got != nil {
			t.Errorf("input %q should produce nil, got %v", c, got)
		}
	}
}
