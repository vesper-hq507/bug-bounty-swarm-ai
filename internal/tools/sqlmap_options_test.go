package tools

import "testing"

func TestBuildSqlmapOptions_DetectionVsExploit(t *testing.T) {
	det := buildSqlmapOptions("http://x/?id=1", Options{})
	for _, k := range []string{"getCurrentUser", "isDba", "getDbs"} {
		if _, ok := det[k]; ok {
			t.Errorf("detection mode should NOT set %q", k)
		}
	}
	if det["level"] != 2 || det["risk"] != 1 {
		t.Errorf("defaults wrong: %v", det)
	}

	exp := buildSqlmapOptions("http://x/?id=1", Options{"exploit": true, "level": 3})
	for _, k := range []string{"getCurrentUser", "getCurrentDb", "isDba", "getBanner", "getDbs"} {
		if exp[k] != true {
			t.Errorf("exploit mode should set %q=true", k)
		}
	}
	if exp["level"] != 3 {
		t.Errorf("level override lost: %v", exp["level"])
	}
}
