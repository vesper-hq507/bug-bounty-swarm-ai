package attackgraph

import (
	"strings"
	"testing"
)

func TestRenderHTMLAndJSON(t *testing.T) {
	g := buildDemo()
	html := string(g.RenderHTML("account takeover"))
	for _, want := range []string{"<svg", "ATTACK PATH TO OBJECTIVE", "admin takeover", "</svg>"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	js := string(g.ToJSON())
	if !strings.Contains(js, `"on_path": true`) || !strings.Contains(js, `"probability"`) {
		t.Errorf("json missing path/probability markers:\n%s", js[:200])
	}
}

func TestLayerFromEntry(t *testing.T) {
	g := buildDemo()
	l := g.LayerFromEntry()
	if l["entry"] != 0 {
		t.Errorf("entry layer = %d", l["entry"])
	}
	if l[objectiveID] <= l["jwt"] {
		t.Errorf("objective should be deeper than intermediate nodes: obj=%d jwt=%d", l[objectiveID], l["jwt"])
	}
}
