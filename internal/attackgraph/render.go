package attackgraph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// palette (matches banner/hero.svg)
const (
	colVoid  = "#0B0E14"
	colCyan  = "#57C7FF"
	colPurple = "#7F77DD"
	colAmber = "#F5A623"
	colGreen = "#3DDC97"
	colRed   = "#ff6b6b"
	colWhite = "#E6E9EF"
	colMuted = "#5C6577"
)

func nodeColor(t NodeType) string {
	switch t {
	case NodeEntry:
		return colCyan
	case NodeEndpoint, NodeAsset:
		return colPurple
	case NodeToken, NodeSecret:
		return colAmber
	case NodeObjectRef:
		return colAmber
	case NodeIdentity:
		return colGreen
	case NodeCapability:
		return colRed
	case NodeObjective:
		return colAmber
	}
	return colMuted
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// GraphJSON is the serializable shape the web dashboard consumes.
type GraphJSON struct {
	Nodes []nodeJSON `json:"nodes"`
	Edges []edgeJSON `json:"edges"`
	Path  []string   `json:"path"` // ordered node ids of the most-likely route
	Prob  float64    `json:"probability"`
}
type nodeJSON struct {
	ID, Type, Label string
	OnPath          bool `json:"on_path"`
}
type edgeJSON struct {
	From, To, Type, Detail string
	Exploitability         float64
	OnPath                 bool `json:"on_path"`
}

// ToJSON serialises the graph + the most-likely path to the objective, for the
// dashboard / programmatic consumers.
func (g *Graph) ToJSON() []byte {
	_, path, prob := g.BestPathToObjective(objectiveID)
	onEdge, onNode := pathSets(path)
	out := GraphJSON{Prob: prob}
	for _, n := range g.AllNodes() {
		out.Nodes = append(out.Nodes, nodeJSON{ID: n.ID, Type: string(n.Type), Label: n.Label, OnPath: onNode[n.ID]})
	}
	for _, e := range g.Edges() {
		out.Edges = append(out.Edges, edgeJSON{From: e.From, To: e.To, Type: string(e.Type), Detail: e.Detail, Exploitability: e.Exploitability, OnPath: onEdge[edgeKey(e)]})
	}
	if len(path) > 0 {
		out.Path = append(out.Path, path[0].From)
		for _, e := range path {
			out.Path = append(out.Path, e.To)
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

func edgeKey(e Edge) string { return e.From + "|" + e.To + "|" + string(e.Type) }

func pathSets(path []Edge) (edges map[string]bool, nodes map[string]bool) {
	edges, nodes = map[string]bool{}, map[string]bool{}
	for _, e := range path {
		edges[edgeKey(e)] = true
		nodes[e.From] = true
		nodes[e.To] = true
	}
	return
}

// RenderHTML produces a self-contained, interactive attack-map page: a
// left-to-right layered layout of the graph with the most-likely path to the
// objective highlighted. title names the page (e.g. the target).
func (g *Graph) RenderHTML(title string) []byte {
	const nodeW, nodeH, xStep, rowGap = 176.0, 56.0, 250.0, 92.0
	const marginL, marginTop = 70.0, 110.0

	layer := g.LayerFromEntry()
	// group node ids by layer
	byLayer := map[int][]string{}
	maxLayer := 0
	for _, n := range g.AllNodes() {
		l := layer[n.ID]
		byLayer[l] = append(byLayer[l], n.ID)
		if l > maxLayer {
			maxLayer = l
		}
	}
	maxInLayer := 1
	for _, ids := range byLayer {
		if len(ids) > maxInLayer {
			maxInLayer = len(ids)
		}
	}
	width := marginL*2 + float64(maxLayer)*xStep + nodeW
	height := marginTop + float64(maxInLayer)*rowGap + 90
	centerY := marginTop + (height-marginTop)/2

	// positions
	type pos struct{ x, y float64 }
	P := map[string]pos{}
	for l := 0; l <= maxLayer; l++ {
		ids := byLayer[l]
		sort.Strings(ids)
		n := len(ids)
		for i, id := range ids {
			x := marginL + float64(l)*xStep
			y := centerY + (float64(i)-float64(n-1)/2)*rowGap - nodeH/2
			P[id] = pos{x, y}
		}
	}

	_, path, prob := g.BestPathToObjective(objectiveID)
	onEdge, onNode := pathSets(path)

	var b strings.Builder
	fmt.Fprintf(&b, `<!doctype html><html><head><meta charset="utf-8"><title>%s — attack map</title>
<style>html,body{margin:0;background:%s;font-family:-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{overflow:auto}text{pointer-events:none}</style></head><body><div class="wrap">
<svg width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f">
<defs>
<marker id="ah" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="%s"/></marker>
<marker id="ahm" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="%s"/></marker>
<filter id="glow" x="-50%%" y="-50%%" width="200%%" height="200%%"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect x="0" y="0" width="%.0f" height="%.0f" fill="%s"/>`,
		esc(title), colVoid, width, height, width, height, colGreen, colMuted, width, height, colVoid)

	// edges
	for _, e := range g.Edges() {
		a, ok1 := P[e.From]
		c, ok2 := P[e.To]
		if !ok1 || !ok2 {
			continue
		}
		x1, y1 := a.x+nodeW, a.y+nodeH/2
		x2, y2 := c.x, c.y+nodeH/2
		mx := (x1 + x2) / 2
		on := onEdge[edgeKey(e)]
		stroke, w, dash, mark, op := colMuted, "1.5", `stroke-dasharray="5 5"`, "url(#ahm)", "0.5"
		if on {
			stroke, w, dash, mark, op = colGreen, "3", "", "url(#ah)", "0.95"
		}
		glow := ""
		if on {
			glow = `filter="url(#glow)"`
		}
		fmt.Fprintf(&b, `<path d="M%.0f,%.0f C%.0f,%.0f %.0f,%.0f %.0f,%.0f" fill="none" stroke="%s" stroke-width="%s" %s marker-end="%s" opacity="%s" %s/>`,
			x1, y1, mx, y1, mx, y2, x2, y2, stroke, w, dash, mark, op, glow)
		// label
		lx, ly := (x1+x2)/2, (y1+y2)/2-8
		lab := fmt.Sprintf("%s  %.0f%%", e.Type, e.Exploitability*100)
		tw := float64(len(lab))*6.4 + 16
		lc := colMuted
		if on {
			lc = colGreen
		}
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.0f" width="%.0f" height="20" rx="5" fill="%s" opacity="0.9"/><text x="%.0f" y="%.0f" text-anchor="middle" font-size="11" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>`,
			lx-tw/2, ly-13, tw, colVoid, lx, ly+1, lc, esc(lab))
	}

	// nodes
	for _, n := range g.AllNodes() {
		p := P[n.ID]
		col := nodeColor(n.Type)
		on := onNode[n.ID]
		sw, glow := "1.4", ""
		if on {
			sw, glow = "2.5", `filter="url(#glow)"`
		}
		fmt.Fprintf(&b, `<rect x="%.0f" y="%.0f" width="%.0f" height="%.0f" rx="11" fill="#0f1420" stroke="%s" stroke-width="%s" %s/>`,
			p.x, p.y, nodeW, nodeH, col, sw, glow)
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="9.5" fill="%s" font-family="ui-monospace,Menlo,monospace" letter-spacing="1">%s</text>`,
			p.x+14, p.y+20, col, strings.ToUpper(string(n.Type)))
		fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" font-size="14" fill="%s" font-weight="600">%s</text>`,
			p.x+14, p.y+42, colWhite, esc(clip(n.Label, 22)))
	}

	// header + legend
	fmt.Fprintf(&b, `<text x="44" y="48" font-size="26" fill="%s" font-weight="800">ATTACK PATH TO OBJECTIVE</text>`, colAmber)
	sub := "no reachable path to the objective from the current findings"
	if len(path) > 0 {
		sub = fmt.Sprintf("most-likely path highlighted   ·   %.0f%% combined exploitability", prob*100)
	}
	fmt.Fprintf(&b, `<text x="46" y="74" font-size="14" fill="%s" font-family="ui-monospace,Menlo,monospace">%s   ·   %s</text>`,
		colWhite, esc(clip("goal: "+title, 60)), sub)
	legend := []struct{ l, c string }{{"entry", colCyan}, {"endpoint", colPurple}, {"token/secret", colAmber}, {"identity", colGreen}, {"capability", colRed}}
	lx := 44.0
	ly := height - 34
	for _, it := range legend {
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="6" fill="%s"/><text x="%.0f" y="%.0f" font-size="12" fill="%s">%s</text>`,
			lx+6, ly, it.c, lx+18, ly+4, colMuted, it.l)
		lx += float64(len(it.l))*7.2 + 50
	}
	b.WriteString(`</svg></div></body></html>`)
	return []byte(b.String())
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
