package attackgraph

import (
	"math"
	"testing"
)

// entry → /login endpoint → (leak) token → (auth) victim identity →
// (escalate) admin objective. Also a weaker direct guess path.
func buildDemo() *Graph {
	g := New()
	g.AddNode(Node{ID: "entry", Type: NodeEntry, Label: "unauth attacker"})
	g.AddNode(Node{ID: "obj", Type: NodeObjective, Label: "admin takeover"})
	g.AddEdge(Edge{From: "entry", To: "login", Type: EdgeReaches, Exploitability: 0.95})
	g.AddEdge(Edge{From: "login", To: "jwt", Type: EdgeLeaks, Exploitability: 0.8, Detail: "alg:none accepted"})
	g.AddEdge(Edge{From: "jwt", To: "victim", Type: EdgeAuthAs, Exploitability: 0.9})
	g.AddEdge(Edge{From: "victim", To: "obj", Type: EdgeEscalates, Exploitability: 0.7, Detail: "BFLA"})
	// a much weaker alternative direct path entry→obj
	g.AddEdge(Edge{From: "entry", To: "obj", Type: EdgeExploits, Exploitability: 0.05, Detail: "blind guess"})
	return g
}

func TestShortestPath_MostLikely(t *testing.T) {
	g := buildDemo()
	path, prob := g.ShortestPath("entry", "obj")
	if len(path) != 4 {
		t.Fatalf("expected the 4-hop chain, got %d hops: %+v", len(path), path)
	}
	want := 0.95 * 0.8 * 0.9 * 0.7 // ~0.4788
	if math.Abs(prob-want) > 1e-6 {
		t.Errorf("prob = %v, want %v", prob, want)
	}
	// must prefer the chain over the 0.05 direct guess
	if path[0].To == "obj" {
		t.Error("planner took the weak direct guess instead of the reliable chain")
	}
}

func TestShortestPath_Unreachable(t *testing.T) {
	g := New()
	g.AddNode(Node{ID: "a", Type: NodeEntry})
	g.AddNode(Node{ID: "b", Type: NodeObjective})
	if p, pr := g.ShortestPath("a", "b"); p != nil || pr != 0 {
		t.Errorf("disconnected nodes should be unreachable, got %v/%v", p, pr)
	}
}

func TestBestPathToObjective(t *testing.T) {
	g := buildDemo()
	entry, path, prob := g.BestPathToObjective("obj")
	if entry != "entry" || len(path) != 4 || prob < 0.4 {
		t.Fatalf("best path wrong: entry=%s hops=%d prob=%.3f", entry, len(path), prob)
	}
}

func TestCountsAndTypes(t *testing.T) {
	g := buildDemo()
	n, e := g.Counts()
	if n < 5 || e != 5 {
		t.Errorf("counts nodes=%d edges=%d", n, e)
	}
	if len(g.NodesOfType(NodeEntry)) != 1 || len(g.NodesOfType(NodeObjective)) != 1 {
		t.Error("type filters wrong")
	}
}
