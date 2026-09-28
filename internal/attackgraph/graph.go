// Package attackgraph models a target as a typed graph the swarm reasons over —
// "BloodHound for the app/cloud layer." Nodes are things an attacker moves
// through (assets, endpoints, identities, tokens, secrets, object references,
// capabilities); edges are the transitions between them (reach one, leak a
// secret, authenticate as an identity, escalate to a capability), each weighted
// by how reliably it can be exploited. The planner then finds the most-likely
// path from an attacker entry point to a declared crown-jewel objective.
package attackgraph

import (
	"math"
	"sort"
)

// NodeType categorises a graph node.
type NodeType string

const (
	NodeEntry     NodeType = "entry"      // the attacker's starting point (unauthenticated)
	NodeAsset     NodeType = "asset"      // a host / service / app
	NodeEndpoint  NodeType = "endpoint"   // a specific URL / API endpoint
	NodeIdentity  NodeType = "identity"   // a user / role / principal
	NodeToken     NodeType = "token"      // a session / JWT / API key
	NodeSecret    NodeType = "secret"     // a credential / key / secret value
	NodeObjectRef NodeType = "object_ref" // an object id (BOLA/IDOR pivot)
	NodeCapability NodeType = "capability" // an ability gained (e.g. RCE, admin)
	NodeObjective NodeType = "objective"  // the crown jewel we plan toward
)

// EdgeType categorises a transition.
type EdgeType string

const (
	EdgeReaches   EdgeType = "reaches"      // can reach / discover the target node
	EdgeAuthAs    EdgeType = "auth_as"      // can authenticate as the identity
	EdgeLeaks     EdgeType = "leaks"        // discloses the target (a secret/token)
	EdgeEscalates EdgeType = "escalates_to" // gains the capability / objective
	EdgeExploits  EdgeType = "exploits"     // exploits a vuln to transition
)

// Node is a vertex in the attack graph.
type Node struct {
	ID    string
	Type  NodeType
	Label string
	Meta  map[string]string
}

// Edge is a weighted, directed transition. Exploitability in (0,1] is how
// reliably an attacker can make this transition (1 = trivial/proven).
type Edge struct {
	From, To       string
	Type           EdgeType
	Exploitability float64
	Detail         string
}

// Graph is a directed multigraph of nodes + weighted edges.
type Graph struct {
	nodes map[string]*Node
	adj   map[string][]Edge
}

// New builds an empty graph.
func New() *Graph { return &Graph{nodes: map[string]*Node{}, adj: map[string][]Edge{}} }

// AddNode inserts a node. If the id already exists as a bare placeholder
// (auto-created by AddEdge as an asset labelled with its id), the real typed
// node upgrades it — so node/edge insertion order doesn't matter.
func (g *Graph) AddNode(n Node) {
	if n.ID == "" {
		return
	}
	if existing, ok := g.nodes[n.ID]; ok {
		if existing.Type == NodeAsset && existing.Label == existing.ID {
			cp := n
			g.nodes[n.ID] = &cp
		}
		return
	}
	cp := n
	g.nodes[n.ID] = &cp
}

// AddEdge inserts a directed edge, auto-creating bare endpoint nodes if needed
// and clamping exploitability to (0,1].
func (g *Graph) AddEdge(e Edge) {
	if e.From == "" || e.To == "" {
		return
	}
	g.AddNode(Node{ID: e.From, Type: NodeAsset, Label: e.From})
	g.AddNode(Node{ID: e.To, Type: NodeAsset, Label: e.To})
	if e.Exploitability <= 0 {
		e.Exploitability = 0.01
	}
	if e.Exploitability > 1 {
		e.Exploitability = 1
	}
	g.adj[e.From] = append(g.adj[e.From], e)
}

// Node returns a node by id (nil if absent).
func (g *Graph) Node(id string) *Node { return g.nodes[id] }

// NodesOfType returns the ids of nodes of a given type, sorted.
func (g *Graph) NodesOfType(t NodeType) []string {
	var out []string
	for id, n := range g.nodes {
		if n.Type == t {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Counts returns the number of nodes and edges (for telemetry).
func (g *Graph) Counts() (nodes, edges int) {
	nodes = len(g.nodes)
	for _, es := range g.adj {
		edges += len(es)
	}
	return
}

// AllNodes returns every node, sorted by id (stable rendering/serialization).
func (g *Graph) AllNodes() []*Node {
	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*Node, 0, len(ids))
	for _, id := range ids {
		out = append(out, g.nodes[id])
	}
	return out
}

// Edges returns every edge, grouped by source in sorted order.
func (g *Graph) Edges() []Edge {
	srcs := make([]string, 0, len(g.adj))
	for s := range g.adj {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	var out []Edge
	for _, s := range srcs {
		out = append(out, g.adj[s]...)
	}
	return out
}

// LayerFromEntry returns each node's shortest hop-distance from EntryID (BFS
// over directed edges). Nodes unreachable from entry get the max layer + 1, so a
// layered left-to-right layout can still place them. Missing entry → all 0.
func (g *Graph) LayerFromEntry() map[string]int {
	layer := map[string]int{}
	if _, ok := g.nodes[EntryID]; !ok {
		for id := range g.nodes {
			layer[id] = 0
		}
		return layer
	}
	for id := range g.nodes {
		layer[id] = -1
	}
	layer[EntryID] = 0
	queue := []string{EntryID}
	maxL := 0
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		for _, e := range g.adj[u] {
			if layer[e.To] == -1 {
				layer[e.To] = layer[u] + 1
				if layer[e.To] > maxL {
					maxL = layer[e.To]
				}
				queue = append(queue, e.To)
			}
		}
	}
	// Objective goes alone in the last column; other unreachable nodes
	// (dead-ends) sit in the last reachable column.
	for id, l := range layer {
		if l == -1 && id != objectiveID {
			layer[id] = maxL
		}
	}
	if _, ok := g.nodes[objectiveID]; ok {
		layer[objectiveID] = maxL + 1
	}
	return layer
}

// ShortestPath returns the MOST-LIKELY attack path from `from` to `to`: the
// path maximising the product of edge exploitabilities. It runs Dijkstra over
// cost = -log(exploitability) (non-negative), so minimising total cost
// maximises the product. Returns the ordered edges and the overall success
// probability (that product), or (nil, 0) if `to` is unreachable.
func (g *Graph) ShortestPath(from, to string) ([]Edge, float64) {
	if _, ok := g.nodes[from]; !ok {
		return nil, 0
	}
	if _, ok := g.nodes[to]; !ok {
		return nil, 0
	}
	dist := make(map[string]float64, len(g.nodes))
	for id := range g.nodes {
		dist[id] = math.Inf(1)
	}
	dist[from] = 0
	prev := map[string]Edge{}
	visited := map[string]bool{}

	for {
		u, best := "", math.Inf(1)
		for id, d := range dist {
			if !visited[id] && d < best {
				best, u = d, id
			}
		}
		if u == "" || u == to {
			break
		}
		visited[u] = true
		for _, e := range g.adj[u] {
			cost := -math.Log(e.Exploitability)
			if nd := dist[u] + cost; nd < dist[e.To] {
				dist[e.To] = nd
				prev[e.To] = e
			}
		}
	}
	if math.IsInf(dist[to], 1) {
		return nil, 0
	}
	var path []Edge
	for cur := to; cur != from; {
		e, ok := prev[cur]
		if !ok {
			return nil, 0
		}
		path = append([]Edge{e}, path...)
		cur = e.From
	}
	return path, math.Exp(-dist[to])
}

// BestPathToObjective finds the most-likely path from ANY entry node to the
// given objective node, returning the entry it starts from, the path, and its
// probability. If there are no entry nodes it tries every node as a start.
func (g *Graph) BestPathToObjective(objective string) (entry string, path []Edge, prob float64) {
	starts := g.NodesOfType(NodeEntry)
	if len(starts) == 0 {
		for id := range g.nodes {
			starts = append(starts, id)
		}
		sort.Strings(starts)
	}
	for _, s := range starts {
		if p, pr := g.ShortestPath(s, objective); pr > prob {
			entry, path, prob = s, p, pr
		}
	}
	return
}
