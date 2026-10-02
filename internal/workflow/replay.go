package workflow

import (
	"fmt"
	"sort"
)

type ReplayStep struct {
	TransitionID  string `json:"transition_id"`
	Action        string `json:"action"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	ApprovalClass string `json:"approval_class"`
	Executable    bool   `json:"executable"`
	Reason        string `json:"reason,omitempty"`
}

func PlanReplay(g Graph, from, to string, allowStateful bool) ([]ReplayStep, error) {
	if from == "" || to == "" {
		return nil, fmt.Errorf("from and to states are required")
	}
	if from == to {
		return nil, nil
	}

	adj := map[string][]Transition{}
	for i := range g.Transitions {
		tr := g.Transitions[i]
		adj[tr.From.Name] = append(adj[tr.From.Name], tr)
	}
	for key := range adj {
		sort.Slice(adj[key], func(i, j int) bool { return adj[key][i].ID < adj[key][j].ID })
	}

	type node struct {
		state string
		path  []Transition
	}
	queue := []node{{state: from}}
	visited := map[string]bool{from: true}
	var path []Transition
	found := false
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		transitions := adj[cur.state]
		for i := range transitions {
			tr := &transitions[i]
			nextPath := append(append([]Transition(nil), cur.path...), *tr)
			if tr.To.Name == to {
				path = nextPath
				found = true
				break
			}
			if !visited[tr.To.Name] {
				visited[tr.To.Name] = true
				queue = append(queue, node{state: tr.To.Name, path: nextPath})
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no workflow path from %q to %q", from, to)
	}

	out := make([]ReplayStep, 0, len(path))
	for i := range path {
		tr := &path[i]
		step := ReplayStep{
			TransitionID:  tr.ID,
			Action:        tr.Action,
			Method:        tr.Method,
			URL:           tr.URL,
			ApprovalClass: tr.ApprovalClass,
			Executable:    !tr.MutatesState || allowStateful,
		}
		if tr.MutatesState && !allowStateful {
			step.Reason = "state-changing replay step requires explicit stateful approval"
		}
		out = append(out, step)
	}
	return out, nil
}
