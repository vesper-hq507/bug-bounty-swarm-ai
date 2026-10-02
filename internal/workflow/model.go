package workflow

import (
	"fmt"
	"net/http"
	"strings"
)

type State struct {
	Name     string `json:"name"`
	Terminal bool   `json:"terminal,omitempty"`
}

type Event struct {
	WorkflowID   string   `json:"workflow_id"`
	Sequence     int      `json:"sequence"`
	StateBefore  string   `json:"state_before"`
	StateAfter   string   `json:"state_after"`
	Action       string   `json:"action"`
	Method       string   `json:"method"`
	URL          string   `json:"url"`
	ActorID      string   `json:"actor_id"`
	ActorRole    string   `json:"actor_role,omitempty"`
	ObjectID     string   `json:"object_id,omitempty"`
	ObjectOwner  string   `json:"object_owner,omitempty"`
	StatusCode   int      `json:"status_code"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

func (e Event) MutatesState() bool {
	switch strings.ToUpper(strings.TrimSpace(e.Method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

type Transition struct {
	ID              string   `json:"id"`
	From            State    `json:"from"`
	To              State    `json:"to"`
	Action          string   `json:"action"`
	Method          string   `json:"method"`
	URL             string   `json:"url"`
	RequiredRole    string   `json:"required_role,omitempty"`
	RequiresOwner   bool     `json:"requires_owner,omitempty"`
	RequiredPrior   []string `json:"required_prior,omitempty"`
	ApprovalClass   string   `json:"approval_class"`
	MutatesState    bool     `json:"mutates_state"`
}

type Graph struct {
	States      map[string]State `json:"states"`
	Transitions []Transition     `json:"transitions"`
}

func BuildGraph(events []Event) Graph {
	g := Graph{States: map[string]State{}}
	seen := map[string]struct{}{}
	for i := range events {
		e := &events[i]
		if e.StateBefore == "" || e.StateAfter == "" || e.Action == "" {
			continue
		}
		if _, ok := g.States[e.StateBefore]; !ok {
			g.States[e.StateBefore] = State{Name: e.StateBefore}
		}
		if _, ok := g.States[e.StateAfter]; !ok {
			g.States[e.StateAfter] = State{Name: e.StateAfter}
		}
		id := transitionID(*e)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		g.Transitions = append(g.Transitions, Transition{
			ID:            id,
			From:          g.States[e.StateBefore],
			To:            g.States[e.StateAfter],
			Action:        e.Action,
			Method:        e.Method,
			URL:           e.URL,
			ApprovalClass: approvalClassFor(*e),
			MutatesState:  e.MutatesState(),
		})
	}
	return g
}

func transitionID(e Event) string {
	return fmt.Sprintf("%s:%s:%s:%s", e.StateBefore, e.Action, e.Method, e.StateAfter)
}

func approvalClassFor(e Event) string {
	if e.MutatesState() {
		return "stateful"
	}
	return "read-only"
}
