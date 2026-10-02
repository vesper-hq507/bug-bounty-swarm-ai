package workflow

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

type Observation struct {
	Method       string
	URL          string
	ActorID      string
	ActorRole    string
	StatusCode   int
	RequestBody  []byte
	ResponseBody []byte
	EvidenceRefs []string
}

type Collector struct {
	mu        sync.Mutex
	sequences map[string]int
	lastState map[string]string
	events    []Event
}

func NewCollector() *Collector {
	return &Collector{
		sequences: map[string]int{},
		lastState: map[string]string{},
	}
}

func (c *Collector) Observe(o Observation) Event {
	if c == nil {
		return Event{}
	}
	method := strings.ToUpper(strings.TrimSpace(o.Method))
	if method == "" {
		method = "GET"
	}
	workflowID, objectID, action := deriveWorkflowIdentity(method, o.URL)
	before := extractPreviousState(o.RequestBody)
	after := extractState(o.ResponseBody)
	if after == "" {
		after = extractState(o.RequestBody)
	}
	if after == "" {
		switch {
		case o.StatusCode == 0:
			after = "network-error"
		case o.StatusCode >= 200 && o.StatusCode < 300 && method == "DELETE":
			after = "deleted"
		default:
			after = fmt.Sprintf("http-%d", o.StatusCode)
		}
	}
	owner := extractOwner(o.ResponseBody)
	if owner == "" {
		owner = extractOwner(o.RequestBody)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if before == "" {
		before = c.lastState[workflowID]
	}
	if before == "" {
		before = "unknown"
	}
	c.sequences[workflowID]++
	event := Event{
		WorkflowID:   workflowID,
		Sequence:     c.sequences[workflowID],
		StateBefore:  before,
		StateAfter:   after,
		Action:       action,
		Method:       method,
		URL:          o.URL,
		ActorID:      o.ActorID,
		ActorRole:    o.ActorRole,
		ObjectID:     objectID,
		ObjectOwner:  owner,
		StatusCode:   o.StatusCode,
		EvidenceRefs: append([]string(nil), o.EvidenceRefs...),
	}
	c.events = append(c.events, event)
	if o.StatusCode >= 200 && o.StatusCode < 400 {
		c.lastState[workflowID] = after
	}
	return event
}

func (c *Collector) Events() []Event {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

var idLike = regexp.MustCompile(`^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,})$`)

func deriveWorkflowIdentity(method, rawURL string) (workflowID, objectID, action string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "request:" + rawURL, "", strings.ToLower(method)
	}
	segments := splitPath(u.Path)
	pattern := make([]string, 0, len(segments))
	resource := "root"
	for i, segment := range segments {
		if idLike.MatchString(segment) {
			if objectID == "" {
				objectID = segment
				if i > 0 {
					resource = segments[i-1]
				}
			}
			pattern = append(pattern, ":id")
			continue
		}
		if objectID == "" {
			resource = segment
		}
		pattern = append(pattern, segment)
	}
	if len(pattern) == 0 {
		pattern = []string{"root"}
	}
	last := pattern[len(pattern)-1]
	if last == ":id" && len(pattern) > 1 {
		last = pattern[len(pattern)-2]
	}
	switch method {
	case "POST":
		if isActionWord(last) {
			action = last
		} else {
			action = "create-" + last
		}
	case "PUT", "PATCH":
		if isActionWord(last) {
			action = last
		} else {
			action = "update-" + last
		}
	case "DELETE":
		action = "delete-" + last
	default:
		action = "read-" + last
	}
	key := u.Hostname() + ":" + resource
	if objectID != "" {
		key += ":" + objectID
	} else {
		key += ":" + strings.Join(pattern, "/")
	}
	return key, objectID, action
}

func splitPath(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, segment := range raw {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func isActionWord(s string) bool {
	switch strings.ToLower(s) {
	case "approve", "cancel", "checkout", "confirm", "invite", "pay", "publish",
		"redeem", "refund", "reset", "ship", "submit", "transfer", "verify",
		"withdraw", "deposit", "activate", "deactivate", "upload", "import":
		return true
	default:
		return false
	}
}

func extractPreviousState(body []byte) string {
	return extractJSONValue(body, []string{"previous_state", "previousState", "from_state", "fromState", "old_state", "oldState"})
}

func extractState(body []byte) string {
	return extractJSONValue(body, []string{"state", "status", "phase", "stage"})
}

func extractOwner(body []byte) string {
	return extractJSONValue(body, []string{"owner_id", "ownerId", "user_id", "userId", "account_id", "accountId"})
}

func extractJSONValue(body []byte, keys []string) string {
	if len(body) == 0 {
		return ""
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return ""
	}
	return findJSONValue(value, keys, 0)
}

func findJSONValue(value any, keys []string, depth int) string {
	if depth > 3 {
		return ""
	}
	switch v := value.(type) {
	case map[string]any:
		for _, key := range keys {
			if raw, ok := v[key]; ok {
				switch x := raw.(type) {
				case string:
					return strings.TrimSpace(x)
				case float64:
					return fmt.Sprintf("%.0f", x)
				case bool:
					return fmt.Sprintf("%t", x)
				}
			}
		}
		for _, child := range v {
			if got := findJSONValue(child, keys, depth+1); got != "" {
				return got
			}
		}
	case []any:
		for _, child := range v {
			if got := findJSONValue(child, keys, depth+1); got != "" {
				return got
			}
		}
	}
	return ""
}
