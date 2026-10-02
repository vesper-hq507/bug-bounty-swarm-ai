package identity

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

var (
	ErrDuplicateIdentity = errors.New("identity already exists")
	ErrIdentityNotFound  = errors.New("identity not found")
)

type Registry struct {
	mu    sync.RWMutex
	items map[ID]Identity
}

func NewRegistry() *Registry {
	return &Registry{items: map[ID]Identity{}}
}

func (r *Registry) Add(i Identity) error {
	if r == nil {
		return fmt.Errorf("identity registry unavailable")
	}
	i.ID = ID(strings.TrimSpace(string(i.ID)))
	i.Alias = strings.TrimSpace(i.Alias)
	if i.ID == "" {
		return fmt.Errorf("identity id is required")
	}
	if i.Alias == "" {
		return fmt.Errorf("identity alias is required")
	}
	if i.Role == "" {
		i.Role = RoleUser
	}
	if i.Role != RoleAnonymous && i.SessionRef == "" {
		return fmt.Errorf("identity %q requires a session reference", i.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[i.ID]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateIdentity, i.ID)
	}
	if i.Metadata != nil {
		cp := make(map[string]string, len(i.Metadata))
		for k, v := range i.Metadata {
			cp[k] = v
		}
		i.Metadata = cp
	}
	r.items[i.ID] = i
	return nil
}

func (r *Registry) Get(id ID) (Identity, error) {
	if r == nil {
		return Identity{}, ErrIdentityNotFound
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.items[id]
	if !ok {
		return Identity{}, fmt.Errorf("%w: %s", ErrIdentityNotFound, id)
	}
	return i, nil
}

func (r *Registry) List() []Identity {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Identity, 0, len(r.items))
	for _, i := range r.items {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}
