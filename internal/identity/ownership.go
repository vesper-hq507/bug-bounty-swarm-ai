package identity

import (
	"fmt"
	"sync"
)

type OwnershipMap struct {
	mu     sync.RWMutex
	owners map[string]ID
}

func NewOwnershipMap() *OwnershipMap {
	return &OwnershipMap{owners: map[string]ID{}}
}

func (m *OwnershipMap) SetOwner(obj ObjectRef, owner ID) error {
	if m == nil {
		return fmt.Errorf("ownership map unavailable")
	}
	if obj.Type == "" || obj.ID == "" || owner == "" {
		return fmt.Errorf("object type, object id and owner are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.owners[obj.Key()] = owner
	return nil
}

func (m *OwnershipMap) OwnerOf(obj ObjectRef) (ID, bool) {
	if m == nil {
		return "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	owner, ok := m.owners[obj.Key()]
	return owner, ok
}

func (m *OwnershipMap) IsOwner(obj ObjectRef, actor ID) bool {
	owner, ok := m.OwnerOf(obj)
	return ok && owner == actor
}
