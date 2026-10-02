package evidence

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type Store interface {
	Add(Record) error
	Get(uuid.UUID) (Record, error)
	ForFinding(uuid.UUID) []Record
}

type MemoryStore struct {
	mu      sync.RWMutex
	records map[uuid.UUID]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[uuid.UUID]Record{}}
}

func (s *MemoryStore) Add(r Record) error {
	if s == nil {
		return fmt.Errorf("evidence store unavailable")
	}
	if r.ID == uuid.Nil || !r.VerifyIntegrity() {
		return fmt.Errorf("invalid evidence record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[r.ID]; exists {
		return fmt.Errorf("evidence record %s already exists", r.ID)
	}
	s.records[r.ID] = r
	return nil
}

func (s *MemoryStore) Get(id uuid.UUID) (Record, error) {
	if s == nil {
		return Record{}, fmt.Errorf("evidence store unavailable")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return Record{}, fmt.Errorf("evidence record %s not found", id)
	}
	return r, nil
}

func (s *MemoryStore) ForFinding(findingID uuid.UUID) []Record {
	if s == nil || findingID == uuid.Nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0)
	for id := range s.records {
		r := s.records[id]
		if r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out
}
