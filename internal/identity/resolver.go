package identity

import (
	"context"
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

type SessionResolver interface {
	ResolveSession(ctx context.Context, ref SessionRef) (*session.Session, error)
}

type MemorySessionResolver struct {
	sessions map[SessionRef]*session.Session
}

func NewMemorySessionResolver() *MemorySessionResolver {
	return &MemorySessionResolver{sessions: map[SessionRef]*session.Session{}}
}

func (m *MemorySessionResolver) Put(ref SessionRef, sess *session.Session) error {
	if m == nil || ref == "" {
		return fmt.Errorf("session reference is required")
	}
	if sess == nil || sess.Empty() {
		return fmt.Errorf("session must not be empty")
	}
	cp := make(map[string]string, len(sess.Headers))
	for k, v := range sess.Headers {
		cp[k] = v
	}
	m.sessions[ref] = session.New(cp)
	return nil
}

func (m *MemorySessionResolver) ResolveSession(_ context.Context, ref SessionRef) (*session.Session, error) {
	if m == nil || ref == "" {
		return nil, fmt.Errorf("session reference is required")
	}
	s, ok := m.sessions[ref]
	if !ok {
		return nil, fmt.Errorf("session reference %q not found", ref)
	}
	cp := make(map[string]string, len(s.Headers))
	for k, v := range s.Headers {
		cp[k] = v
	}
	return session.New(cp), nil
}
