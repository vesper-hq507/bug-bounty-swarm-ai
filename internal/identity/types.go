package identity

import "time"

type ID string
type SessionRef string

type Role string

const (
	RoleAnonymous Role = "anonymous"
	RoleUser      Role = "user"
	RolePrivileged Role = "privileged"
	RoleCustom    Role = "custom"
)

type Identity struct {
	ID         ID
	Alias      string
	Role       Role
	SessionRef SessionRef
	FreshUntil time.Time
	Metadata   map[string]string
}

func (i Identity) AuthFresh(now time.Time) bool {
	if i.Role == RoleAnonymous {
		return true
	}
	if i.SessionRef == "" {
		return false
	}
	return i.FreshUntil.IsZero() || now.Before(i.FreshUntil)
}

type ObjectRef struct {
	Type string
	ID   string
}

func (o ObjectRef) Key() string {
	return o.Type + ":" + o.ID
}
