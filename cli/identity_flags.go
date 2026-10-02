package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/session"
)

type campaignIdentityFlags struct {
	Identities []identity.Identity
	Sessions   map[identity.SessionRef]*session.Session
	Primary    identity.ID
}

func parseCampaignIdentityFlags(identitySpecs, sessionSpecs []string, primary string, legacyHeaders map[string]string) (campaignIdentityFlags, error) {
	if len(identitySpecs) == 0 {
		return campaignIdentityFlags{}, nil
	}
	if len(legacyHeaders) > 0 {
		return campaignIdentityFlags{}, fmt.Errorf("do not mix --identity with --auth/--cookie/--header; use --identity-session references instead")
	}

	out := campaignIdentityFlags{Sessions: map[identity.SessionRef]*session.Session{}}
	for _, raw := range sessionSpecs {
		refRaw, source, ok := strings.Cut(raw, "=")
		ref := identity.SessionRef(strings.TrimSpace(refRaw))
		source = strings.TrimSpace(source)
		if !ok || ref == "" || source == "" {
			return campaignIdentityFlags{}, fmt.Errorf("invalid --identity-session %q; expected ref=env:NAME or ref=keychain:KEY", raw)
		}
		sess, err := resolveIdentitySessionSource(source)
		if err != nil {
			return campaignIdentityFlags{}, fmt.Errorf("session %q: %w", ref, err)
		}
		if _, exists := out.Sessions[ref]; exists {
			return campaignIdentityFlags{}, fmt.Errorf("duplicate identity session reference %q", ref)
		}
		out.Sessions[ref] = sess
	}

	seen := map[identity.ID]struct{}{}
	for _, raw := range identitySpecs {
		parts := strings.SplitN(strings.TrimSpace(raw), ":", 3)
		if len(parts) < 2 {
			return campaignIdentityFlags{}, fmt.Errorf("invalid --identity %q; expected id:role[:session-ref]", raw)
		}
		id := identity.ID(strings.TrimSpace(parts[0]))
		role := identity.Role(strings.ToLower(strings.TrimSpace(parts[1])))
		ref := identity.SessionRef("")
		if len(parts) == 3 {
			ref = identity.SessionRef(strings.TrimSpace(parts[2]))
		}
		if id == "" {
			return campaignIdentityFlags{}, fmt.Errorf("identity id is required")
		}
		switch role {
		case identity.RoleAnonymous:
			if ref != "" {
				return campaignIdentityFlags{}, fmt.Errorf("anonymous identity %q must not have a session reference", id)
			}
		case identity.RoleUser, identity.RolePrivileged, identity.RoleCustom:
			if ref == "" {
				return campaignIdentityFlags{}, fmt.Errorf("identity %q requires a session reference", id)
			}
			if _, ok := out.Sessions[ref]; !ok {
				return campaignIdentityFlags{}, fmt.Errorf("identity %q references undefined session %q", id, ref)
			}
		default:
			return campaignIdentityFlags{}, fmt.Errorf("identity %q has unsupported role %q", id, role)
		}
		if _, dup := seen[id]; dup {
			return campaignIdentityFlags{}, fmt.Errorf("duplicate identity %q", id)
		}
		seen[id] = struct{}{}
		out.Identities = append(out.Identities, identity.Identity{
			ID: id, Alias: string(id), Role: role, SessionRef: ref,
		})
	}

	out.Primary = identity.ID(strings.TrimSpace(primary))
	if out.Primary == "" {
		if len(out.Identities) == 1 {
			out.Primary = out.Identities[0].ID
		} else {
			return campaignIdentityFlags{}, fmt.Errorf("--primary-identity is required when configuring multiple identities")
		}
	}
	if _, ok := seen[out.Primary]; !ok {
		return campaignIdentityFlags{}, fmt.Errorf("primary identity %q is not configured", out.Primary)
	}
	return out, nil
}

func resolveIdentitySessionSource(source string) (*session.Session, error) {
	var raw string
	switch {
	case strings.HasPrefix(source, "env:"):
		name := strings.TrimSpace(strings.TrimPrefix(source, "env:"))
		if name == "" {
			return nil, fmt.Errorf("environment variable name is required")
		}
		raw = os.Getenv(name)
		if raw == "" {
			return nil, fmt.Errorf("environment variable %s is empty or unset", name)
		}
	case strings.HasPrefix(source, "keychain:"):
		name := strings.TrimSpace(strings.TrimPrefix(source, "keychain:"))
		if name == "" {
			return nil, fmt.Errorf("keychain key is required")
		}
		value, err := keychain.Get(name)
		if err != nil {
			return nil, err
		}
		raw = value
	default:
		return nil, fmt.Errorf("unsupported session source %q; use env:NAME or keychain:KEY", source)
	}

	var headers map[string]string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return nil, fmt.Errorf("session source must contain a JSON object of HTTP headers: %w", err)
	}
	sess := session.New(headers)
	if sess == nil || sess.Empty() {
		return nil, fmt.Errorf("session source contains no headers")
	}
	return sess, nil
}
