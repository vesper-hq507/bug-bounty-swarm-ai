package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

type Observation struct {
	IdentityID      ID
	Object          ObjectRef
	StatusCode      int
	ContentType     string
	BodyFingerprint string
	BodyLength      int
}

func Snapshot(id ID, obj ObjectRef, status int, header http.Header, body []byte) Observation {
	normalized := normalizeBody(header.Get("Content-Type"), body)
	sum := sha256.Sum256(normalized)
	return Observation{
		IdentityID:       id,
		Object:           obj,
		StatusCode:       status,
		ContentType:      header.Get("Content-Type"),
		BodyFingerprint:  hex.EncodeToString(sum[:16]),
		BodyLength:       len(normalized),
	}
}

type DifferentialKind string

const (
	DiffEquivalent       DifferentialKind = "equivalent"
	DiffDifferent        DifferentialKind = "different"
	DiffOwnerOnly        DifferentialKind = "owner_only"
	DiffUnexpectedAccess DifferentialKind = "unexpected_access"
)

type DifferentialResult struct {
	Kind        DifferentialKind
	Owner       ID
	Actor       ID
	Object      ObjectRef
	OwnerStatus int
	ActorStatus int
	SameBody    bool
	Hypothesis  string
	EvidenceRefs []string
}

func CompareObjectAccess(ownerObs, actorObs Observation, owners *OwnershipMap) DifferentialResult {
	ownerID := ownerObs.IdentityID
	if owners != nil {
		if known, ok := owners.OwnerOf(ownerObs.Object); ok {
			ownerID = known
		}
	}
	sameBody := ownerObs.BodyFingerprint != "" && ownerObs.BodyFingerprint == actorObs.BodyFingerprint
	ownerAllowed := allowedStatus(ownerObs.StatusCode)
	actorAllowed := allowedStatus(actorObs.StatusCode)

	result := DifferentialResult{
		Owner:       ownerID,
		Actor:       actorObs.IdentityID,
		Object:      ownerObs.Object,
		OwnerStatus: ownerObs.StatusCode,
		ActorStatus: actorObs.StatusCode,
		SameBody:    sameBody,
	}
	switch {
	case ownerAllowed && actorObs.IdentityID != ownerID && actorAllowed && sameBody:
		result.Kind = DiffUnexpectedAccess
		result.Hypothesis = "possible BOLA/IDOR: non-owner received the same successful object representation as the owner"
	case ownerAllowed && !actorAllowed:
		result.Kind = DiffOwnerOnly
		result.Hypothesis = "ownership boundary appears enforced for this observation"
	case ownerObs.StatusCode == actorObs.StatusCode && sameBody:
		result.Kind = DiffEquivalent
	default:
		result.Kind = DiffDifferent
	}
	return result
}

func allowedStatus(code int) bool { return code >= 200 && code < 300 }

func normalizeBody(contentType string, body []byte) []byte {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return []byte(strings.TrimSpace(string(body)))
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return []byte(strings.TrimSpace(string(body)))
	}
	redactJSON(v)
	b, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return b
}

var sensitiveJSONKeys = map[string]struct{}{
	"authorization": {}, "cookie": {}, "password": {}, "token": {},
	"access_token": {}, "refresh_token": {}, "secret": {}, "api_key": {},
}

func redactJSON(v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, sensitive := sensitiveJSONKeys[strings.ToLower(k)]; sensitive {
				x[k] = "[REDACTED]"
				continue
			}
			redactJSON(x[k])
		}
	case []any:
		for _, item := range x {
			redactJSON(item)
		}
	}
}
