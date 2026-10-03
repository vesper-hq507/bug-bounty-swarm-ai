package mobile

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/identity"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/programterms"
)

// CompareControlled performs offline differential authorization analysis across
// two captures from controlled identities. It never replays a mobile request.
func CompareControlled(owner, actor Capture, def scope.ScopeDefinition, constraints programterms.Constraints) []identity.DifferentialResult {
	if owner.IdentityAlias == "" || actor.IdentityAlias == "" ||
		owner.IdentityAlias == actor.IdentityAlias {
		return nil
	}
	actorIndex := make(map[string]*Transaction, len(actor.Transactions))
	for i := range actor.Transactions {
		tx := &actor.Transactions[i]
		if scope.Validate(tx.URL, def) != nil || deniedPath(tx.URL, constraints.DisallowedPaths) {
			continue
		}
		actorIndex[transactionKey(*tx)] = tx
	}

	owners := identity.NewOwnershipMap()
	var out []identity.DifferentialResult
	for i := range owner.Transactions {
		ownerTx := &owner.Transactions[i]
		if scope.Validate(ownerTx.URL, def) != nil || deniedPath(ownerTx.URL, constraints.DisallowedPaths) {
			continue
		}
		actorTx := actorIndex[transactionKey(*ownerTx)]
		if actorTx == nil {
			continue
		}
		obj, ok := objectRef(ownerTx.URL)
		if !ok {
			continue
		}
		if err := owners.SetOwner(obj, identity.ID(owner.IdentityAlias)); err != nil {
			continue
		}
		ownerObs := identity.Snapshot(
			identity.ID(owner.IdentityAlias), obj, ownerTx.StatusCode,
			responseHeader(ownerTx.ResponseHeaders), ownerTx.ResponseBody,
		)
		actorObs := identity.Snapshot(
			identity.ID(actor.IdentityAlias), obj, actorTx.StatusCode,
			responseHeader(actorTx.ResponseHeaders), actorTx.ResponseBody,
		)
		out = append(out, identity.CompareObjectAccess(ownerObs, actorObs, owners))
	}
	return out
}

func transactionKey(tx Transaction) string {
	return strings.ToUpper(strings.TrimSpace(tx.Method)) + " " + strings.TrimSpace(tx.URL)
}

func objectRef(rawURL string) (identity.ObjectRef, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return identity.ObjectRef{}, false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return identity.ObjectRef{}, false
	}
	objectID := strings.TrimSpace(parts[len(parts)-1])
	objectType := strings.TrimSpace(parts[len(parts)-2])
	if objectID == "" || objectType == "" {
		return identity.ObjectRef{}, false
	}
	return identity.ObjectRef{Type: objectType, ID: objectID}, true
}

func responseHeader(values map[string]string) http.Header {
	h := make(http.Header, len(values))
	for key, value := range values {
		h.Set(key, value)
	}
	return h
}
