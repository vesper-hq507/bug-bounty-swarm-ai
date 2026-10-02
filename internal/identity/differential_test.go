package identity

import (
	"net/http"
	"strings"
	"testing"
)

func TestSnapshotRedactsSensitiveJSONBeforeHashing(t *testing.T) {
	h := http.Header{"Content-Type": []string{"application/json"}}
	a := Snapshot("user-a", ObjectRef{Type: "invoice", ID: "1"}, 200, h, []byte(`{"id":1,"token":"secret-a","name":"same"}`))
	b := Snapshot("user-b", ObjectRef{Type: "invoice", ID: "1"}, 200, h, []byte(`{"id":1,"token":"secret-b","name":"same"}`))
	if a.BodyFingerprint != b.BodyFingerprint {
		t.Fatal("sensitive token variation should not change normalized fingerprint")
	}
}

func TestCompareObjectAccessFlagsEquivalentNonOwnerResponse(t *testing.T) {
	owners := NewOwnershipMap()
	obj := ObjectRef{Type: "invoice", ID: "inv-1"}
	if err := owners.SetOwner(obj, "user-a"); err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Content-Type": []string{"application/json"}}
	owner := Snapshot("user-a", obj, 200, h, []byte(`{"id":"inv-1","amount":10}`))
	other := Snapshot("user-b", obj, 200, h, []byte(`{"id":"inv-1","amount":10}`))

	got := CompareObjectAccess(owner, other, owners)
	if got.Kind != DiffUnexpectedAccess {
		t.Fatalf("kind = %s, want %s", got.Kind, DiffUnexpectedAccess)
	}
	if !strings.Contains(got.Hypothesis, "BOLA/IDOR") {
		t.Fatalf("unexpected hypothesis: %q", got.Hypothesis)
	}
}

func TestCompareObjectAccessRecognizesDeniedNonOwner(t *testing.T) {
	owners := NewOwnershipMap()
	obj := ObjectRef{Type: "invoice", ID: "inv-1"}
	_ = owners.SetOwner(obj, "user-a")
	h := http.Header{"Content-Type": []string{"application/json"}}
	owner := Snapshot("user-a", obj, 200, h, []byte(`{"id":"inv-1"}`))
	other := Snapshot("user-b", obj, 403, h, []byte(`{"error":"forbidden"}`))

	got := CompareObjectAccess(owner, other, owners)
	if got.Kind != DiffOwnerOnly {
		t.Fatalf("kind = %s, want %s", got.Kind, DiffOwnerOnly)
	}
}
