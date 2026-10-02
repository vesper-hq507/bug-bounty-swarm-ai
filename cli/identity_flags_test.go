package cli

import (
	"testing"
)

func TestParseCampaignIdentityFlagsFromEnvironmentReference(t *testing.T) {
	t.Setenv("USER_A_SESSION", `{"Authorization":"Bearer test-value","Cookie":"sid=abc"}`)
	got, err := parseCampaignIdentityFlags(
		[]string{"user-a:user:session-a"},
		[]string{"session-a=env:USER_A_SESSION"},
		"user-a",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Identities) != 1 || got.Primary != "user-a" {
		t.Fatalf("identity config = %+v", got)
	}
	sess := got.Sessions["session-a"]
	if sess == nil || sess.Headers["Authorization"] != "Bearer test-value" {
		t.Fatalf("session resolution failed: %+v", sess)
	}
}

func TestParseCampaignIdentityFlagsRequiresPrimaryForMultiple(t *testing.T) {
	t.Setenv("SESSION_A", `{"Authorization":"Bearer a"}`)
	t.Setenv("SESSION_B", `{"Authorization":"Bearer b"}`)
	_, err := parseCampaignIdentityFlags(
		[]string{"a:user:sa", "b:user:sb"},
		[]string{"sa=env:SESSION_A", "sb=env:SESSION_B"},
		"",
		nil,
	)
	if err == nil {
		t.Fatal("multiple identities without --primary-identity must fail")
	}
}

func TestParseCampaignIdentityFlagsRejectsLegacyAndExplicitMix(t *testing.T) {
	_, err := parseCampaignIdentityFlags(
		[]string{"anon:anonymous"},
		nil,
		"anon",
		map[string]string{"Authorization": "Bearer legacy"},
	)
	if err == nil {
		t.Fatal("explicit identities must not mix with legacy auth flags")
	}
}
