package connector

import "testing"

// TestEntitlementSlugRegressionPin guards against an accidental rename of the
// shared entitlement slug: it's built into every group/role/userGroup/site
// entitlement and grant ID already synced for existing customers, so a rename
// here would silently orphan every existing grant of these types. Asserts
// against the literal string, not memberEntitlement itself, so renaming the
// constant's value actually fails this test instead of trivially passing.
func TestEntitlementSlugRegressionPin(t *testing.T) {
	const wantMemberSlug = "member"
	if memberEntitlement != wantMemberSlug {
		t.Fatalf("memberEntitlement slug changed: got %q, want %q — this orphans every existing grant of this type", memberEntitlement, wantMemberSlug)
	}
}
