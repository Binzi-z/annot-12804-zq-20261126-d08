package graph

import (
	"testing"

	"rotationverify/internal/model"
)

func TestEnumerateAgreesAndWatermark(t *testing.T) {
	res := Enumerate()
	if !res.Agree {
		t.Fatal("Decide and ReferenceValid disagreed on some enumerated case")
	}
	if res.NumCases != 4*2*2*3 { // 4 signer subsets x 2 gens x 2 windows x 3 times
		t.Fatalf("num cases = %d, want 48", res.NumCases)
	}
	if res.ValidCount == 0 {
		t.Fatal("expected some valid cases")
	}

	// Minimal witness must be a single credential covering both services with
	// exactly two signers.
	if !res.MinimalWitness.Found {
		t.Fatal("no minimal witness found")
	}
	if len(res.MinimalWitness.Signers) != 2 {
		t.Fatalf("witness signers = %v, want 2", res.MinimalWitness.Signers)
	}
	if len(res.MinimalWitness.Credentials) != 1 {
		t.Fatalf("witness credentials = %v, want 1 merged credential", res.MinimalWitness.Credentials)
	}
	// Re-decide the witness independently: must be valid.
	if d := model.Decide(res.MinimalWitness.Request, res.MinimalWitness.Auth); !d.Valid {
		t.Fatalf("minimal witness re-decision invalid: %v", d.Reasons)
	}
	// Minimality: dropping any element must break validity.
	if !res.MinimalWitness.Minimal {
		t.Fatalf("witness is not minimal: %+v", res.MinimalWitness.Minimality)
	}
	if len(res.MinimalWitness.Minimality) != 3 { // 2 signoffs + 1 merged credential
		t.Fatalf("expected 3 minimality checks, got %d", len(res.MinimalWitness.Minimality))
	}

	// Watermark: first invalidation at the temp-authority expiry (500).
	if res.Watermark.FirstInvalidAt != 500 {
		t.Fatalf("first invalid at %d, want 500", res.Watermark.FirstInvalidAt)
	}
	if res.Watermark.Trigger != "temp_authority_expired_at_500" {
		t.Fatalf("trigger = %q", res.Watermark.Trigger)
	}
	if !contains(res.Watermark.FirstInvalidReason, model.ReasonCoverageGap) &&
		!contains(res.Watermark.FirstInvalidReason, model.ReasonTempExpired) {
		t.Fatalf("unexpected watermark reason: %v", res.Watermark.FirstInvalidReason)
	}
}

// TestAllValidCasesHaveTwoCurrentSigners is a structural invariant across the
// whole enumeration. The enumerated cases use plain credentials (no borrowed
// temp authority), so they stay valid past the temp expiry at 500; that
// dependence is exercised separately by computeWatermark.
func TestAllValidCasesHaveTwoCurrentSigners(t *testing.T) {
	res := Enumerate()
	for _, c := range res.Cases {
		if c.Valid {
			if len(c.SignerMask) < 2 {
				t.Fatalf("valid case with <2 signers: %+v", c)
			}
			if c.Generation != 7 || c.SignoffWindow != "inside" {
				t.Fatalf("valid case outside constraints: %+v", c)
			}
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
