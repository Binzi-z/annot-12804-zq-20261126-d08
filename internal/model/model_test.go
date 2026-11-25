package model

import (
	"math/rand"
	"testing"
)

// baseAuth builds a clean authority for generation 7 with two live signers,
// two services, and one live temp authority.
func baseAuth() Authority {
	return Authority{
		ExpectedGeneration: map[string]int{"svc-a": 7, "svc-b": 7},
		Signers: map[string]SignerState{
			"alice": {ValidFrom: 0, ValidTo: 1000},
			"bob":   {ValidFrom: 0, ValidTo: 1000},
			"carol": {ValidFrom: 0, ValidTo: 1000},
		},
		TempAuthorities: map[string]TempState{
			"T-9": {Services: []string{"svc-a", "svc-b"}, Start: 0, Expires: 500},
		},
		RevokedAuthorizers: map[string]bool{},
	}
}

func baseReq() TakeoverRequest {
	return TakeoverRequest{
		RequestKey: "rk-1",
		Generation: 7,
		At:         100,
		Required:   []string{"svc-a", "svc-b"},
		Credentials: []Credential{
			{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
			{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7},
		},
		Signoffs: []Signoff{
			Sign("alice", "rk-1", 7, 90),
			Sign("bob", "rk-1", 7, 95),
		},
	}
}

func TestValidBaseline(t *testing.T) {
	d := Decide(baseReq(), baseAuth())
	if !d.Valid {
		t.Fatalf("expected valid, got %v", d.Reasons)
	}
	if !ReferenceValid(baseReq(), baseAuth()) {
		t.Fatal("reference disagreed on baseline")
	}
}

func TestNeedsTwoIndependentSigners(t *testing.T) {
	req := baseReq()
	req.Signoffs = []Signoff{Sign("alice", "rk-1", 7, 90), Sign("alice", "rk-1", 7, 95)}
	d := Decide(req, baseAuth())
	if d.Valid || !hasReason(d, ReasonDuplicateSigner) || !hasReason(d, ReasonTooFewSigners) {
		t.Fatalf("duplicate signer should fail: %v", d.Reasons)
	}
}

func TestSignerRevoked(t *testing.T) {
	auth := baseAuth()
	s := auth.Signers["bob"]
	s.Revoked = true
	auth.Signers["bob"] = s
	if Decide(baseReq(), auth).Valid {
		t.Fatal("revoked signer must invalidate")
	}
}

func TestSignoffOutsideWindow(t *testing.T) {
	req := baseReq()
	req.Signoffs[1] = Sign("bob", "rk-1", 7, 2000) // after ValidTo
	if Decide(req, baseAuth()).Valid {
		t.Fatal("signoff outside window must fail")
	}
}

func TestSignoffFuture(t *testing.T) {
	req := baseReq()
	req.Signoffs[1] = Sign("bob", "rk-1", 7, 150) // At=100, signoff at 150 is future
	if Decide(req, baseAuth()).Valid {
		t.Fatal("future signoff must fail")
	}
}

func TestBadSignature(t *testing.T) {
	req := baseReq()
	req.Signoffs[0].Sig = "deadbeef"
	if Decide(req, baseAuth()).Valid {
		t.Fatal("forged signature must fail")
	}
}

func TestCoverageGap(t *testing.T) {
	req := baseReq()
	req.Credentials = req.Credentials[:1] // drop svc-b
	if Decide(req, baseAuth()).Valid {
		t.Fatal("coverage gap must fail")
	}
	if !hasReason(Decide(req, baseAuth()), ReasonCoverageGap) {
		t.Fatal("expected coverage gap reason")
	}
}

func TestGenerationMismatch(t *testing.T) {
	req := baseReq()
	req.Generation = 6 // not the expected generation
	if Decide(req, baseAuth()).Valid {
		t.Fatal("generation mismatch must fail")
	}
}

func TestRevokedAuthorizer(t *testing.T) {
	auth := baseAuth()
	auth.RevokedAuthorizers["auth-y"] = true
	if Decide(baseReq(), auth).Valid {
		t.Fatal("revoked authorizer must break coverage")
	}
}

func TestTempAuthorityExpiryAndNoReplay(t *testing.T) {
	req := baseReq()
	req.Credentials[1] = Credential{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7, TempAuthID: "T-9"}
	auth := baseAuth()

	// Before expiry: valid.
	if !Decide(req, auth).Valid {
		t.Fatal("live temp authority should be valid")
	}

	// At/after expiry: invalid.
	expired := req
	expired.At = 500
	if Decide(expired, auth).Valid {
		t.Fatal("expired temp authority must invalidate")
	}

	// Simulate the reaper tombstoning it, then a same-number resubmission.
	tomb := auth.TempAuthorities["T-9"]
	tomb.Tombstone = true
	auth.TempAuthorities["T-9"] = tomb
	replay := req // same TempAuthID number, same request, At still before expiry
	if Decide(replay, auth).Valid {
		t.Fatal("tombstoned temp authority must not be revivable by same-number replay")
	}
	label, isReplay := TempExpiredLabel(req.Credentials[1], req.At, auth)
	if !isReplay || label != ReasonTempReplay {
		t.Fatalf("expected replay label, got %q replay=%v", label, isReplay)
	}
}

// TestDecideMatchesReference fuzzes random mutations and asserts Decide and the
// independent ReferenceValid always agree.
func TestDecideMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	signers := []string{"alice", "bob", "carol", "dave"}
	svcs := []string{"svc-a", "svc-b", "svc-c"}
	for i := 0; i < 20000; i++ {
		auth := baseAuth()
		req := TakeoverRequest{
			RequestKey: "rk",
			Generation: 5 + rng.Intn(4),
			At:         int64(rng.Intn(1200)),
			Required:   nil,
		}
		for _, s := range svcs {
			if rng.Intn(2) == 0 {
				req.Required = append(req.Required, s)
				auth.ExpectedGeneration[s] = req.Generation
			}
		}
		// credentials
		ncred := rng.Intn(4)
		for c := 0; c < ncred; c++ {
			cred := Credential{
				ID:         "c" + string(rune('0'+c)),
				Authorizer: "auth-" + string(rune('a'+rng.Intn(3))),
				Generation: req.Generation + rng.Intn(3) - 1,
			}
			for _, s := range svcs {
				if rng.Intn(2) == 0 {
					cred.Services = append(cred.Services, s)
				}
			}
			if rng.Intn(3) == 0 {
				cred.TempAuthID = "T-" + string(rune('0'+rng.Intn(2)))
			}
			req.Credentials = append(req.Credentials, cred)
		}
		// signoffs
		nsig := rng.Intn(4)
		for s := 0; s < nsig; s++ {
			name := signers[rng.Intn(len(signers))]
			at := int64(rng.Intn(1200))
			gen := req.Generation
			if rng.Intn(4) == 0 {
				gen = req.Generation - 1
			}
			so := Sign(name, req.RequestKey, gen, at)
			if rng.Intn(10) == 0 {
				so.Sig = "bad"
			}
			req.Signoffs = append(req.Signoffs, so)
		}
		// random revocation
		for _, s := range signers {
			st := auth.Signers[s]
			st.Revoked = rng.Intn(6) == 0
			auth.Signers[s] = st
		}
		if rng.Intn(4) == 0 {
			auth.RevokedAuthorizers["auth-a"] = true
		}
		// random temp tombstone; give the temps partial grants so the
		// grant-intersection logic is genuinely exercised.
		for _, tid := range []string{"T-0", "T-1"} {
			tt := auth.TempAuthorities[tid]
			tt.Tombstone = rng.Intn(5) == 0
			tt.Services = nil
			for _, s := range svcs {
				if rng.Intn(2) == 0 {
					tt.Services = append(tt.Services, s)
				}
			}
			auth.TempAuthorities[tid] = tt
		}

		got := Decide(req, auth).Valid
		want := ReferenceValid(req, auth)
		if got != want {
			t.Fatalf("iter %d: Decide=%v Reference=%v req=%+v auth=%+v", i, got, want, req, auth)
		}
	}
}

func TestTempGrantLimitsCoverage(t *testing.T) {
	// A credential on a temp authority granted only svc-a must not cover svc-b,
	// even if it lists svc-b among its own services.
	auth := baseAuth()
	tg := auth.TempAuthorities["T-9"]
	tg.Services = []string{"svc-a"}
	auth.TempAuthorities["T-9"] = tg

	req := baseReq()
	req.Credentials[1] = Credential{
		ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"},
		Generation: 7, TempAuthID: "T-9",
	}
	d := Decide(req, auth)
	if d.Valid {
		t.Fatal("credential exceeded its temp grant but was accepted")
	}
	if !hasReason(d, ReasonCoverageGap) {
		t.Fatalf("expected coverage gap, got %v", d.Reasons)
	}
	if ReferenceValid(req, auth) {
		t.Fatal("reference disagreed: grant must limit coverage")
	}
}

func hasReason(d Decision, r string) bool {
	for _, x := range d.Reasons {
		if x == r {
			return true
		}
	}
	return false
}
