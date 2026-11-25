// Package graph exhaustively enumerates a small decision graph over sign-off
// choices and time windows, and reports:
//
//   - the truth table of validity across the enumerated states,
//   - the minimal coverage evidence (a smallest witness that decides valid),
//   - the first invalidation watermark: the earliest decision time at which a
//     rotation checklist that was valid at the start of the timeline first
//     becomes invalid along a fixed, monotone timeline of authoritative events.
//
// Everything here is a pure function of the inputs so the verifier can
// recompute it from the same on-disk inputs without trusting the run.
package graph

import (
	"fmt"
	"sort"

	"rotationverify/internal/model"
)

// Case is one enumerated decision state.
type Case struct {
	// SignerMask records which signers signed off (indices into Signers).
	SignerMask []string `json:"signer_mask"`
	// Generation of both the request and the sign-offs.
	Generation int `json:"generation"`
	// SignoffWindow tags whether sign-offs fall inside or outside the signer
	// authorization window.
	SignoffWindow string `json:"signoff_window"`
	// At is the decision time.
	At int64 `json:"at"`
	// Valid is model.Decide's verdict.
	Valid bool `json:"valid"`
	// Reference agrees with Valid.
	Reference bool `json:"reference"`
	// Reasons is the diagnostic set.
	Reasons []string `json:"reasons,omitempty"`
}

// Result is the full enumeration output.
type Result struct {
	Cases []Case `json:"cases"`
	// Agree is true iff Decide == ReferenceValid for every case.
	Agree bool `json:"agree"`
	// NumCases is len(Cases).
	NumCases int `json:"num_cases"`
	// ValidCount is how many cases are valid.
	ValidCount int `json:"valid_count"`
	// MinimalWitness is the smallest (fewest signoffs, then fewest credentials)
	// valid case found.
	MinimalWitness MinimalWitness `json:"minimal_witness"`
	// Watermark is the first invalidation watermark on the canonical timeline.
	Watermark Watermark `json:"watermark"`
}

// MinimalWitness is a smallest independently-checkable proof of validity.
type MinimalWitness struct {
	Found       bool     `json:"found"`
	Signers     []string `json:"signers"`
	Credentials []string `json:"credentials"`
	Services    []string `json:"services"`
	At          int64    `json:"at"`
	Generation  int      `json:"generation"`
	// Reproducible records the exact request so the verifier can re-decide.
	Request model.TakeoverRequest `json:"request"`
	Auth    model.Authority       `json:"auth"`
	// Minimality proves that dropping any single required element breaks
	// validity. Each check's Pass means "reduction correctly became invalid".
	Minimality []MinimalityCheck `json:"minimality"`
	// Minimal is true iff the witness is valid and every reduction is invalid.
	Minimal bool `json:"minimal"`
}

// MinimalityCheck is one "remove one element -> must be invalid" probe.
// Valid is the validity after removal (should be false); Pass is Valid==false.
type MinimalityCheck struct {
	Removed string `json:"removed"`
	Valid   bool   `json:"valid"`
	Pass    bool   `json:"pass"`
}

// Watermark is the first tick at which a previously-valid checklist fails.
type Watermark struct {
	// Timeline is the ascending list of decision times examined.
	Timeline []TimelinePoint `json:"timeline"`
	// FirstInvalidAt is the decision time of the first valid->invalid
	// transition; -1 if the checklist never becomes invalid.
	FirstInvalidAt int64 `json:"first_invalid_at"`
	// FirstInvalidReason explains why it failed at that tick.
	FirstInvalidReason []string `json:"first_invalid_reason,omitempty"`
	// Trigger names the authoritative event that caused the invalidation.
	Trigger string `json:"trigger,omitempty"`
}

// TimelinePoint is one evaluated decision time.
type TimelinePoint struct {
	At     int64    `json:"at"`
	Valid  bool     `json:"valid"`
	Reason []string `json:"reason,omitempty"`
}

// Enumerate builds the small graph and evaluates every state.
//
// The graph axes are:
//   - which distinct signers contribute a sign-off: all subsets of size 0..2
//     over two signers (so 1, 2, and 3+ signer situations are represented),
//   - the request/sign-off generation: current (7) or stale (6),
//   - the sign-off time window: inside [0,1000) or outside (at/after 1000),
//   - the decision time At: {50, 400, 600} straddling the temp-authority expiry
//     at 500.
//
// That yields a small but exhaustive grid whose every cell is checked.
func Enumerate() Result {
	auth := canonicalAuth()
	signers := []string{"alice", "bob"}
	times := []int64{50, 400, 600}
	gens := []int{7, 6}
	windows := []string{"inside", "outside"}

	var cases []Case
	for _, mask := range signerSubsets(signers) {
		for _, gen := range gens {
			for _, win := range windows {
				for _, at := range times {
					req := canonicalRequest(gen, at, mask, win)
					d := model.Decide(req, auth)
					ref := model.ReferenceValid(req, auth)
					cases = append(cases, Case{
						SignerMask:    mask,
						Generation:    gen,
						SignoffWindow: win,
						At:            at,
						Valid:         d.Valid,
						Reference:     ref,
						Reasons:       d.Reasons,
					})
				}
			}
		}
	}

	res := Result{Cases: cases, NumCases: len(cases), Agree: true}
	for _, c := range cases {
		if c.Valid != c.Reference {
			res.Agree = false
		}
		if c.Valid {
			res.ValidCount++
		}
	}
	res.MinimalWitness = findMinimalWitness(auth, signers)
	res.Watermark = computeWatermark(auth)
	return res
}

// findMinimalWitness searches for a valid decision with the fewest sign-offs,
// then fewest credentials, and returns its exact reproducible request.
func findMinimalWitness(auth model.Authority, signers []string) MinimalWitness {
	// Try credential sets of increasing size, then signer pairs of increasing
	// size, keeping the first valid combination.
	credSets := [][]model.Credential{
		{ // one credential covering both services is ideal
			{ID: "c-merged", Authorizer: "auth-x", Services: []string{"svc-a", "svc-b"}, Generation: 7},
		},
		{ // otherwise two single-service credentials
			{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
			{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7},
		},
	}
	for _, creds := range credSets {
		for _, mask := range signerSubsets(signers) {
			if len(mask) < 2 {
				continue
			}
			req := model.TakeoverRequest{
				RequestKey:  "witness",
				Generation:  7,
				At:          100,
				Required:    []string{"svc-a", "svc-b"},
				Credentials: creds,
				Signoffs:    signoffsFor("witness", mask, 7, 100),
			}
			d := model.Decide(req, auth)
			if d.Valid {
				svcs := map[string]bool{}
				var cids []string
				for _, c := range creds {
					cids = append(cids, c.ID)
					for _, s := range c.Services {
						svcs[s] = true
					}
				}
				w := MinimalWitness{
					Found:       true,
					Signers:     mask,
					Credentials: cids,
					Services:    sortedKeys(svcs),
					At:          req.At,
					Generation:  req.Generation,
					Request:     req,
					Auth:        auth,
				}
				proveMinimal(&w)
				return w
			}
		}
	}
	return MinimalWitness{Found: false}
}

// computeWatermark walks a fixed ascending timeline and reports the first tick
// where the checklist, valid at the first tick, becomes invalid.
//
// The canonical timeline holds all else fixed (two current-gen sign-offs, two
// covering credentials) and advances At across the temp-authority expiry at 500
// and the signer window end at 1000. The first invalidation is therefore the
// temporary-substitute expiry.
func computeWatermark(auth model.Authority) Watermark {
	timeline := []int64{0, 100, 250, 400, 499, 500, 501, 750, 999, 1000, 1200}
	w := Watermark{FirstInvalidAt: -1}
	wasValid := false
	for i, at := range timeline {
		req := model.TakeoverRequest{
			RequestKey: "wm",
			Generation: 7,
			At:         at,
			Required:   []string{"svc-a", "svc-b"},
			Credentials: []model.Credential{
				{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
				// c2 borrows the temporary authority T-9 for svc-b.
				{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7, TempAuthID: "T-9"},
			},
			Signoffs: signoffsFor("wm", []string{"alice", "bob"}, 7, 0),
		}
		// Sign-offs are fixed at t=0 (inside every window), decision varies.
		d := model.Decide(req, auth)
		w.Timeline = append(w.Timeline, TimelinePoint{At: at, Valid: d.Valid, Reason: d.Reasons})
		if i == 0 {
			wasValid = d.Valid
			continue
		}
		if wasValid && !d.Valid && w.FirstInvalidAt == -1 {
			w.FirstInvalidAt = at
			w.FirstInvalidReason = d.Reasons
			w.Trigger = triggerFor(at)
		}
		wasValid = d.Valid
	}
	return w
}

func triggerFor(at int64) string {
	switch {
	case at >= 500 && at < 1000:
		return "temp_authority_expired_at_500"
	case at >= 1000:
		return "signer_window_closed_at_1000"
	default:
		return "unknown"
	}
}

// proveMinimal checks that removing any single sign-off or credential from the
// witness makes the decision invalid. That is what "minimal coverage evidence"
// means: nothing in the witness is redundant.
func proveMinimal(w *MinimalWitness) {
	ok := true
	for i := range w.Request.Signoffs {
		reduced := cloneReq(w.Request)
		reduced.Signoffs = append(reduced.Signoffs[:i:i], reduced.Signoffs[i+1:]...)
		v := model.Decide(reduced, w.Auth).Valid
		c := MinimalityCheck{Removed: "signoff:" + w.Request.Signoffs[i].Signer, Valid: v, Pass: !v}
		w.Minimality = append(w.Minimality, c)
		ok = ok && c.Pass
	}
	for i := range w.Request.Credentials {
		reduced := cloneReq(w.Request)
		reduced.Credentials = append(reduced.Credentials[:i:i], reduced.Credentials[i+1:]...)
		v := model.Decide(reduced, w.Auth).Valid
		c := MinimalityCheck{Removed: "credential:" + w.Request.Credentials[i].ID, Valid: v, Pass: !v}
		w.Minimality = append(w.Minimality, c)
		ok = ok && c.Pass
	}
	w.Minimal = ok
}

func cloneReq(r model.TakeoverRequest) model.TakeoverRequest {
	out := r
	out.Required = append([]string(nil), r.Required...)
	out.Credentials = append([]model.Credential(nil), r.Credentials...)
	out.Signoffs = append([]model.Signoff(nil), r.Signoffs...)
	return out
}

// -- canonical fixtures -----------------------------------------------------

func canonicalAuth() model.Authority {
	return model.Authority{
		ExpectedGeneration: map[string]int{"svc-a": 7, "svc-b": 7},
		Signers: map[string]model.SignerState{
			"alice": {ValidFrom: 0, ValidTo: 1000},
			"bob":   {ValidFrom: 0, ValidTo: 1000},
		},
		TempAuthorities: map[string]model.TempState{
			"T-9": {Services: []string{"svc-a", "svc-b"}, Start: 0, Expires: 500},
		},
		RevokedAuthorizers: map[string]bool{},
	}
}

func canonicalRequest(gen int, at int64, signerMask []string, window string) model.TakeoverRequest {
	signTime := int64(90)
	if window == "outside" {
		signTime = 1500 // after both the signer window and any decision time
	}
	return model.TakeoverRequest{
		RequestKey: fmt.Sprintf("graph-%d-%d-%v-%s", gen, at, signerMask, window),
		Generation: gen,
		At:         at,
		Required:   []string{"svc-a", "svc-b"},
		Credentials: []model.Credential{
			{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
			{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7},
		},
		Signoffs: signoffsFor(fmt.Sprintf("graph-%d-%d-%v-%s", gen, at, signerMask, window), signerMask, gen, signTime),
	}
}

func signoffsFor(requestKey string, signerMask []string, gen int, at int64) []model.Signoff {
	out := make([]model.Signoff, 0, len(signerMask))
	for _, s := range signerMask {
		out = append(out, model.Sign(s, requestKey, gen, at))
	}
	return out
}

// signerSubsets returns all subsets of ss up to size 2 (empty, singletons,
// the full pair), in deterministic order.
func signerSubsets(ss []string) [][]string {
	out := [][]string{{}}
	for i := range ss {
		out = append(out, []string{ss[i]})
	}
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			out = append(out, []string{ss[i], ss[j]})
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
