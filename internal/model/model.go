// Package model defines the pure takeover-decision semantics.
//
// A takeover decision is valid only when ALL of the following hold at the
// decision time At:
//
//  1. Two independent signers signed off (>=2 distinct signer IDs), each with a
//     valid signature that binds (signer, requestKey, generation, signedAt),
//     each signer authorized over [ValidFrom, ValidTo) at sign-off time and not
//     revoked at decision time.
//  2. Service coverage: the usable credentials, taken together, cover every
//     required service. A credential is usable only if its authorizer is not
//     revoked and (when it borrows a temporary substitute authority) that
//     authority is live at At and has never been tombstoned.
//  3. Authorization generation match: the request's generation must be the
//     current expected generation for every required service, every covering
//     credential must carry that generation, and every sign-off must attest to
//     it.
//  4. Temporary substitute authorities expire. Once a temporary authority has
//     expired it is tombstoned permanently: resubmitting the same authority
//     number cannot revive it.
package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Signoff is one independent person's approval.
type Signoff struct {
	Signer     string `json:"signer"`
	Generation int    `json:"generation"`
	At         int64  `json:"at"`
	Sig        string `json:"sig"`
}

// Credential is one credential entry participating in a takeover.
type Credential struct {
	ID         string   `json:"id"`
	Authorizer string   `json:"authorizer"`
	Services   []string `json:"services"`
	Generation int      `json:"generation"`
	// TempAuthID, when non-empty, means the credential borrows authority from a
	// temporary substitute grant and is unusable once that grant is dead.
	TempAuthID string `json:"temp_auth_id,omitempty"`
}

// SignerState is the authorization window for a signer.
type SignerState struct {
	ValidFrom int64 `json:"valid_from"`
	ValidTo   int64 `json:"valid_to"` // exclusive
	Revoked   bool  `json:"revoked"`
}

// TempState is the lifecycle state of a temporary substitute authority.
type TempState struct {
	Services  []string `json:"services"`
	Start     int64    `json:"start"`
	Expires   int64    `json:"expires"` // exclusive; At >= Expires means expired
	Tombstone bool     `json:"tombstone"`
	Revoked   bool     `json:"revoked"`
}

// Authority is the trusted authorization ledger snapshot.
type Authority struct {
	// ExpectedGeneration is the current generation required per service.
	ExpectedGeneration map[string]int         `json:"expected_generation"`
	Signers            map[string]SignerState `json:"signers"`
	TempAuthorities    map[string]TempState   `json:"temp_authorities"`
	// RevokedAuthorizers marks credential authorizers whose authority ended.
	RevokedAuthorizers map[string]bool `json:"revoked_authorizers"`
}

// TakeoverRequest is the candidate decision to evaluate.
type TakeoverRequest struct {
	RequestKey  string       `json:"request_key"`
	Generation  int          `json:"generation"`
	At          int64        `json:"at"`
	Required    []string     `json:"required"`
	Credentials []Credential `json:"credentials"`
	Signoffs    []Signoff    `json:"signoffs"`
}

// Decision is the outcome plus every reason it failed (empty when Valid).
type Decision struct {
	Valid   bool     `json:"valid"`
	Reasons []string `json:"reasons"`
}

// Reason codes returned in Decision.Reasons, stable for evidence.
const (
	ReasonTooFewSigners      = "too_few_independent_signers"
	ReasonDuplicateSigner    = "duplicate_signer"
	ReasonUnknownSigner      = "unknown_signer"
	ReasonSignerRevoked      = "signer_revoked"
	ReasonSignerWindow       = "signoff_outside_signer_window"
	ReasonSignoffFuture      = "signoff_after_decision_time"
	ReasonBadSignature       = "bad_signature"
	ReasonGenerationMismatch = "generation_mismatch"
	ReasonCoverageGap        = "service_coverage_gap"
	ReasonTempExpired        = "temp_authority_expired"
	ReasonTempReplay         = "temp_authority_replayed_after_expiry"
	ReasonTempRevoked        = "temp_authority_revoked"
	ReasonTempUnknown        = "temp_authority_unknown"
	ReasonAuthorizerRevoked  = "credential_authorizer_revoked"
)

// Canonicalize returns a sorted, de-duplicated copy of ss.
func Canonicalize(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SignoffMAC computes the deterministic signature for a signoff. The signer
// secret is synthetic and derived from the signer ID, which is enough for a
// self-contained verification harness using only standard library primitives.
func SignoffMAC(signer, requestKey string, generation int, at int64) string {
	key := []byte("rotationverify/v1/signer/" + signer)
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s\x00%d\x00%d", requestKey, generation, at)
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign constructs a correctly signed Signoff for tests and fixtures.
func Sign(signer, requestKey string, generation int, at int64) Signoff {
	return Signoff{
		Signer:     signer,
		Generation: generation,
		At:         at,
		Sig:        SignoffMAC(signer, requestKey, generation, at),
	}
}

// Decide evaluates the request against the authority snapshot.
//
// Valid is a strict conjunction of the three positive requirements (two
// independent valid sign-offs, full service coverage, generation match). The
// Reasons list is diagnostic only: it records every check that did not
// contribute, including ignorable stale sign-offs and unused stale credentials.
// A stale sign-off or stale credential never *helps* a decision, but its mere
// presence never *poisons* an otherwise-valid one; that asymmetry is what makes
// "收到旧代签核" (an old-generation sign-off arriving late) harmless.
func Decide(req TakeoverRequest, auth Authority) Decision {
	required := Canonicalize(req.Required)

	genOK := true
	for _, svc := range required {
		if exp, ok := auth.ExpectedGeneration[svc]; !ok || exp != req.Generation {
			genOK = false
			break
		}
	}

	signReasons, signOK := evaluateSignoffs(req, auth)
	coverReasons, covered := evaluateCoverage(req, auth, required)
	coverOK := true
	for _, s := range required {
		if !covered[s] {
			coverOK = false
			break
		}
	}

	reasons := dedupe(append(append([]string{}, signReasons...), coverReasons...))
	if !genOK {
		reasons = dedupe(append(reasons, ReasonGenerationMismatch))
	}
	valid := genOK && signOK && coverOK && len(required) > 0
	return Decision{Valid: valid, Reasons: reasons}
}

// evaluateSignoffs returns diagnostics and whether >=2 independent signers
// validly attested to req.Generation by req.At.
//
// Independence means distinct signer identities: a signer counts at most once,
// and only if at least one of their sign-offs is valid. Extra or duplicate
// sign-offs are noted but never subtract a legitimate signer.
func evaluateSignoffs(req TakeoverRequest, auth Authority) (reasons []string, ok bool) {
	validSigners := map[string]struct{}{}
	occurrences := map[string]int{}

	for _, so := range req.Signoffs {
		occurrences[so.Signer]++
		if occurrences[so.Signer] > 1 {
			reasons = append(reasons, ReasonDuplicateSigner)
		}
		if so.Generation != req.Generation {
			// Old-generation sign-off: ignored, cannot attest to current gen.
			reasons = append(reasons, ReasonGenerationMismatch)
			continue
		}
		st, exists := auth.Signers[so.Signer]
		switch {
		case !exists:
			reasons = append(reasons, ReasonUnknownSigner)
		case st.Revoked:
			reasons = append(reasons, ReasonSignerRevoked)
		case so.At < st.ValidFrom || so.At >= st.ValidTo:
			reasons = append(reasons, ReasonSignerWindow)
		case so.At > req.At:
			reasons = append(reasons, ReasonSignoffFuture)
		case !hmac.Equal([]byte(so.Sig), []byte(SignoffMAC(so.Signer, req.RequestKey, so.Generation, so.At))):
			reasons = append(reasons, ReasonBadSignature)
		default:
			validSigners[so.Signer] = struct{}{}
		}
	}

	if len(validSigners) < 2 {
		reasons = append(reasons, ReasonTooFewSigners)
		return reasons, false
	}
	return reasons, true
}

// usableCredential reports whether cred may contribute coverage at req.At, and
// which of its services it actually covers at req.Generation.
//
// A credential that borrows a temporary substitute authority can only cover the
// services that authority was granted; its own Services list may not exceed the
// grant.
func usableCredential(cred Credential, req TakeoverRequest, auth Authority) (covered []string, reasons []string) {
	if auth.RevokedAuthorizers[cred.Authorizer] {
		return nil, []string{ReasonAuthorizerRevoked}
	}
	var granted []string
	if cred.TempAuthID != "" {
		t, ok := auth.TempAuthorities[cred.TempAuthID]
		if !ok {
			return nil, []string{ReasonTempUnknown}
		}
		if t.Tombstone || req.At >= t.Expires {
			return nil, []string{ReasonTempExpired} // permanent; same-number replay cannot revive
		}
		if t.Revoked {
			return nil, []string{ReasonTempRevoked}
		}
		if req.At < t.Start {
			return nil, []string{ReasonTempExpired} // not yet live
		}
		granted = t.Services
	}
	if cred.Generation != req.Generation {
		// Stale or future credential: it covers nothing this generation.
		return nil, []string{ReasonGenerationMismatch}
	}
	if cred.TempAuthID != "" {
		return intersect(cred.Services, granted), nil
	}
	return Canonicalize(cred.Services), nil
}

// intersect returns the sorted, de-duplicated services present in both lists.
func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return Canonicalize(out)
}

// evaluateCoverage checks that all required services are covered; it also
// returns the covered set and the missing services for evidence.
func evaluateCoverage(req TakeoverRequest, auth Authority, required []string) (reasons []string, covered map[string]bool) {
	covered = map[string]bool{}
	for _, cred := range req.Credentials {
		svcs, rs := usableCredential(cred, req, auth)
		reasons = append(reasons, rs...)
		for _, s := range svcs {
			covered[s] = true
		}
	}
	for _, s := range required {
		if !covered[s] {
			reasons = append(reasons, ReasonCoverageGap)
			break
		}
	}
	return dedupe(reasons), covered
}

func dedupe(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := ss[:0]
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ReferenceValid is an independently written predicate used to cross-check
// Decide. It uses a different control flow (set algebra / early exit) so an
// implementation bug is unlikely to be mirrored.
func ReferenceValid(req TakeoverRequest, auth Authority) bool {
	required := map[string]struct{}{}
	for _, s := range req.Required {
		required[s] = struct{}{}
	}
	if len(required) == 0 {
		return false // a takeover that covers nothing is not a valid takeover
	}
	// generation currency
	for s := range required {
		if auth.ExpectedGeneration[s] != req.Generation {
			return false
		}
	}
	// signers: build a set of signers that pass every check
	good := map[string]bool{}
	for _, so := range req.Signoffs {
		ok := so.Generation == req.Generation &&
			so.At <= req.At &&
			!good[so.Signer] &&
			signatureOK(so, req.RequestKey)
		st, exists := auth.Signers[so.Signer]
		ok = ok && exists && !st.Revoked && so.At >= st.ValidFrom && so.At < st.ValidTo
		if ok {
			good[so.Signer] = true
		}
	}
	if len(good) < 2 {
		return false
	}
	// coverage
	have := map[string]bool{}
	for _, c := range req.Credentials {
		if auth.RevokedAuthorizers[c.Authorizer] {
			continue
		}
		var granted map[string]struct{}
		if c.TempAuthID != "" {
			t, exists := auth.TempAuthorities[c.TempAuthID]
			if !exists || t.Tombstone || t.Revoked || req.At < t.Start || req.At >= t.Expires {
				continue
			}
			granted = make(map[string]struct{}, len(t.Services))
			for _, s := range t.Services {
				granted[s] = struct{}{}
			}
		}
		if c.Generation != req.Generation {
			continue
		}
		for _, s := range c.Services {
			// A borrowed authority only covers what it was granted.
			if granted != nil {
				if _, ok := granted[s]; !ok {
					continue
				}
			}
			have[s] = true
		}
	}
	for s := range required {
		if !have[s] {
			return false
		}
	}
	return true
}

func signatureOK(so Signoff, requestKey string) bool {
	want := SignoffMAC(so.Signer, requestKey, so.Generation, so.At)
	return hmac.Equal([]byte(so.Sig), []byte(want))
}

// TempExpiredLabel distinguishes the two temp-authority failure modes for
// evidence: a plain expiry versus a post-expiry same-number replay.
func TempExpiredLabel(cred Credential, at int64, auth Authority) (label string, isReplay bool) {
	t, ok := auth.TempAuthorities[cred.TempAuthID]
	if !ok {
		return ReasonTempUnknown, false
	}
	if t.Tombstone {
		return ReasonTempReplay, true
	}
	if at >= t.Expires {
		return ReasonTempExpired, false
	}
	return "", false
}

// Describe returns a human summary of a decision for logs.
func (d Decision) Describe() string {
	if d.Valid {
		return "VALID"
	}
	return "INVALID(" + strings.Join(d.Reasons, ",") + ")"
}
