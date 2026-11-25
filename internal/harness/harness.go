// Package harness reproduces the three required concurrency/recovery failure
// modes against a real durable commit log:
//
//  1. Revocation wins the race: a takeover decided against a stale authority
//     view must not be committed after a revocation that invalidates it.
//  2. Takeover committed but the response is lost: a promised (fsync'd) commit
//     whose acknowledgement never reaches the caller must be recoverable and
//     idempotent on resubmission.
//  3. Old-generation sign-off after recovery: after a restart, sign-offs from a
//     previous authorization generation must not approve the new generation.
//
// The workers run on two goroutines, synchronised by a cyclic barrier, with
// explicit fault points between commit and acknowledgement. Every scenario
// emits a self-contained evidence record. The commit log on disk is the
// authoritative artifact; verification re-reads it rather than trusting the
// in-memory trace.
package harness

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"rotationverify/internal/model"
	"rotationverify/internal/store"
)

// Barrier is a cyclic barrier for N workers.
type Barrier struct {
	n     int
	mu    sync.Mutex
	cond  *sync.Cond
	count int
	gen   int
}

// NewBarrier returns a barrier that releases every N waiters.
func NewBarrier(n int) *Barrier {
	b := &Barrier{n: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Wait blocks until N workers have arrived, then releases them together.
func (b *Barrier) Wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.gen
	b.count++
	if b.count == b.n {
		b.count = 0
		b.gen++
		b.cond.Broadcast()
		return
	}
	for g == b.gen {
		b.cond.Wait()
	}
}

// Event is one ordered observation in a scenario trace.
type Event struct {
	Seq    int    `json:"seq"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Rev    int64  `json:"rev"`
	Note   string `json:"note,omitempty"`
}

// Assertion is one checked invariant with expected vs actual.
type Assertion struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Pass     bool   `json:"pass"`
}

// ScenarioResult is the evidence for one reproduced failure mode.
type ScenarioResult struct {
	Name       string      `json:"name"`
	CommitLog  string      `json:"commit_log"` // path relative to run dir
	Events     []Event     `json:"events"`
	Assertions []Assertion `json:"assertions"`
	Pass       bool        `json:"pass"`
	FinalRev   int64       `json:"final_revision"`
	// RecordCounts is the on-disk count per record type, for the verifier.
	RecordCounts map[string]int `json:"record_counts"`
}

// recorder assigns monotonic sequence numbers under a lock so concurrent
// workers cannot interleave sequence numbers, keeping the trace deterministic.
type recorder struct {
	mu     sync.Mutex
	seq    int
	events []Event
}

func (r *recorder) add(actor, action string, rev int64, note string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.events = append(r.events, Event{Seq: r.seq, Actor: actor, Action: action, Rev: rev, Note: note})
}

func (r *recorder) list() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recorder) mark(name, expected, actual string) Assertion {
	return Assertion{Name: name, Expected: expected, Actual: actual, Pass: expected == actual}
}

var errResponseLost = errors.New("response lost after durable commit")

// -- Scenario 1: revocation wins the race -----------------------------------

// RevocationWins demonstrates that when revocation commits first, a takeover
// whose credential authority was just revoked cannot be accepted. The takeover
// worker (a) is rejected at the stale revision and (b) re-evaluated against the
// post-revocation authority is invalid because coverage is gone.
func RevocationWins(runDir string) (ScenarioResult, error) {
	dir := filepath.Join(runDir, "revocation_wins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ScenarioResult{}, err
	}
	logPath := filepath.Join(dir, "commit.log")
	st, err := store.Open(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	defer st.Close()

	rec := &recorder{}
	base := st.Revision()

	auth := baseAuthority()
	req := baseTakeover()
	// The takeover depends on auth-y (credential c2 covers svc-b).
	if !model.Decide(req, auth).Valid {
		return ScenarioResult{}, fmt.Errorf("precondition: takeover should start valid: %v", model.Decide(req, auth).Reasons)
	}

	barrier := NewBarrier(2)
	revokeDone := make(chan struct{})
	var takeoverOutcome store.Outcome
	var takeoverErr error
	var reeval model.Decision
	var wg sync.WaitGroup

	// Revocation worker.
	wg.Add(1)
	go func() {
		defer wg.Done()
		barrier.Wait() // align both workers, then revoke commits first
		rec.add("revoke-worker", "commit_revocation", 0, "revoke auth-y (feeds credential c2)")
		o, err := st.Append(store.Record{
			Type: store.RecRevocation, RequestKey: "rv-auth-y", Target: "auth-y",
			Actor: "revoke-worker", BaseRevision: base,
		})
		if err != nil {
			rec.add("revoke-worker", "commit_error", 0, err.Error())
		} else {
			rec.add("revoke-worker", "committed", o.Revision, "")
		}
		close(revokeDone)
	}()

	// Takeover worker.
	wg.Add(1)
	go func() {
		defer wg.Done()
		barrier.Wait()
		<-revokeDone // fault point: force revocation to get ahead deterministically
		rec.add("takeover-worker", "commit_attempt_stale", base, "still holding pre-revocation authority view")
		takeoverOutcome, takeoverErr = st.Append(store.Record{
			Type: store.RecTakeover, RequestKey: req.RequestKey, Generation: req.Generation,
			Target: "svc-a,svc-b", Actor: "takeover-worker", Valid: true, BaseRevision: base,
		})
		if takeoverErr != nil {
			rec.add("takeover-worker", "commit_rejected", st.Revision(), takeoverErr.Error())
		} else {
			rec.add("takeover-worker", "committed", takeoverOutcome.Revision, "")
		}
		// Re-evaluate against the post-revocation authority.
		auth2 := auth
		auth2.RevokedAuthorizers = copyBoolMap(auth.RevokedAuthorizers)
		auth2.RevokedAuthorizers["auth-y"] = true
		reeval = model.Decide(req, auth2)
		rec.add("takeover-worker", "reeval_after_revoke", st.Revision(), reeval.Describe())
	}()
	wg.Wait()

	res := ScenarioResult{Name: "revocation_wins", CommitLog: rel(runDir, logPath)}
	res.Events = rec.list()
	res.Assertions = append(res.Assertions,
		rec.mark("takeover_commit_rejected_stale", "true", boolStr(errors.Is(takeoverErr, store.ErrStaleRevision))),
		rec.mark("reeval_invalid_after_revoke", "true", boolStr(!reeval.Valid)),
		rec.mark("reeval_reports_coverage_gap", "true", boolStr(hasReason(reeval, model.ReasonCoverageGap))),
		rec.mark("no_takeover_record", "true", boolStr(!hasType(st.Records(), store.RecTakeover))),
		rec.mark("exactly_one_revocation", "1", itoa(countType(st.Records(), store.RecRevocation))),
	)
	res.Pass = allPass(res.Assertions)
	res.FinalRev = st.Revision()
	res.RecordCounts = countAll(st.Records())
	return res, nil
}

// -- Scenario 2: takeover committed, response lost -------------------------

// LostResponse demonstrates that a takeover committed to stable storage whose
// acknowledgement is lost is (a) still present on disk, and (b) idempotently
// recoverable: resubmitting the same request key after reopening the store
// returns the original outcome without appending a second record.
func LostResponse(runDir string) (ScenarioResult, error) {
	dir := filepath.Join(runDir, "lost_response")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ScenarioResult{}, err
	}
	logPath := filepath.Join(dir, "commit.log")
	rec := &recorder{}

	auth := baseAuthority()
	req := baseTakeover()
	d := model.Decide(req, auth)
	if !d.Valid {
		return ScenarioResult{}, fmt.Errorf("precondition: takeover invalid: %v", d.Reasons)
	}

	// Phase 1: worker commits, then loses the response at a fault point.
	phase1 := func() (lostRev int64, gotErr error) {
		st, err := store.Open(logPath)
		if err != nil {
			return 0, err
		}
		defer st.Close()
		o, err := st.Append(store.Record{
			Type: store.RecTakeover, RequestKey: req.RequestKey, Generation: req.Generation,
			Target: "svc-a,svc-b", Actor: "takeover-worker", Valid: true, BaseRevision: 0,
			Detail: d.Describe(),
		})
		if err != nil {
			return 0, err
		}
		rec.add("takeover-worker", "committed_fsync", o.Revision, "durable before ack")
		// Fault point: the acknowledgement is lost.
		rec.add("fault", "response_lost", o.Revision, "caller never sees success")
		return o.Revision, errResponseLost
	}
	lostRev, gotErr := phase1()
	if !errors.Is(gotErr, errResponseLost) {
		return ScenarioResult{}, fmt.Errorf("expected response-lost fault, got %v", gotErr)
	}
	// Confirm durability by reading the file directly (independent of the worker).
	raw1, err := os.ReadFile(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	onDiskAfterCrash := countLines(raw1)

	// Phase 2: recovery — reopen the log and resubmit the same request key.
	st2, err := store.Open(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	defer st2.Close()
	rec.add("recovery", "reopened", st2.Revision(), "replayed from disk")
	out2, err := st2.Append(store.Record{
		Type: store.RecTakeover, RequestKey: req.RequestKey, Generation: req.Generation,
		Target: "svc-a,svc-b", Actor: "takeover-worker", Valid: true, BaseRevision: st2.Revision(),
	})
	if err != nil {
		rec.add("recovery", "resubmit_error", st2.Revision(), err.Error())
	}
	raw2, _ := os.ReadFile(logPath)
	onDiskAfterRecovery := countLines(raw2)

	res := ScenarioResult{Name: "lost_response", CommitLog: rel(runDir, logPath)}
	res.Events = rec.list()
	res.Assertions = append(res.Assertions,
		rec.mark("commit_durable_before_ack", "1", itoa(onDiskAfterCrash)),
		rec.mark("acknowledgement_lost", "true", boolStr(errors.Is(gotErr, errResponseLost))),
		rec.mark("resubmit_is_duplicate", "true", boolStr(out2.Duplicate)),
		rec.mark("resubmit_returns_same_rev", itoa64(lostRev), itoa64(out2.Revision)),
		rec.mark("no_double_append", itoa(onDiskAfterCrash), itoa(onDiskAfterRecovery)),
		rec.mark("store_revision_unchanged", "1", itoa(int(st2.Revision()))),
	)
	res.Pass = allPass(res.Assertions)
	res.FinalRev = st2.Revision()
	res.RecordCounts = countAll(st2.Records())
	return res, nil
}

// -- Scenario 3: old-generation sign-off after recovery --------------------

// OldGenerationAfterRecovery demonstrates that after a restart and generation
// advance, a takeover carrying sign-offs from the previous authorization
// generation is rejected even when the signer identities are otherwise valid.
func OldGenerationAfterRecovery(runDir string) (ScenarioResult, error) {
	dir := filepath.Join(runDir, "old_generation_after_recovery")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ScenarioResult{}, err
	}
	logPath := filepath.Join(dir, "commit.log")
	rec := &recorder{}

	// Seed the log with the prior generation's accepted takeover, then "crash".
	st0, err := store.Open(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	if _, err := st0.Append(store.Record{
		Type: store.RecTakeover, RequestKey: "rk-gen7", Generation: 7,
		Target: "svc-a,svc-b", Actor: "takeover-worker", Valid: true, BaseRevision: 0,
	}); err != nil {
		return ScenarioResult{}, err
	}
	st0.Close()
	rec.add("before-restart", "committed_gen7", 1, "prior rotation accepted")

	// Recovery: reopen. Authority advances to generation 8.
	st, err := store.Open(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	defer st.Close()
	rec.add("recovery", "reopened", st.Revision(), "generation advanced to 8")

	auth := baseAuthority()
	auth.ExpectedGeneration = map[string]int{"svc-a": 8, "svc-b": 8}

	// The new request is for generation 8 but both sign-offs are generation 7
	// (i.e. they were minted before the rotation, arriving late after recovery).
	req := baseTakeover()
	req.RequestKey = "rk-gen8"
	req.Generation = 8
	req.At = 300
	for i := range req.Credentials {
		req.Credentials[i].Generation = 8
	}
	req.Signoffs = []model.Signoff{
		model.Sign("alice", "rk-gen8", 7, 290), // old-generation sign-offs
		model.Sign("bob", "rk-gen8", 7, 295),
	}
	d := model.Decide(req, auth)
	rec.add("takeover-worker", "evaluate_gen8_with_old_signoffs", st.Revision(), d.Describe())

	// Control: replacing exactly one sign-off with a current-generation sign-off
	// is still insufficient (only one current-gen signer).
	reqMixed := req
	reqMixed.Signoffs = []model.Signoff{
		model.Sign("alice", "rk-gen8", 8, 290), // current
		model.Sign("bob", "rk-gen8", 7, 295),   // old
	}
	dMixed := model.Decide(reqMixed, auth)
	rec.add("takeover-worker", "evaluate_mixed_signoffs", st.Revision(), dMixed.Describe())

	// Control: two current-generation sign-offs are valid.
	reqOK := req
	reqOK.Signoffs = []model.Signoff{
		model.Sign("alice", "rk-gen8", 8, 290),
		model.Sign("bob", "rk-gen8", 8, 295),
	}
	dOK := model.Decide(reqOK, auth)
	rec.add("takeover-worker", "evaluate_current_signoffs", st.Revision(), dOK.Describe())

	res := ScenarioResult{Name: "old_generation_after_recovery", CommitLog: rel(runDir, logPath)}
	res.Events = rec.list()
	res.Assertions = append(res.Assertions,
		rec.mark("old_gen_rejected", "true", boolStr(!d.Valid)),
		rec.mark("old_gen_reports_generation_mismatch", "true", boolStr(hasReason(d, model.ReasonGenerationMismatch))),
		rec.mark("mixed_one_current_still_rejected", "true", boolStr(!dMixed.Valid)),
		rec.mark("mixed_reports_too_few_signers", "true", boolStr(hasReason(dMixed, model.ReasonTooFewSigners))),
		rec.mark("two_current_signoffs_valid", "true", boolStr(dOK.Valid)),
		rec.mark("prior_generation_preserved", "1", itoa(countType(st.Records(), store.RecTakeover))),
	)
	res.Pass = allPass(res.Assertions)
	res.FinalRev = st.Revision()
	res.RecordCounts = countAll(st.Records())
	return res, nil
}

// -- Scenario 4: expired temp authority, same-number replay ---------------

// TempExpiryNoReplay demonstrates that once a temporary substitute authority
// has expired and been tombstoned durably, resubmitting the same authority
// number — even with otherwise-valid sign-offs and current generation — cannot
// revive it. It also shows a naive "number-only" check would wrongly accept it.
func TempExpiryNoReplay(runDir string) (ScenarioResult, error) {
	dir := filepath.Join(runDir, "temp_expiry_no_replay")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ScenarioResult{}, err
	}
	logPath := filepath.Join(dir, "commit.log")
	rec := &recorder{}

	auth := baseAuthority()
	// The takeover borrows T-9 (expires at 500) for svc-b.
	req := baseTakeover()
	req.RequestKey = "rk-temp"
	req.At = 400
	req.Credentials = []model.Credential{
		{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
		{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7, TempAuthID: "T-9"},
	}
	req.Signoffs = []model.Signoff{
		model.Sign("alice", "rk-temp", 7, 350),
		model.Sign("bob", "rk-temp", 7, 360),
	}

	// Before expiry: valid.
	dLive := model.Decide(req, auth)
	rec.add("takeover-worker", "evaluate_before_expiry", 0, dLive.Describe())

	// The reaper tombstones T-9 durably.
	st, err := store.Open(logPath)
	if err != nil {
		return ScenarioResult{}, err
	}
	defer st.Close()
	o, err := st.Append(store.Record{
		Type: store.RecTempExpire, RequestKey: "reap-T-9", Target: "T-9",
		Actor: "reaper", BaseRevision: 0,
	})
	if err != nil {
		return ScenarioResult{}, err
	}
	rec.add("reaper", "tombstoned_T-9", o.Revision, "expired authority marked permanently dead")

	// Reconstruct authority from durable tombstone.
	auth2 := auth
	auth2.TempAuthorities = copyTempMap(auth.TempAuthorities)
	tt := auth2.TempAuthorities["T-9"]
	tt.Tombstone = true
	auth2.TempAuthorities["T-9"] = tt

	// Same-number resubmission at At=400 (before the numeric expiry!), with
	// fresh current-generation sign-offs. The numeric expiry alone would say
	// "still live"; only the tombstone reveals the authority is dead.
	replay := req
	replay.RequestKey = "rk-temp-replay"
	replay.Signoffs = []model.Signoff{
		model.Sign("alice", "rk-temp-replay", 7, 350),
		model.Sign("bob", "rk-temp-replay", 7, 360),
	}
	dReplay := model.Decide(replay, auth2)
	rec.add("takeover-worker", "resubmit_same_number", st.Revision(), dReplay.Describe())

	// A naive check that only compares At against the numeric expiry (ignoring
	// the tombstone) would (wrongly) accept. Show that contrast.
	naiveLive := req.At < auth2.TempAuthorities["T-9"].Expires
	rec.add("control", "naive_numeric_ok", st.Revision(), boolStr(naiveLive)+" (ignores tombstone)")

	label, isReplay := model.TempExpiredLabel(replay.Credentials[1], replay.At, auth2)
	rec.add("control", "classified_as", st.Revision(), label)

	res := ScenarioResult{Name: "temp_expiry_no_replay", CommitLog: rel(runDir, logPath)}
	res.Events = rec.list()
	res.Assertions = append(res.Assertions,
		rec.mark("live_before_expiry_valid", "true", boolStr(dLive.Valid)),
		rec.mark("replay_rejected", "true", boolStr(!dReplay.Valid)),
		rec.mark("replay_reports_expired", "true", boolStr(hasReason(dReplay, model.ReasonTempExpired))),
		rec.mark("naive_numeric_would_accept", "true", boolStr(naiveLive)),
		rec.mark("classified_as_replay", "true", boolStr(isReplay && label == model.ReasonTempReplay)),
		rec.mark("tombstone_durable", "1", itoa(countType(st.Records(), store.RecTempExpire))),
	)
	res.Pass = allPass(res.Assertions)
	res.FinalRev = st.Revision()
	res.RecordCounts = countAll(st.Records())
	return res, nil
}

// -- shared fixtures --------------------------------------------------------

func baseAuthority() model.Authority {
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

func baseTakeover() model.TakeoverRequest {
	return model.TakeoverRequest{
		RequestKey: "rk-takeover-1",
		Generation: 7,
		At:         100,
		Required:   []string{"svc-a", "svc-b"},
		Credentials: []model.Credential{
			{ID: "c1", Authorizer: "auth-x", Services: []string{"svc-a"}, Generation: 7},
			{ID: "c2", Authorizer: "auth-y", Services: []string{"svc-b"}, Generation: 7},
		},
		Signoffs: []model.Signoff{
			model.Sign("alice", "rk-takeover-1", 7, 90),
			model.Sign("bob", "rk-takeover-1", 7, 95),
		},
	}
}

func hasReason(d model.Decision, r string) bool {
	for _, x := range d.Reasons {
		if x == r {
			return true
		}
	}
	return false
}

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyTempMap(m map[string]model.TempState) map[string]model.TempState {
	out := make(map[string]model.TempState, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func rel(base, p string) string {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

func boolStr(b bool) string { return fmt.Sprintf("%t", b) }

func itoa(i int) string { return fmt.Sprintf("%d", i) }

func itoa64(i int64) string { return fmt.Sprintf("%d", i) }

func countType(rs []store.Record, t store.RecordType) int {
	n := 0
	for _, r := range rs {
		if r.Type == t {
			n++
		}
	}
	return n
}

func hasType(rs []store.Record, t store.RecordType) bool { return countType(rs, t) > 0 }

func countAll(rs []store.Record) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[string(r.Type)]++
	}
	return m
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

func allPass(as []Assertion) bool {
	for _, a := range as {
		if !a.Pass {
			return false
		}
	}
	return true
}

// WriteEvidence marshals a scenario result to evidence.json in its directory.
func WriteEvidence(runDir string, res ScenarioResult) error {
	dir := filepath.Join(runDir, res.Name)
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "evidence.json"), append(b, '\n'), 0o644)
}
