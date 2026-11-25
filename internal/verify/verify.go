// Package verify independently re-checks a run directory from disk.
//
// It deliberately does not import the harness/run result structs' PASS flags
// as truth. It re-opens each commit log through the store (which re-verifies
// record checksums and ordering), recomputes the decision for the minimal
// witness, recomputes the watermark, and rebuilds the reclamation dataset and
// comparison from parameters. Any disagreement with the recorded artifacts is
// reported as a failure.
package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"rotationverify/internal/graph"
	"rotationverify/internal/harness"
	"rotationverify/internal/model"
	"rotationverify/internal/reclaim"
	"rotationverify/internal/run"
	"rotationverify/internal/store"
)

// Check is one verifier assertion.
type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Report is the verifier output.
type Report struct {
	Checks []Check `json:"checks"`
	Pass   bool    `json:"pass"`
}

// Verify re-checks the run at dir.
func Verify(dir string) (Report, error) {
	var rep Report
	var man run.Manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &man); err != nil {
		return rep, fmt.Errorf("read manifest: %w", err)
	}

	// 1. Fault commit logs: re-open through the store, which re-validates every
	//    record's checksum and revision ordering. Confirm revision counts and
	//    record types match the recorded evidence.
	for _, fp := range man.Faults {
		sceneDir := filepath.Join(dir, filepath.FromSlash(fp.Dir))
		var ev harness.ScenarioResult
		if err := readJSON(filepath.Join(sceneDir, fp.Evidence), &ev); err != nil {
			return rep, fmt.Errorf("%s: read evidence: %w", fp.Name, err)
		}
		st, err := store.Open(filepath.Join(sceneDir, fp.CommitLog))
		if err != nil {
			return rep, fmt.Errorf("%s: reopen commit log: %w", fp.Name, err)
		}
		recs := st.Records()
		finalRev := st.Revision()
		st.Close()

		rep.add(fp.Name+":commit_log_replays", finalRev == ev.FinalRev,
			fmt.Sprintf("on-disk final rev %d vs evidence %d", finalRev, ev.FinalRev))
		rep.add(fp.Name+":record_counts_match", sameCounts(countAll(recs), ev.RecordCounts),
			fmt.Sprintf("disk %v evidence %v", countAll(recs), ev.RecordCounts))
		// All records must be contiguous revisions 1..N with matching checksums
		// (checksums are re-verified inside store.replay).
		rep.add(fp.Name+":revisions_contiguous", contiguous(recs),
			fmt.Sprintf("revs %v", revisions(recs)))
	}

	// 2. Graph: recompute the enumeration from scratch and compare verdicts by
	//    re-deciding the recorded witness and re-running the watermark.
	var g graph.Result
	if err := readJSON(filepath.Join(dir, filepath.FromSlash(man.GraphPath)), &g); err != nil {
		return rep, fmt.Errorf("read graph: %w", err)
	}
	if g.MinimalWitness.Found {
		d := model.Decide(g.MinimalWitness.Request, g.MinimalWitness.Auth)
		rep.add("graph:witness_redecides_valid", d.Valid, d.Describe())
		// Re-prove minimality independently.
		minOK := true
		for i := range g.MinimalWitness.Request.Signoffs {
			r := cloneReq(g.MinimalWitness.Request)
			r.Signoffs = append(r.Signoffs[:i:i], r.Signoffs[i+1:]...)
			if model.Decide(r, g.MinimalWitness.Auth).Valid {
				minOK = false
			}
		}
		for i := range g.MinimalWitness.Request.Credentials {
			r := cloneReq(g.MinimalWitness.Request)
			r.Credentials = append(r.Credentials[:i:i], r.Credentials[i+1:]...)
			if model.Decide(r, g.MinimalWitness.Auth).Valid {
				minOK = false
			}
		}
		rep.add("graph:witness_reductions_invalid", minOK, "removing any element must invalidate")
	}
	// Recompute the whole enumeration and confirm Decide==Reference holds and
	// the watermark is unchanged.
	fresh := graph.Enumerate()
	rep.add("graph:enumeration_agrees", fresh.Agree && fresh.NumCases == g.NumCases,
		fmt.Sprintf("fresh agree=%t cases=%d recorded cases=%d", fresh.Agree, fresh.NumCases, g.NumCases))
	rep.add("graph:watermark_reproduced", fresh.Watermark.FirstInvalidAt == g.Watermark.FirstInvalidAt,
		fmt.Sprintf("fresh %d recorded %d", fresh.Watermark.FirstInvalidAt, g.Watermark.FirstInvalidAt))
	// Independently re-walk the recorded timeline and confirm the first
	// valid->invalid transition lands where claimed.
	rep.add("graph:watermark_matches_timeline", watermarkConsistent(g.Watermark),
		fmt.Sprintf("first_invalid_at=%d", g.Watermark.FirstInvalidAt))

	// 3. Reclaim: rebuild dataset from params and recompute both modes + compare.
	var sum reclaim.Summary
	if err := readJSON(filepath.Join(dir, filepath.FromSlash(man.ReclaimPath)), &sum); err != nil {
		return rep, fmt.Errorf("read reclaim: %w", err)
	}
	freshSum := reclaim.Run(sum.Params)
	rep.add("reclaim:full_digest_reproduced", freshSum.Full.Digest == sum.Full.Digest,
		"full-scan reclaim set identical")
	rep.add("reclaim:local_digest_reproduced", freshSum.Local.Digest == sum.Local.Digest,
		"local reclaim set identical")
	rep.add("reclaim:comparison_equal", freshSum.Comparison.Equal && freshSum.Comparison.DigestEqual,
		fmt.Sprintf("mismatches=%d", len(freshSum.Comparison.Mismatches)))
	rep.add("reclaim:all_compared_item_by_item", freshSum.Comparison.ComparedCreds == sum.Params.Tenants*sum.Params.CredsPerTenant,
		fmt.Sprintf("compared %d", freshSum.Comparison.ComparedCreds))
	rep.add("reclaim:local_partial_but_equivalent",
		freshSum.Comparison.LocalIsPartial && freshSum.Comparison.Equal,
		fmt.Sprintf("touched %d/%d partitions", freshSum.Comparison.PartitionsTouched, freshSum.Comparison.TotalPartitions))

	rep.Pass = true
	for _, c := range rep.Checks {
		if !c.Pass {
			rep.Pass = false
		}
	}
	return rep, nil
}

func (r *Report) add(name string, pass bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Pass: pass, Detail: detail})
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func countAll(rs []store.Record) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[string(r.Type)]++
	}
	return m
}

func sameCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func revisions(rs []store.Record) []int64 {
	out := make([]int64, len(rs))
	for i, r := range rs {
		out[i] = r.Revision
	}
	return out
}

func contiguous(rs []store.Record) bool {
	for i, r := range rs {
		if r.Revision != int64(i+1) {
			return false
		}
	}
	return true
}

func watermarkConsistent(w graph.Watermark) bool {
	found := false
	prevValid := false
	var firstAt int64 = -1
	for i, p := range w.Timeline {
		if i == 0 {
			prevValid = p.Valid
			continue
		}
		if !found && prevValid && !p.Valid {
			found = true
			firstAt = p.At
		}
		prevValid = p.Valid
	}
	if w.FirstInvalidAt == -1 {
		return !found
	}
	return found && firstAt == w.FirstInvalidAt
}

func cloneReq(r model.TakeoverRequest) model.TakeoverRequest {
	out := r
	out.Required = append([]string(nil), r.Required...)
	out.Credentials = append([]model.Credential(nil), r.Credentials...)
	out.Signoffs = append([]model.Signoff(nil), r.Signoffs...)
	return out
}
