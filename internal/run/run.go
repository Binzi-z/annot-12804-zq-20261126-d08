// Package run orchestrates a full verification pass and writes a self-describing
// artifact tree that an independent verifier can re-check from disk alone.
//
// Layout under the run directory:
//
//	manifest.json                         summary + pointers (written last)
//	faults/<scenario>/commit.log          durable commit logs (authoritative)
//	faults/<scenario>/evidence.json       per-scenario trace + assertions
//	graph/enumeration.json                full truth table + witness + watermark
//	reclaim/summary.json                  full vs local results + comparison
//
// The verifier re-derives every claim from these files and re-runs the pure
// decision logic; it never trusts a PASS flag baked into a manifest.
package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"rotationverify/internal/graph"
	"rotationverify/internal/harness"
	"rotationverify/internal/reclaim"
)

// Manifest is the top-level index. It records only what the verifier needs to
// locate artifacts and recompute; verdicts are recomputed, not trusted.
type Manifest struct {
	GeneratedAt string         `json:"generated_at"`
	Root        string         `json:"root"`
	Faults      []FaultPointer `json:"faults"`
	GraphPath   string         `json:"graph_path"`
	ReclaimPath string         `json:"reclaim_path"`
	// Checks is the runner's own self-assessment (the verifier recomputes).
	Checks []harness.Assertion `json:"runner_checks"`
}

// FaultPointer locates one fault scenario's artifacts. CommitLog and Evidence
// are relative to Dir.
type FaultPointer struct {
	Name      string `json:"name"`
	Dir       string `json:"dir"`
	CommitLog string `json:"commit_log"`
	Evidence  string `json:"evidence"`
}

// Run executes everything, writes artifacts under dir, and returns the manifest.
func Run(dir string) (Manifest, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, err
	}
	faultsDir := filepath.Join(dir, "faults")
	if err := os.MkdirAll(faultsDir, 0o755); err != nil {
		return Manifest{}, err
	}

	man := Manifest{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Root: dir}

	scenarios := []struct {
		name string
		fn   func(string) (harness.ScenarioResult, error)
	}{
		{"revocation_wins", harness.RevocationWins},
		{"lost_response", harness.LostResponse},
		{"old_generation_after_recovery", harness.OldGenerationAfterRecovery},
		{"temp_expiry_no_replay", harness.TempExpiryNoReplay},
	}

	for _, sc := range scenarios {
		res, err := sc.fn(faultsDir)
		if err != nil {
			return man, fmt.Errorf("scenario %s: %w", sc.name, err)
		}
		if err := harness.WriteEvidence(faultsDir, res); err != nil {
			return man, err
		}
		man.Checks = append(man.Checks, harness.Assertion{
			Name: "scenario:" + sc.name, Expected: "pass", Actual: passStr(res.Pass), Pass: res.Pass,
		})
		man.Faults = append(man.Faults, FaultPointer{
			Name:      sc.name,
			Dir:       filepath.ToSlash(filepath.Join("faults", sc.name)),
			CommitLog: "commit.log",
			Evidence:  "evidence.json",
		})
	}

	// Exhaustive small graph.
	g := graph.Enumerate()
	gdir := filepath.Join(dir, "graph")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		return man, err
	}
	if err := writeJSON(filepath.Join(gdir, "enumeration.json"), g); err != nil {
		return man, err
	}
	man.GraphPath = "graph/enumeration.json"
	man.Checks = append(man.Checks,
		harness.Assertion{Name: "graph:decide_matches_reference", Expected: "true", Actual: fmt.Sprintf("%t", g.Agree), Pass: g.Agree},
		harness.Assertion{Name: "graph:witness_minimal", Expected: "true", Actual: fmt.Sprintf("%t", g.MinimalWitness.Minimal), Pass: g.MinimalWitness.Minimal},
		harness.Assertion{Name: "graph:first_invalid_at", Expected: "500", Actual: fmt.Sprintf("%d", g.Watermark.FirstInvalidAt), Pass: g.Watermark.FirstInvalidAt == 500},
	)

	// 50k reclamation.
	rs := reclaim.Run(reclaim.DefaultParams())
	rdir := filepath.Join(dir, "reclaim")
	if err := os.MkdirAll(rdir, 0o755); err != nil {
		return man, err
	}
	if err := writeJSON(filepath.Join(rdir, "summary.json"), rs); err != nil {
		return man, err
	}
	man.ReclaimPath = "reclaim/summary.json"
	man.Checks = append(man.Checks,
		harness.Assertion{Name: "reclaim:all_50k_compared", Expected: "50000", Actual: fmt.Sprintf("%d", rs.Comparison.ComparedCreds), Pass: rs.Comparison.ComparedCreds == 50000},
		harness.Assertion{Name: "reclaim:local_equals_full", Expected: "true", Actual: fmt.Sprintf("%t", rs.Comparison.Equal && rs.Comparison.DigestEqual), Pass: rs.Comparison.Equal && rs.Comparison.DigestEqual},
		harness.Assertion{Name: "reclaim:local_is_partial", Expected: "true", Actual: fmt.Sprintf("%t", rs.Comparison.LocalIsPartial), Pass: rs.Comparison.LocalIsPartial},
	)

	if err := writeJSON(filepath.Join(dir, "manifest.json"), man); err != nil {
		return man, err
	}
	return man, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func passStr(b bool) string {
	if b {
		return "pass"
	}
	return "fail"
}
