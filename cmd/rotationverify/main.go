// Command rotationverify runs and independently verifies the rotation-takeover
// checklist using only the Go standard library and local synthetic inputs.
//
// Usage:
//
//	rotationverify run    [-dir artifacts/run]
//	rotationverify verify [-dir artifacts/run]
//
// `run` executes the fault scenarios, the exhaustive small graph, and the 50k
// reclamation, then writes a self-describing artifact tree. `verify` re-reads
// that tree from disk and recomputes every claim without trusting the run.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"rotationverify/internal/graph"
	"rotationverify/internal/reclaim"
	"rotationverify/internal/run"
	"rotationverify/internal/verify"
)

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

// dispatch is the testable entrypoint: it returns an exit code instead of
// calling os.Exit, so tests can drive each subcommand in-process.
func dispatch(args []string) int {
	if len(args) < 1 {
		usage()
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", defaultDir(cmd), "artifact directory")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	switch cmd {
	case "run":
		man, err := run.Run(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "run failed:", err)
			return 1
		}
		printRunSummary(*dir, man)
		return 0
	case "verify":
		rep, err := verify.Verify(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify failed:", err)
			return 1
		}
		printVerifyReport(*dir, rep)
		if !rep.Pass {
			return 1
		}
		return 0
	case "summary":
		printArtifactSummary(*dir)
		return 0
	default:
		usage()
		return 2
	}
}

func defaultDir(cmd string) string {
	switch cmd {
	case "run":
		return "artifacts/run"
	case "verify":
		return "artifacts/run"
	default:
		return "artifacts/run"
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `rotationverify — rotation-takeover checklist verifier

  rotationverify run    [-dir artifacts/run]   run scenarios + graph + 50k reclaim
  rotationverify verify [-dir artifacts/run]   re-check artifacts from disk
  rotationverify summary [-dir artifacts/run]  print artifact highlights`)
}

func printRunSummary(dir string, man run.Manifest) {
	fmt.Printf("RUN complete: artifacts in %s\n", dir)
	fmt.Printf("  generated_at: %s\n", man.GeneratedAt)
	for _, c := range man.Checks {
		fmt.Printf("  [%s] %s (expected=%s actual=%s)\n", status(c.Pass), c.Name, c.Expected, c.Actual)
	}

	// Pull a few headline numbers directly from the written artifacts.
	var g graph.Result
	if b, err := os.ReadFile(dir + "/graph/enumeration.json"); err == nil {
		json.Unmarshal(b, &g)
		fmt.Printf("\nGRAPH: %d enumerated cases, %d valid, Decide==Reference=%t\n",
			g.NumCases, g.ValidCount, g.Agree)
		w := g.MinimalWitness
		fmt.Printf("  minimal witness: signers=%v creds=%v services=%v @t=%d gen=%d minimal=%t\n",
			w.Signers, w.Credentials, w.Services, w.At, w.Generation, w.Minimal)
		fmt.Printf("  first invalidation watermark: t=%d trigger=%s reasons=%v\n",
			g.Watermark.FirstInvalidAt, g.Watermark.Trigger, g.Watermark.FirstInvalidReason)
	}

	var rs reclaim.Summary
	if b, err := os.ReadFile(dir + "/reclaim/summary.json"); err == nil {
		json.Unmarshal(b, &rs)
		c := rs.Comparison
		fmt.Printf("\nRECLAIM: %d credentials, %d partitions\n",
			c.TotalCredentials, c.TotalPartitions)
		fmt.Printf("  full scan:  reclaimed=%d %v\n", rs.Full.ReclaimedCount, rs.Full.PerReason)
		fmt.Printf("  local pass: reclaimed=%d touched=%d/%d partitions (%d untouched)\n",
			rs.Local.ReclaimedCount, c.PartitionsTouched, c.TotalPartitions, c.UntouchedPartitions)
		fmt.Printf("  cross-check: compared=%d item-by-item, mismatches=%d, equal=%t, digest_equal=%t\n",
			c.ComparedCreds, len(c.Mismatches), c.Equal, c.DigestEqual)
		fmt.Printf("  cross-partition hazard: widest revoked authorizer spans %d partitions\n",
			rs.IndexStats.MaxPartitionsPerRevokedAuth)
	}
}

func printVerifyReport(dir string, rep verify.Report) {
	fmt.Printf("VERIFY %s: %s\n", dir, passFail(rep.Pass))
	for _, c := range rep.Checks {
		fmt.Printf("  [%s] %s — %s\n", status(c.Pass), c.Name, c.Detail)
	}
}

// printArtifactSummary reads the fault evidence and prints assertions.
func printArtifactSummary(dir string) {
	fmt.Println("artifact summary (from disk):")
	for _, name := range []string{"revocation_wins", "lost_response", "old_generation_after_recovery", "temp_expiry_no_replay"} {
		b, err := os.ReadFile(fmt.Sprintf("%s/faults/%s/evidence.json", dir, name))
		if err != nil {
			fmt.Printf("  %s: missing (%v)\n", name, err)
			continue
		}
		var raw map[string]any
		json.Unmarshal(b, &raw)
		fmt.Printf("  %s: pass=%v assertions=%d\n", name, raw["pass"], len(raw["assertions"].([]any)))
	}
}

func status(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func passFail(p bool) string {
	if p {
		return "PASS"
	}
	return "FAIL"
}
