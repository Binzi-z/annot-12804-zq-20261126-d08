package run_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rotationverify/internal/graph"
	"rotationverify/internal/reclaim"
	"rotationverify/internal/run"
	"rotationverify/internal/verify"
)

// TestEmitHeadlineNumbers runs the full pipeline into the stable
// artifacts/run directory (so the tree is independently verifiable on disk)
// and writes headline numbers to artifacts/headline_numbers.txt.
func TestEmitHeadlineNumbers(t *testing.T) {
	dir := filepath.Join("..", "..", "artifacts", "run")
	os.RemoveAll(dir)
	man, err := run.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range man.Checks {
		if !c.Pass {
			t.Fatalf("runner check failed: %s", c.Name)
		}
	}
	var g graph.Result
	b, _ := os.ReadFile(filepath.Join(dir, "graph", "enumeration.json"))
	json.Unmarshal(b, &g)

	var rs reclaim.Summary
	b, _ = os.ReadFile(filepath.Join(dir, "reclaim", "summary.json"))
	json.Unmarshal(b, &rs)
	c := rs.Comparison

	var sb strings.Builder
	fmt.Fprintf(&sb, "GRAPH cases=%d valid=%d agree=%t\n", g.NumCases, g.ValidCount, g.Agree)
	fmt.Fprintf(&sb, "  witness signers=%v creds=%v services=%v minimal=%t\n",
		g.MinimalWitness.Signers, g.MinimalWitness.Credentials, g.MinimalWitness.Services, g.MinimalWitness.Minimal)
	fmt.Fprintf(&sb, "  watermark first_invalid_at=%d trigger=%s reason=%v\n",
		g.Watermark.FirstInvalidAt, g.Watermark.Trigger, g.Watermark.FirstInvalidReason)
	fmt.Fprintf(&sb, "RECLAIM total=%d partitions=%d\n", c.TotalCredentials, c.TotalPartitions)
	fmt.Fprintf(&sb, "  full reclaimed=%d %v\n", rs.Full.ReclaimedCount, rs.Full.PerReason)
	fmt.Fprintf(&sb, "  local reclaimed=%d touched=%d/%d untouched=%d\n",
		rs.Local.ReclaimedCount, c.PartitionsTouched, c.TotalPartitions, c.UntouchedPartitions)
	fmt.Fprintf(&sb, "  compared=%d mismatches=%d equal=%t digest_equal=%t\n",
		c.ComparedCreds, len(c.Mismatches), c.Equal, c.DigestEqual)
	fmt.Fprintf(&sb, "  widest revoked auth spans=%d expired_temps=%d revoked_auths=%d\n",
		rs.IndexStats.MaxPartitionsPerRevokedAuth, rs.IndexStats.ExpiredTemps, rs.IndexStats.RevokedAuthorizers)
	fmt.Fprintf(&sb, "  full_digest=%s\n  local_digest=%s\n", rs.Full.Digest, rs.Local.Digest)

	out := filepath.Join("..", "..", "artifacts", "headline_numbers.txt")
	os.MkdirAll(filepath.Dir(out), 0o755)

	// Independently verify the stable tree we just wrote.
	rep, err := verify.Verify(dir)
	if err != nil {
		t.Fatalf("verify stable tree: %v", err)
	}
	if !rep.Pass {
		for _, ch := range rep.Checks {
			if !ch.Pass {
				t.Fatalf("verifier rejected stable tree: %s — %s", ch.Name, ch.Detail)
			}
		}
	}
	fmt.Fprintf(&sb, "VERIFY stable_tree=%s checks=%d\n",
		map[bool]string{true: "PASS", false: "FAIL"}[rep.Pass], len(rep.Checks))

	if err := os.WriteFile(out, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log(sb.String())
}
