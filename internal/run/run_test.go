package run_test

import (
	"os"
	"path/filepath"
	"testing"

	"rotationverify/internal/run"
	"rotationverify/internal/verify"
)

// TestRunThenVerifyIndependent drives the full pipeline and then re-verifies
// every claim from disk. If the verifier ever trusted a run-time PASS flag
// instead of recomputing, a tamper test below would catch it.
func TestRunThenVerifyIndependent(t *testing.T) {
	dir := t.TempDir()
	man, err := run.Run(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The runner's own checks must all pass.
	for _, c := range man.Checks {
		if !c.Pass {
			t.Fatalf("runner check failed: %s (expected %s actual %s)", c.Name, c.Expected, c.Actual)
		}
	}
	rep, err := verify.Verify(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, c := range rep.Checks {
		if !c.Pass {
			t.Fatalf("verifier check failed: %s — %s", c.Name, c.Detail)
		}
	}
	if !rep.Pass {
		t.Fatalf("verify report not passing: %+v", rep.Checks)
	}
}

// TestVerifierCatchesTamperedCommitLog proves the verifier re-reads and
// re-validates the commit log: flipping a byte in the durable log must make
// verification fail (checksum rejection), not silently pass.
func TestVerifierCatchesTamperedCommitLog(t *testing.T) {
	dir := t.TempDir()
	if _, err := run.Run(dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Sanity: verifies clean first.
	if rep, err := verify.Verify(dir); err != nil || !rep.Pass {
		t.Fatalf("clean verify should pass: err=%v", err)
	}
	// Tamper: flip a byte inside the revocation-wins commit log payload.
	logPath := filepath.Join(dir, "faults", "revocation_wins", "commit.log")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := false
	for i := range b {
		if b[i] == 'a' { // inside "auth-y" target
			b[i] = 'A'
			tampered = true
			break
		}
	}
	if !tampered {
		t.Fatal("could not find byte to tamper")
	}
	os.WriteFile(logPath, b, 0o600)
	if _, err := verify.Verify(dir); err == nil {
		t.Fatal("verifier accepted a tampered commit log")
	}
}

// TestVerifierCatchesTamperedReclaim proves the reclaim check recomputes from
// params rather than trusting the recorded digest.
func TestVerifierCatchesTamperedReclaim(t *testing.T) {
	dir := t.TempDir()
	if _, err := run.Run(dir); err != nil {
		t.Fatalf("run: %v", err)
	}
	p := filepath.Join(dir, "reclaim", "summary.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the recorded full digest string in place.
	const field = `"digest": "`
	idx := indexOf(b, []byte(field))
	if idx < 0 {
		t.Fatal("digest field not found")
	}
	start := idx + len(field)
	b[start] = 'x'
	os.WriteFile(p, b, 0o600)

	rep, err := verify.Verify(dir)
	if err != nil {
		// A parse error is also an acceptable rejection.
		return
	}
	if rep.Pass {
		t.Fatal("verifier accepted a tampered reclaim digest")
	}
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
