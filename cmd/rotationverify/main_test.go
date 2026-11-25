package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunThenVerifyCLITree drives the CLI subcommands end-to-end in-process:
// run writes the artifact tree, verify independently re-checks it from disk,
// and summary reads it back.
func TestRunThenVerifyCLITree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")

	if code := dispatch([]string{"run", "-dir", dir}); code != 0 {
		t.Fatalf("run exit=%d", code)
	}
	if code := dispatch([]string{"verify", "-dir", dir}); code != 0 {
		t.Fatalf("verify exit=%d (should independently pass)", code)
	}
	if code := dispatch([]string{"summary", "-dir", dir}); code != 0 {
		t.Fatalf("summary exit=%d", code)
	}

	// Verify must fail if artifacts are missing.
	if code := dispatch([]string{"verify", "-dir", filepath.Join(dir, "nope")}); code == 0 {
		t.Fatal("verify on missing dir should fail")
	}
	// Bad/absent subcommand.
	if code := dispatch(nil); code != 2 {
		t.Fatalf("no-arg exit=%d want 2", code)
	}
	if code := dispatch([]string{"bogus"}); code != 2 {
		t.Fatalf("bogus exit=%d want 2", code)
	}
}

// TestVerifyDetectsTamperViaCLI confirms the verify subcommand returns non-zero
// on a tampered commit log rather than trusting the manifest.
func TestVerifyDetectsTamperViaCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if code := dispatch([]string{"run", "-dir", dir}); code != 0 {
		t.Fatalf("run exit=%d", code)
	}
	logPath := filepath.Join(dir, "faults", "lost_response", "commit.log")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the `target` VALUE ("svc-a,svc-b" -> "svc-X,svc-b").
	// Flipping a JSON key byte would not change semantics (encoding/json keys
	// are case-insensitive), so tamper the payload value the checksum binds.
	needle := []byte("svc-a")
	idx := indexOf(b, needle)
	if idx < 0 {
		t.Fatal("target value not found to tamper")
	}
	b[idx+4] = 'X' // 'a' -> 'X'
	os.WriteFile(logPath, b, 0o600)
	if code := dispatch([]string{"verify", "-dir", dir}); code == 0 {
		t.Fatal("verify should exit non-zero on tampered log")
	}
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
