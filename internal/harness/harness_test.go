package harness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAllScenarios(t *testing.T) {
	dir := t.TempDir()

	r1, err := RevocationWins(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Pass {
		t.Fatalf("revocation_wins failed: %+v", r1.Assertions)
	}

	r2, err := LostResponse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Pass {
		t.Fatalf("lost_response failed: %+v", r2.Assertions)
	}

	r3, err := OldGenerationAfterRecovery(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r3.Pass {
		t.Fatalf("old_generation failed: %+v", r3.Assertions)
	}

	r4, err := TempExpiryNoReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !r4.Pass {
		t.Fatalf("temp_expiry_no_replay failed: %+v", r4.Assertions)
	}

	// Evidence must be written and re-readable.
	for _, r := range []ScenarioResult{r1, r2, r3, r4} {
		if err := WriteEvidence(dir, r); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, r.Name, "evidence.json"))
		if err != nil {
			t.Fatal(err)
		}
		var back ScenarioResult
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Name != r.Name || !back.Pass {
			t.Fatalf("evidence roundtrip mismatch: %+v", back)
		}
	}
}

// TestBarrierReleasesTogether sanity-checks the cyclic barrier.
func TestBarrierReleasesTogether(t *testing.T) {
	const n = 4
	b := NewBarrier(n)
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			b.Wait()
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	// Second generation.
	for i := 0; i < n; i++ {
		go func() {
			b.Wait()
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
}
