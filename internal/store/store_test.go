package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func tmpPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "commit.log")
}

func takeoverRec(key, target string, valid bool, base int64) Record {
	return Record{Type: RecTakeover, RequestKey: key, Generation: 7, Target: target, Actor: "takeover-worker", Valid: valid, BaseRevision: base}
}

func TestAppendAndReplay(t *testing.T) {
	p := tmpPath(t)
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(takeoverRec("rk-1", "svc-a,svc-b", true, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Record{Type: RecRevocation, RequestKey: "rv-1", Target: "auth-y", Actor: "revoke-worker", BaseRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if got := s.Revision(); got != 2 {
		t.Fatalf("revision=%d want 2", got)
	}
	s.Close()

	// Reopen and confirm state rebuilt purely from disk.
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.Revision(); got != 2 {
		t.Fatalf("replayed revision=%d want 2", got)
	}
	if !s2.IsRevoked("auth-y") {
		t.Fatal("revocation not replayed")
	}
	if o, ok := s2.Lookup("rk-1"); !ok || !o.Accepted {
		t.Fatalf("takeover outcome not replayed: %+v ok=%v", o, ok)
	}
}

func TestIdempotentReplay(t *testing.T) {
	p := tmpPath(t)
	s, _ := Open(p)
	defer s.Close()
	first, err := s.Append(takeoverRec("rk-1", "svc-a", true, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Same request key resubmitted (response was "lost"): must return original,
	// must NOT append, duplicate flag set.
	second, err := s.Append(takeoverRec("rk-1", "svc-a", true, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate {
		t.Fatal("expected duplicate outcome")
	}
	if second.Revision != first.Revision {
		t.Fatalf("duplicate rev=%d want %d", second.Revision, first.Revision)
	}
	if s.Revision() != 1 {
		t.Fatalf("duplicate append mutated revision: %d", s.Revision())
	}
}

func TestStaleRevisionRejected(t *testing.T) {
	p := tmpPath(t)
	s, _ := Open(p)
	defer s.Close()
	if _, err := s.Append(takeoverRec("rk-1", "svc-a", true, 0)); err != nil {
		t.Fatal(err)
	}
	// Both workers believed base=0; the second to commit is stale.
	_, err := s.Append(Record{Type: RecRevocation, RequestKey: "rv-2", Target: "auth-x", Actor: "revoke", BaseRevision: 0})
	if err == nil {
		t.Fatal("expected stale revision error")
	}
}

func TestTornTailRecovery(t *testing.T) {
	p := tmpPath(t)
	s, _ := Open(p)
	if _, err := s.Append(takeoverRec("rk-1", "svc-a", true, 0)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Simulate a torn append: a partial JSON fragment with no trailing newline.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"revision":2,"type":"revoc`)
	f.Close()

	s2, err := Open(p)
	if err != nil {
		t.Fatalf("reopen after torn tail failed: %v", err)
	}
	defer s2.Close()
	if s2.Revision() != 1 {
		t.Fatalf("torn tail should be truncated, revision=%d want 1", s2.Revision())
	}
	// Must be able to append cleanly after recovery.
	if _, err := s2.Append(Record{Type: RecRevocation, RequestKey: "rv-3", Target: "auth-z", BaseRevision: 1}); err != nil {
		t.Fatalf("append after torn-tail recovery: %v", err)
	}
}

func TestChecksumTamperDetected(t *testing.T) {
	p := tmpPath(t)
	s, _ := Open(p)
	s.Append(takeoverRec("rk-1", "svc-a", true, 0))
	s.Close()

	// Flip a byte in the payload region (the target string).
	data, _ := os.ReadFile(p)
	for i := range data {
		if data[i] == 's' { // first byte of "svc-a"
			data[i] = 'X'
			break
		}
	}
	os.WriteFile(p, data, 0o600)

	s2, err := Open(p)
	if err == nil {
		s2.Close()
		t.Fatal("tampered record should fail checksum on replay")
	}
}

// TestConcurrentAppendSerializes stresses the single-writer lock: many workers
// append distinct keys with the correct current base revision. Exactly one
// record per key must land, revisions must be unique and contiguous, and the
// replayed log must match. (Run with -race where a C toolchain is available.)
func TestConcurrentAppendSerializes(t *testing.T) {
	p := tmpPath(t)
	s, _ := Open(p)
	defer s.Close()

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := map[int64]string{}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for attempt := 0; attempt < 1000; attempt++ {
				base := s.Revision() // read current, then try to commit at it
				o, err := s.Append(Record{
					Type: RecRevocation, RequestKey: fmt.Sprintf("rv-%d", i),
					Target: fmt.Sprintf("auth-%d", i), Actor: "w", BaseRevision: base,
				})
				if err == nil {
					mu.Lock()
					accepted[o.Revision] = o.RequestKey
					mu.Unlock()
					return
				}
				// stale revision: retry with a fresh base
			}
			t.Errorf("worker %d never committed", i)
		}(i)
	}
	wg.Wait()

	if got := len(s.Records()); got != workers {
		t.Fatalf("records=%d want %d", got, workers)
	}
	// Unique, contiguous 1..N revisions.
	seen := map[int64]bool{}
	for _, r := range s.Records() {
		if seen[r.Revision] {
			t.Fatalf("duplicate revision %d", r.Revision)
		}
		seen[r.Revision] = true
	}
	for rev := int64(1); rev <= workers; rev++ {
		if !seen[rev] {
			t.Fatalf("missing revision %d", rev)
		}
	}
	// Replay from disk agrees.
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := len(s2.Records()); got != workers {
		t.Fatalf("replayed records=%d want %d", got, workers)
	}
}
