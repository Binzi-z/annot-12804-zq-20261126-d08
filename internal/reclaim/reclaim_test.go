package reclaim

import "testing"

func TestDefaultScale(t *testing.T) {
	p := DefaultParams()
	if p.Tenants*p.CredsPerTenant != 50000 {
		t.Fatalf("expected 50,000 credentials, got %d", p.Tenants*p.CredsPerTenant)
	}
	s := Run(p)
	if s.Comparison.TotalCredentials != 50000 {
		t.Fatalf("total creds = %d", s.Comparison.TotalCredentials)
	}
	if s.Comparison.ComparedCreds != 50000 {
		t.Fatalf("compared = %d, want item-by-item across all 50,000", s.Comparison.ComparedCreds)
	}
	if !s.Comparison.Equal || !s.Comparison.DigestEqual {
		t.Fatalf("local != full: %d mismatches", len(s.Comparison.Mismatches))
	}
	if s.Full.ReclaimedCount == 0 {
		t.Fatal("expected some reclamation")
	}
	if s.Full.ReclaimedCount != s.Local.ReclaimedCount {
		t.Fatalf("count mismatch full=%d local=%d", s.Full.ReclaimedCount, s.Local.ReclaimedCount)
	}
	if !s.Comparison.LocalIsPartial {
		t.Fatalf("local touched all %d partitions; optimization skipped nothing", s.Comparison.PartitionsTouched)
	}
	// The cross-partition hazard must be real: one revoked authorizer spans
	// multiple partitions, else "local" would be trivially a single partition.
	if s.IndexStats.MaxPartitionsPerRevokedAuth <= 1 {
		t.Fatalf("cross-partition fan-out not exercised: max=%d", s.IndexStats.MaxPartitionsPerRevokedAuth)
	}
}

func TestDeterministic(t *testing.T) {
	p := DefaultParams()
	a := Run(p)
	b := Run(p)
	if a.Full.Digest != b.Full.Digest || a.Local.Digest != b.Local.Digest {
		t.Fatal("non-deterministic dataset or result")
	}
	if a.Full.ReclaimedCount != b.Full.ReclaimedCount {
		t.Fatal("non-deterministic count")
	}
}

func TestRevokedAuthSpansPartitions(t *testing.T) {
	ds := Generate(DefaultParams())
	idx := ds.BuildIndex()
	// At least one revoked global must span many partitions (cross-partition
	// hazard). Find the widest.
	best := 0
	for a, rev := range ds.RevokedAuth {
		if rev && len(idx.ByAuthorizer[a]) > best {
			best = len(idx.ByAuthorizer[a])
		}
	}
	if best < 50 {
		t.Fatalf("widest revoked authorizer spans only %d partitions", best)
	}
}

// TestLocalMissesWithoutIndex proves the comparison is meaningful: a local pass
// restricted to a single partition under-reclaims, and Compare detects it.
func TestLocalMissesWithoutIndex(t *testing.T) {
	ds := Generate(DefaultParams())
	full := ds.Full()
	// Fake a "local" run that only looked at partition 0.
	fake := Result{Reclaimed: map[string]ReclaimReason{}, PerReason: map[string]int{}, PartitionsTouched: 1}
	for _, c := range ds.Credentials {
		if c.Tenant != 0 {
			continue
		}
		if r := ds.reasonFor(c); r != Keep {
			fake.Reclaimed[c.ID] = r
		}
	}
	fake.ReclaimedCount = len(fake.Reclaimed)
	fake.Digest = digestOf(fake.Reclaimed)
	cmp := Compare(&ds, fake, full)
	if cmp.Equal {
		t.Fatal("single-partition local pass should NOT match full; comparison is toothless")
	}
	if len(cmp.Mismatches) == 0 {
		t.Fatal("expected mismatches")
	}
}
