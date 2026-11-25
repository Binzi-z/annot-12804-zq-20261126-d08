// Package reclaim models tenant-partitioned credential reclamation at scale.
//
// A "credential" lives in exactly one tenant partition. Reclaiming a credential
// means deleting it because its authority has ended: either its authorizer was
// revoked, or a temporary substitute authority it borrowed has expired.
//
// Full reclamation scans every partition and tests every credential. Local
// reclamation visits only the partitions an authoritative change can affect,
// using an authorizer->partitions index. Local reclamation is correct iff it
// produces exactly the same per-credential reclaim set as the full scan. The
// cross-partition hazard this exercises: one revoked authorizer backs
// credentials in many partitions, so a naive "touch only one partition" local
// pass would silently miss the rest.
//
// The dataset is generated deterministically from Params so the verifier can
// rebuild it and recompute both results from the same on-disk parameters.
package reclaim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// Params fully determine the synthetic dataset.
//
// Authorizers come in two flavours, mirroring real tenant-partitioned systems:
//
//   - Global authorizers, shared across tenants. Revoking one fans out across
//     many partitions — the cross-partition hazard that makes local reclamation
//     non-trivial.
//   - Per-tenant local authorizers. Revoking one touches only its tenant.
//
// Each tenant also has one temporary substitute authority; borrowing
// credentials die when it expires.
type Params struct {
	Tenants            int    `json:"tenants"`
	CredsPerTenant     int    `json:"creds_per_tenant"`
	GlobalAuth         int    `json:"global_auth"`
	LocalAuthPerTenant int    `json:"local_auth_per_tenant"`
	GlobalOneIn        int    `json:"global_one_in"` // 1/N of creds use a global authorizer
	TempBorrowOneIn    int    `json:"temp_borrow_one_in"`
	RevokeGlobal       int    `json:"revoke_global"` // revoke the N widest-fanout globals
	RevokeLocalTenants int    `json:"revoke_local_tenants"`
	Seed               uint64 `json:"seed"`
	ReclaimAt          int64  `json:"reclaim_at"`
	TempExpiryMax      int64  `json:"temp_expiry_max"`
	TempExpiredOneIn   int    `json:"temp_expired_one_in"`
}

// DefaultParams is the 50,000-credential configuration.
func DefaultParams() Params {
	return Params{
		Tenants:            500,
		CredsPerTenant:     100, // 500 * 100 = 50,000
		GlobalAuth:         128,
		LocalAuthPerTenant: 4,
		GlobalOneIn:        6,
		TempBorrowOneIn:    10,
		RevokeGlobal:       5,
		RevokeLocalTenants: 40,
		Seed:               0x9E3779B97F4A7C15,
		ReclaimAt:          10_000,
		TempExpiryMax:      5_000,
		TempExpiredOneIn:   10, // ~1/10 of tenant temporaries are expired
	}
}

// Credential is one tenant-scoped credential.
type Credential struct {
	ID         string `json:"id"`
	Tenant     int    `json:"tenant"` // partition id
	Authorizer int    `json:"authorizer"`
	TempID     int    `json:"temp_id"`     // -1 if none
	TempExpiry int64  `json:"temp_expiry"` // meaningful only when TempID >= 0
}

// TempGrant is a temporary substitute authority.
type TempGrant struct {
	ID      int   `json:"id"`
	Expires int64 `json:"expires"`
}

// Dataset is the deterministic synthetic input.
//
// Authorizer IDs live in one namespace: [0, GlobalAuth) are global, and IDs
// >= GlobalAuth are per-tenant locals addressed as GlobalAuth + tenant*LocalAuthPerTenant + slot.
type Dataset struct {
	Params      Params            `json:"params"`
	Credentials []Credential      `json:"-"` // regenerated, not serialized (size)
	Temps       []TempGrant       `json:"temps"`
	RevokedAuth []bool            `json:"-"` // regenerated
	TempsOf     map[int]TempGrant `json:"-"` // regenerated index
}

// xorshift64* — a small deterministic PRNG; avoids math/rand global state so
// the dataset is a pure function of Params.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	x := r.s
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	r.s = x
	return x * 0x2545F4914F6CDD1D
}

func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// numAuthorizers is the size of the authorizer ID space.
func (p Params) numAuthorizers() int {
	return p.GlobalAuth + p.Tenants*p.LocalAuthPerTenant
}

// localBase is the first local-authorizer ID for tenant t.
func (p Params) localBase(t int) int { return p.GlobalAuth + t*p.LocalAuthPerTenant }

// Generate builds the dataset from params, deterministically.
func Generate(p Params) Dataset {
	r := rng{s: p.Seed | 1}
	ds := Dataset{Params: p, TempsOf: map[int]TempGrant{}}

	// One temporary substitute authority per tenant.
	ds.Temps = make([]TempGrant, p.Tenants)
	for t := 0; t < p.Tenants; t++ {
		// Most temporaries are still live at ReclaimAt; ~1/TempExpiredOneIn are
		// expired (their Expires < ReclaimAt).
		var exp int64
		if r.intn(p.TempExpiredOneIn) == 0 {
			exp = int64(r.intn(int(p.ReclaimAt))) // expired
		} else {
			exp = p.ReclaimAt + int64(1+r.intn(int(p.TempExpiryMax))) // still live
		}
		ds.Temps[t] = TempGrant{ID: t, Expires: exp}
		ds.TempsOf[t] = ds.Temps[t]
	}

	total := p.Tenants * p.CredsPerTenant
	ds.Credentials = make([]Credential, 0, total)
	for t := 0; t < p.Tenants; t++ {
		for k := 0; k < p.CredsPerTenant; k++ {
			c := Credential{
				ID:     fmt.Sprintf("t%03d-c%03d", t, k),
				Tenant: t,
				TempID: -1,
			}
			// Authorizer: sometimes a global, otherwise one of this tenant's locals.
			if r.intn(p.GlobalOneIn) == 0 {
				c.Authorizer = r.intn(p.GlobalAuth)
			} else {
				c.Authorizer = p.localBase(t) + r.intn(p.LocalAuthPerTenant)
			}
			// Occasionally borrow the tenant's temporary authority.
			if p.TempBorrowOneIn > 0 && r.intn(p.TempBorrowOneIn) == 0 {
				c.TempID = t
				c.TempExpiry = ds.TempsOf[t].Expires
			}
			ds.Credentials = append(ds.Credentials, c)
		}
	}

	// Revocation set: the widest-fanout globals plus a block of local tenants.
	ds.RevokedAuth = make([]bool, p.numAuthorizers())
	for _, a := range p.widestGlobals(&ds) {
		ds.RevokedAuth[a] = true
	}
	for t := 0; t < p.RevokeLocalTenants && t < p.Tenants; t++ {
		base := p.localBase(t)
		for s := 0; s < p.LocalAuthPerTenant; s++ {
			ds.RevokedAuth[base+s] = true
		}
	}
	return ds
}

// widestGlobals picks the k global authorizers with the most credentials,
// breaking ties by lower ID, so revocation targets the real fan-out.
func (p Params) widestGlobals(ds *Dataset) []int {
	counts := make([]int, p.GlobalAuth)
	for _, c := range ds.Credentials {
		if c.Authorizer < p.GlobalAuth {
			counts[c.Authorizer]++
		}
	}
	type ac struct{ id, n int }
	all := make([]ac, len(counts))
	for i, n := range counts {
		all[i] = ac{i, n}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].id < all[j].id
	})
	k := p.RevokeGlobal
	if k > len(all) {
		k = len(all)
	}
	out := make([]int, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, all[i].id)
	}
	sort.Ints(out)
	return out
}

// ReclaimReason explains why a credential was (or was not) reclaimed.
type ReclaimReason string

const (
	Keep          ReclaimReason = "keep"
	ByRevokedAuth ReclaimReason = "revoked_authorizer"
	ByTempExpired ReclaimReason = "temp_authority_expired"
)

// reasonFor is the single credential predicate shared by both reclaim modes.
func (ds *Dataset) reasonFor(c Credential) ReclaimReason {
	if ds.RevokedAuth[c.Authorizer] {
		return ByRevokedAuth
	}
	if c.TempID >= 0 {
		if t, ok := ds.TempsOf[c.TempID]; ok && ds.Params.ReclaimAt >= t.Expires {
			return ByTempExpired
		}
	}
	return Keep
}

// PartitionIndex maps authorizer -> set of partition (tenant) ids, and temp ->
// set of partitions, so local reclamation can compute its dirty set.
type PartitionIndex struct {
	ByAuthorizer map[int]map[int]bool
	ByTemp       map[int]map[int]bool
}

// BuildIndex constructs the index in one pass over the dataset.
func (ds *Dataset) BuildIndex() PartitionIndex {
	idx := PartitionIndex{ByAuthorizer: map[int]map[int]bool{}, ByTemp: map[int]map[int]bool{}}
	for _, c := range ds.Credentials {
		add := func(m map[int]map[int]bool, key, part int) {
			if m[key] == nil {
				m[key] = map[int]bool{}
			}
			m[key][part] = true
		}
		add(idx.ByAuthorizer, c.Authorizer, c.Tenant)
		if c.TempID >= 0 {
			add(idx.ByTemp, c.TempID, c.Tenant)
		}
	}
	return idx
}

// Result is the reclaim outcome for the whole dataset.
type Result struct {
	// Reclaimed maps credential ID -> reason (only non-Keep entries present).
	Reclaimed map[string]ReclaimReason `json:"-"`
	// ReclaimedCount is len(Reclaimed).
	ReclaimedCount int `json:"reclaimed_count"`
	// PartitionsTouched is how many partitions this mode actually visited.
	PartitionsTouched int `json:"partitions_touched"`
	// PerReason breaks down reclaimed counts by reason.
	PerReason map[string]int `json:"per_reason"`
	// Digest is a sha256 over the sorted "id:reason" lines — a compact,
	// independently recomputable fingerprint of the full result.
	Digest string `json:"digest"`
}

// Full likewise visits every partition and every credential.
func (ds *Dataset) Full() Result {
	res := Result{Reclaimed: map[string]ReclaimReason{}, PerReason: map[string]int{}, PartitionsTouched: ds.Params.Tenants}
	for _, c := range ds.Credentials {
		reason := ds.reasonFor(c)
		if reason != Keep {
			res.Reclaimed[c.ID] = reason
			res.PerReason[string(reason)]++
		}
	}
	res.ReclaimedCount = len(res.Reclaimed)
	res.Digest = digestOf(res.Reclaimed)
	return res
}

// Local visits only the dirty partitions implied by authoritative changes.
// It returns the result and the exact set of partitions it touched.
func (ds *Dataset) Local(idx PartitionIndex) (Result, []int) {
	res := Result{Reclaimed: map[string]ReclaimReason{}, PerReason: map[string]int{}}

	dirty := map[int]bool{}
	// Revoked authorizers dirty every partition holding one of their creds.
	for a, rev := range ds.RevokedAuth {
		if !rev {
			continue
		}
		for part := range idx.ByAuthorizer[a] {
			dirty[part] = true
		}
	}
	// Expired temps dirty every partition holding a borrowing credential.
	for id, t := range ds.TempsOf {
		if ds.Params.ReclaimAt >= t.Expires {
			for part := range idx.ByTemp[id] {
				dirty[part] = true
			}
		}
	}

	touched := make([]int, 0, len(dirty))
	for p := range dirty {
		touched = append(touched, p)
	}
	sort.Ints(touched)

	// Scan only dirty partitions' credentials.
	byTenant := ds.credentialsByTenant()
	for _, part := range touched {
		for _, c := range byTenant[part] {
			reason := ds.reasonFor(c)
			if reason != Keep {
				res.Reclaimed[c.ID] = reason
				res.PerReason[string(reason)]++
			}
		}
	}
	res.ReclaimedCount = len(res.Reclaimed)
	res.PartitionsTouched = len(touched)
	res.Digest = digestOf(res.Reclaimed)
	return res, touched
}

func (ds *Dataset) credentialsByTenant() map[int][]Credential {
	m := make(map[int][]Credential, ds.Params.Tenants)
	for _, c := range ds.Credentials {
		m[c.Tenant] = append(m[c.Tenant], c)
	}
	return m
}

// Comparison is the item-by-item cross-check of local vs full reclamation.
type Comparison struct {
	TotalCredentials int `json:"total_credentials"`
	// ComparedCreds is how many credentials were compared one by one.
	ComparedCreds int `json:"compared_creds"`
	// Mismatches lists credential IDs where local and full disagree.
	Mismatches []string `json:"mismatches"`
	// Equal is true iff Mismatches is empty.
	Equal bool `json:"equal"`
	// Digests agree.
	DigestEqual bool `json:"digest_equal"`
	// PartitionsTouched marks local coverage.
	PartitionsTouched int `json:"partitions_touched"`
	TotalPartitions   int `json:"total_partitions"`
	// UntouchedPartitions is TotalPartitions - PartitionsTouched.
	UntouchedPartitions int `json:"untouched_partitions"`
	// LocalIsPartial is true iff local touched fewer than all partitions (i.e.
	// the optimization actually skipped work).
	LocalIsPartial bool `json:"local_is_partial"`
}

// Compare performs the item-by-item cross-check.
func Compare(ds *Dataset, local, full Result) Comparison {
	cmp := Comparison{
		TotalCredentials:  len(ds.Credentials),
		PartitionsTouched: local.PartitionsTouched,
		TotalPartitions:   ds.Params.Tenants,
	}
	cmp.UntouchedPartitions = cmp.TotalPartitions - cmp.PartitionsTouched
	cmp.LocalIsPartial = cmp.PartitionsTouched < cmp.TotalPartitions

	// Item-by-item: for every credential in the dataset, local and full must
	// agree on whether it is reclaimed and why.
	for _, c := range ds.Credentials {
		cmp.ComparedCreds++
		lr, lok := local.Reclaimed[c.ID]
		fr, fok := full.Reclaimed[c.ID]
		if lok != fok || lr != fr {
			cmp.Mismatches = append(cmp.Mismatches, c.ID)
		}
	}
	cmp.Equal = len(cmp.Mismatches) == 0
	cmp.DigestEqual = local.Digest == full.Digest
	return cmp
}

// Summary is the serialized artifact for the reclamation run.
type Summary struct {
	Params     Params     `json:"params"`
	Full       Result     `json:"full"`
	Local      Result     `json:"local"`
	Comparison Comparison `json:"comparison"`
	// TouchedPartitions is the exact partition list local reclamation visited.
	TouchedPartitions []int `json:"touched_partitions"`
	// IndexStats quantifies the cross-partition fan-out of the revoked set.
	IndexStats IndexStats `json:"index_stats"`
}

// IndexStats quantifies how a single revoked authorizer spans partitions, which
// is what makes the local optimization non-trivial.
type IndexStats struct {
	RevokedAuthorizers int `json:"revoked_authorizers"`
	// MaxPartitionsPerRevokedAuth is the widest fan-out for one revoked
	// authorizer (must be > 1 to prove the cross-partition hazard is real).
	MaxPartitionsPerRevokedAuth int `json:"max_partitions_per_revoked_auth"`
	// WidestRevokedAuth is the authorizer ID with that widest fan-out.
	WidestRevokedAuth int `json:"widest_revoked_auth"`
	ExpiredTemps      int `json:"expired_temps"`
}

func (ds *Dataset) indexStats(idx PartitionIndex) IndexStats {
	var st IndexStats
	best := 0
	for a, rev := range ds.RevokedAuth {
		if !rev {
			continue
		}
		st.RevokedAuthorizers++
		if n := len(idx.ByAuthorizer[a]); n > best {
			best = n
			st.WidestRevokedAuth = a
		}
	}
	st.MaxPartitionsPerRevokedAuth = best
	for _, t := range ds.TempsOf {
		if ds.Params.ReclaimAt >= t.Expires {
			st.ExpiredTemps++
		}
	}
	return st
}

// Run executes full + local + comparison and returns the summary.
func Run(p Params) Summary {
	ds := Generate(p)
	idx := ds.BuildIndex()
	full := ds.Full()
	local, touched := ds.Local(idx)
	cmp := Compare(&ds, local, full)
	return Summary{
		Params:            p,
		Full:              full,
		Local:             local,
		Comparison:        cmp,
		TouchedPartitions: touched,
		IndexStats:        ds.indexStats(idx),
	}
}

func digestOf(m map[string]ReclaimReason) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s:%s\n", k, m[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}
