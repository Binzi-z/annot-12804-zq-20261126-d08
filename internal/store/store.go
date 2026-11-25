// Package store implements a crash-safe, append-only commit log for takeover
// and revocation records.
//
// Durability model:
//   - Every record is appended as one line of JSON and fsync'd before Commit
//     returns. A record that is acknowledged is on stable storage.
//   - Reopening replays the log to rebuild in-memory state, so the store's
//     state is a pure function of the on-disk file.
//   - Idempotency is keyed by RequestKey: replaying an acknowledged request
//     (e.g. after the response was "lost") returns the original outcome and
//     never appends a second record.
//   - Each commit carries a monotonically increasing Revision. A commit against
//     a stale base revision is rejected (optimistic concurrency), which is how
//     "revocation wins the race" is enforced when both workers commit.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// RecordType distinguishes the kind of committed mutation.
type RecordType string

const (
	RecTakeover   RecordType = "takeover"
	RecRevocation RecordType = "revocation"
	RecTempExpire RecordType = "temp_expire"
)

// Record is a single durable log entry.
//
// Generation is the authorization generation in force when committed. Target
// names the service set (takeover) or the thing revoked. Actor is the
// committing worker identity. Valid mirrors the decision outcome for takeover
// records. BaseRevision is the revision the committer believed was current.
// Checksum binds the record content so a torn/corrupt tail is detectable.
type Record struct {
	Revision     int64      `json:"revision"`
	Type         RecordType `json:"type"`
	RequestKey   string     `json:"request_key"`
	Generation   int        `json:"generation"`
	Target       string     `json:"target"`
	Actor        string     `json:"actor"`
	Valid        bool       `json:"valid"`
	BaseRevision int64      `json:"base_revision"`
	Detail       string     `json:"detail,omitempty"`
	Checksum     string     `json:"checksum"`
}

// ErrStaleRevision is returned when a commit's base revision is behind the
// current store revision.
var ErrStaleRevision = errors.New("store: stale base revision")

// ErrClosed is returned on operations after Close.
var ErrClosed = errors.New("store: closed")

// Store is a durable commit log with replayed in-memory state.
type Store struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	closed bool

	revision int64
	// idempotency: request key -> committed outcome
	outcomes map[string]Outcome
	// revoked authorizers / tombstoned temps accumulated by replay
	revokedAuthorizers map[string]bool
	tombstones         map[string]bool
	records            []Record
}

// Outcome is what a caller learns from a commit.
type Outcome struct {
	Revision   int64  `json:"revision"`
	RequestKey string `json:"request_key"`
	Accepted   bool   `json:"accepted"`
	Duplicate  bool   `json:"duplicate"` // true if served from idempotency cache
	Reason     string `json:"reason,omitempty"`
}

// Open opens (creating if needed) the log at path and replays it.
func Open(path string) (*Store, error) {
	s := &Store{
		path:               path,
		outcomes:           map[string]Outcome{},
		revokedAuthorizers: map[string]bool{},
		tombstones:         map[string]bool{},
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	if err := s.replay(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// replay rebuilds state from the log, tolerating a torn final line (a committed
// prefix is still valid).
func (s *Store) replay() error {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	rd := bufio.NewReader(s.f)
	line := 0
	var goodBytes int64
	for {
		raw, err := rd.ReadBytes('\n')
		if len(raw) > 0 && raw[len(raw)-1] == '\n' {
			line++
			var r Record
			if jerr := json.Unmarshal(raw, &r); jerr != nil {
				return fmt.Errorf("store: corrupt record at line %d: %w", line, jerr)
			}
			if r.Checksum != recordChecksum(r) {
				return fmt.Errorf("store: checksum mismatch at line %d (rev %d)", line, r.Revision)
			}
			s.applyRecord(r)
			goodBytes += int64(len(raw))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	// Truncate any torn trailing bytes (a partial append that was never fsync'd
	// with a complete newline) so future appends start from a clean boundary.
	if fi, err := s.f.Stat(); err == nil && fi.Size() > goodBytes {
		if terr := s.f.Truncate(goodBytes); terr != nil {
			return terr
		}
	}
	if _, err := s.f.Seek(goodBytes, io.SeekStart); err != nil {
		return err
	}
	return nil
}

func mustLine(r Record) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func (s *Store) applyRecord(r Record) {
	s.records = append(s.records, r)
	if r.Revision > s.revision {
		s.revision = r.Revision
	}
	switch r.Type {
	case RecRevocation:
		s.revokedAuthorizers[r.Target] = true
	case RecTempExpire:
		s.tombstones[r.Target] = true
	}
	if r.RequestKey != "" {
		if _, exists := s.outcomes[r.RequestKey]; !exists {
			s.outcomes[r.RequestKey] = Outcome{
				Revision:   r.Revision,
				RequestKey: r.RequestKey,
				Accepted:   r.Valid,
			}
		}
	}
}

// Revision returns the current committed revision.
func (s *Store) Revision() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision
}

// Lookup returns a previously committed outcome for key, if any.
func (s *Store) Lookup(key string) (Outcome, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.outcomes[key]
	return o, ok
}

// IsRevoked reports whether the target has been revoked/tombstoned.
func (s *Store) IsRevoked(target string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokedAuthorizers[target] || s.tombstones[target]
}

// Append persists a record durably and applies it. Callers should prefer the
// typed Commit* helpers, which enforce idempotency and optimistic concurrency.
//
// Append is the single durability point: it fsyncs before returning.
func (s *Store) Append(r Record) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Outcome{}, ErrClosed
	}
	// Idempotency: a repeated request key returns the original outcome.
	if r.RequestKey != "" {
		if prev, ok := s.outcomes[r.RequestKey]; ok {
			prev.Duplicate = true
			return prev, nil
		}
	}
	if r.BaseRevision != s.revision {
		return Outcome{}, fmt.Errorf("%w: base=%d current=%d", ErrStaleRevision, r.BaseRevision, s.revision)
	}
	r.Revision = s.revision + 1
	r.Checksum = recordChecksum(r)
	line := mustLine(r)
	if _, err := s.f.Write(line); err != nil {
		return Outcome{}, err
	}
	if err := s.f.Sync(); err != nil {
		return Outcome{}, err
	}
	s.applyRecord(r)
	return Outcome{Revision: r.Revision, RequestKey: r.RequestKey, Accepted: r.Valid}, nil
}

// Close closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.f.Close()
}

// Records returns a copy of replayed records (for the verifier).
func (s *Store) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}
