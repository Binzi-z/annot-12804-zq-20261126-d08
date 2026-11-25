package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// recordChecksum returns a deterministic checksum over the record's semantic
// fields (excluding Checksum itself). It binds the payload so a torn or
// tampered record is detected on replay.
func recordChecksum(r Record) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%d\x00%s\x00%s\x00%t\x00%d\x00%s",
		r.Revision, r.Type, r.RequestKey, r.Generation, r.Target,
		r.Actor, r.Valid, r.BaseRevision, r.Detail)
	return hex.EncodeToString(h.Sum(nil))
}
