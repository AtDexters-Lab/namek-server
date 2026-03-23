package voucher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const VoucherTypePeerMembership = "peer_membership"

// VoucherData is the payload attested by a TPM quote.
// Fields are declared in alphabetical order so json.Marshal produces
// canonical (alphabetically-ordered keys) JSON for deterministic nonce derivation.
type VoucherData struct {
	AccountID             string `json:"account_id"`
	Epoch                 int    `json:"epoch"`
	FoundingEKFingerprint string `json:"founding_ek_fingerprint"`
	IssuedAt              string `json:"issued_at"`
	IssuerEKFingerprint   string `json:"issuer_ek_fingerprint"`
	SubjectEKFingerprint  string `json:"subject_ek_fingerprint"`
	Type                  string `json:"type"`
	Version               int    `json:"version"`
}

// Canonicalize serializes VoucherData to canonical JSON (alphabetical key order,
// no whitespace, no trailing newline, UTF-8).
func Canonicalize(v *VoucherData) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize voucher data: %w", err)
	}
	return data, nil
}

// NonceFromData computes the hex-encoded SHA-256 hash of canonical JSON bytes.
// This is used as the TPM quote nonce for voucher signing.
func NonceFromData(canonical []byte) string {
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}
