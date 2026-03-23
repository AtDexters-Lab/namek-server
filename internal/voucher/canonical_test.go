package voucher

import (
	"encoding/json"
	"testing"
)

func TestCanonicalize_AlphabeticalOrder(t *testing.T) {
	v := &VoucherData{
		AccountID:             "660e8400-e29b-41d4-a716-446655440000",
		Epoch:                 3,
		FoundingEKFingerprint: "e3b0c44298fc1c149afb",
		IssuedAt:              "2026-03-17T10:00:00Z",
		IssuerEKFingerprint:   "def456",
		SubjectEKFingerprint:  "abc123",
		Type:                  "peer_membership",
		Version:               1,
	}

	data, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}

	// Verify keys are in alphabetical order by parsing and checking
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	expectedKeys := []string{"account_id", "epoch", "founding_ek_fingerprint", "issued_at",
		"issuer_ek_fingerprint", "subject_ek_fingerprint", "type", "version"}

	// Go's json.Marshal on structs preserves declaration order (which is alphabetical here)
	// Verify by checking the raw JSON byte positions
	prevIdx := 0
	for _, key := range expectedKeys {
		idx := indexOf(data, `"`+key+`"`)
		if idx < 0 {
			t.Fatalf("key %q not found in canonical JSON", key)
		}
		if idx < prevIdx {
			t.Errorf("key %q at position %d is before previous key at %d — not alphabetical", key, idx, prevIdx)
		}
		prevIdx = idx
	}
}

func TestCanonicalize_Deterministic(t *testing.T) {
	v := &VoucherData{
		AccountID:             "test-account",
		Epoch:                 1,
		FoundingEKFingerprint: "fp1",
		IssuedAt:              "2026-01-01T00:00:00Z",
		IssuerEKFingerprint:   "fp2",
		SubjectEKFingerprint:  "fp3",
		Type:                  "peer_membership",
		Version:               1,
	}

	d1, _ := Canonicalize(v)
	d2, _ := Canonicalize(v)
	if string(d1) != string(d2) {
		t.Errorf("Canonicalize not deterministic:\n  %s\n  %s", d1, d2)
	}
}

func TestNonceFromData_Deterministic(t *testing.T) {
	data := []byte(`{"account_id":"test","version":1}`)
	n1 := NonceFromData(data)
	n2 := NonceFromData(data)
	if n1 != n2 {
		t.Errorf("NonceFromData not deterministic: %s != %s", n1, n2)
	}
	if len(n1) != 64 {
		t.Errorf("nonce length = %d, want 64 (hex SHA-256)", len(n1))
	}
}

func indexOf(data []byte, substr string) int {
	s := string(data)
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
