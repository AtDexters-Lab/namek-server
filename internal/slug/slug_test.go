package slug

import "testing"

func TestDerive_Deterministic(t *testing.T) {
	// SHA-256 produces 64 hex chars; use a realistic fingerprint
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	s1, err := Derive(fp)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	s2, err := Derive(fp)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if s1 != s2 {
		t.Errorf("Derive not deterministic: %q != %q", s1, s2)
	}
	if len(s1) != 20 {
		t.Errorf("slug length = %d, want 20", len(s1))
	}
	if !IsValid(s1) {
		t.Errorf("derived slug %q failed validation", s1)
	}
}

func TestDerive_DifferentInputs(t *testing.T) {
	fp1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	fp2 := "a3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	s1, _ := Derive(fp1)
	s2, _ := Derive(fp2)
	if s1 == s2 {
		t.Errorf("different fingerprints produced same slug: %q", s1)
	}
}

func TestDerive_InvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"too short", "abcdef"},
		{"not hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"12 bytes hex (24 chars)", "e3b0c44298fc1c149afbf4c8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Derive(tt.input)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0123456789abcdefghjk", true},  // 20 chars, valid crockford
		{"mnpqrstvwxyz01234567", true},  // 20 chars, valid crockford
		{"00000000000000000000", true},  // 20 zeros
		{"", false},                      // empty
		{"short", false},                 // too short
		{"0123456789abcdef", false},      // 16 chars (old format)
		{"0123456789abcdefghjkm", false}, // 21 chars (too long)
		{"0123456789abcdefghij", false},  // 'i' not in crockford
		{"0123456789abcdefghlo", false},  // 'l' and 'o' not in crockford
		{"ABCDEFGHJKMNPQRSTVWX", false}, // uppercase not allowed
	}
	for _, tt := range tests {
		if got := IsValid(tt.input); got != tt.want {
			t.Errorf("IsValid(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEncodeN_ZeroBytes(t *testing.T) {
	input := make([]byte, 13)
	result := encodeN(input, 20)
	if result != "00000000000000000000" {
		t.Errorf("encodeN(zeros, 20) = %q, want all zeros", result)
	}
}

func TestEncodeN_MaxBytes(t *testing.T) {
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	result := encodeN(input, 20)
	if len(result) != 20 {
		t.Errorf("encodeN length = %d, want 20", len(result))
	}
	if !IsValid(result) {
		t.Errorf("encodeN result %q failed validation", result)
	}
}
