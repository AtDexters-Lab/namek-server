package slug

import "testing"

func TestGenerate_Length(t *testing.T) {
	s := Generate()
	if len(s) != 16 {
		t.Errorf("slug length = %d, want 16", len(s))
	}
}

func TestGenerate_Valid(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := Generate()
		if !IsValid(s) {
			t.Errorf("generated slug %q failed validation", s)
		}
	}
}

func TestGenerate_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		s := Generate()
		if seen[s] {
			t.Fatalf("duplicate slug: %s", s)
		}
		seen[s] = true
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0123456789abcdef", true},
		{"ghjkmnpqrstvwxyz", true},
		{"0000000000000000", true},
		{"", false},
		{"short", false},
		{"01234567890abcdefg", false}, // too long
		{"0123456789abcdei", false},   // 'i' not in crockford
		{"0123456789abcdel", false},   // 'l' not in crockford
		{"0123456789abcdeo", false},   // 'o' not in crockford
		{"0123456789abcdeu", false},   // 'u' not in crockford
		{"ABCDEFGHJKMNPQRS", false},   // uppercase not allowed
	}
	for _, tt := range tests {
		if got := IsValid(tt.input); got != tt.want {
			t.Errorf("IsValid(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEncode_Deterministic(t *testing.T) {
	input := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	result := encode(input)
	if result != "0000000000000000" {
		t.Errorf("encode(zeros) = %q, want all zeros", result)
	}

	input2 := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	result2 := encode(input2)
	if result2 != "zzzzzzzzzzzzzzzz" {
		t.Errorf("encode(0xFF*10) = %q, want all z", result2)
	}
}
