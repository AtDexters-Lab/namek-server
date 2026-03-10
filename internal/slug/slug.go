package slug

import (
	"crypto/rand"
	"regexp"
)

// crockford is the lowercase Crockford Base32 alphabet (no i, l, o, u).
const crockford = "0123456789abcdefghjkmnpqrstvwxyz"

var validRegex = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{16}$`)

// Generate returns a 16-character base32-crockford slug (80 bits of entropy).
func Generate() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("slug: rand.Read failed: " + err.Error())
	}
	return encode(b[:])
}

// IsValid reports whether s is a well-formed slug.
func IsValid(s string) bool {
	return validRegex.MatchString(s)
}

// encode converts 10 bytes (80 bits) into 16 crockford base32 characters.
// Each character encodes 5 bits: 80 / 5 = 16.
func encode(src []byte) string {
	// Pack 10 bytes into a bit stream, extract 5-bit groups.
	out := make([]byte, 16)
	// We treat src as a big-endian 80-bit integer and extract 5-bit chunks
	// from the most significant bits down.
	bits := uint64(0)
	bitsAvail := 0
	idx := 0
	for _, b := range src {
		bits = (bits << 8) | uint64(b)
		bitsAvail += 8
		for bitsAvail >= 5 {
			bitsAvail -= 5
			out[idx] = crockford[(bits>>uint(bitsAvail))&0x1F]
			idx++
		}
	}
	return string(out)
}
