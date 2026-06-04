package dnsenc

import (
	"fmt"
	"strings"
)

const MaxDNSNameLen = 128

// EncodeSuffix converts a domain name (e.g., "s3.amazonaws.com") to a
// 256-byte wire-format key suitable for BPF map lookups.
//
// The encoding is lowercase, zero-padded to 256 bytes, and must be
// byte-identical to what the eBPF program extracts from packets.
func EncodeSuffix(domain string) ([MaxDNSNameLen]byte, error) {
	var key [MaxDNSNameLen]byte

	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	if domain == "" {
		return key, fmt.Errorf("empty domain")
	}

	labels := strings.Split(domain, ".")
	pos := 0
	for _, label := range labels {
		if len(label) == 0 {
			return key, fmt.Errorf("empty label in %q", domain)
		}
		if len(label) > 63 {
			return key, fmt.Errorf("label %q exceeds 63 bytes", label)
		}
		if pos+1+len(label) >= MaxDNSNameLen {
			return key, fmt.Errorf("domain %q exceeds max wire-format length", domain)
		}
		key[pos] = byte(len(label))
		pos++
		copy(key[pos:], []byte(label))
		pos += len(label)
	}
	key[pos] = 0 // terminator

	return key, nil
}

// DecodeSuffix converts a wire-format 256-byte key back to a dotted domain
// string for debugging and tests.
func DecodeSuffix(key [MaxDNSNameLen]byte) (string, error) {
	var labels []string
	pos := 0
	for {
		if pos >= MaxDNSNameLen {
			return "", fmt.Errorf("name exceeds buffer at offset %d", pos)
		}
		labelLen := int(key[pos])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 {
			return "", fmt.Errorf("invalid label length %d at offset %d", labelLen, pos)
		}
		pos++
		if pos+labelLen > MaxDNSNameLen {
			return "", fmt.Errorf("label extends beyond buffer at offset %d", pos)
		}
		labels = append(labels, string(key[pos:pos+labelLen]))
		pos += labelLen
	}
	if len(labels) == 0 {
		return "", fmt.Errorf("empty name")
	}
	return strings.Join(labels, "."), nil
}

// ParsePattern strips the "*." prefix from a wildcard pattern and returns
// the suffix domain. For exact patterns (no "*." prefix), returns the
// domain as-is.
func ParsePattern(pattern string) (suffix string, isWildcard bool) {
	if strings.HasPrefix(pattern, "*.") {
		return pattern[2:], true
	}
	return pattern, false
}
