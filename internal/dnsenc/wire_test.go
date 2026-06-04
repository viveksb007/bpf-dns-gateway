package dnsenc

import (
	"bytes"
	"testing"
)

func TestEncodeSuffix(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    []byte // wire-format prefix (before zero-padding)
		wantErr bool
	}{
		{
			name:   "simple two-label",
			domain: "s3.amazonaws.com",
			want:   []byte{2, 's', '3', 9, 'a', 'm', 'a', 'z', 'o', 'n', 'a', 'w', 's', 3, 'c', 'o', 'm', 0},
		},
		{
			name:   "regional endpoint",
			domain: "s3.us-west-2.amazonaws.com",
			want:   []byte{2, 's', '3', 9, 'u', 's', '-', 'w', 'e', 's', 't', '-', '2', 9, 'a', 'm', 'a', 'z', 'o', 'n', 'a', 'w', 's', 3, 'c', 'o', 'm', 0},
		},
		{
			name:   "single label",
			domain: "localhost",
			want:   []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0},
		},
		{
			name:   "trailing dot stripped",
			domain: "s3.amazonaws.com.",
			want:   []byte{2, 's', '3', 9, 'a', 'm', 'a', 'z', 'o', 'n', 'a', 'w', 's', 3, 'c', 'o', 'm', 0},
		},
		{
			name:   "uppercase normalized",
			domain: "S3.AMAZONAWS.COM",
			want:   []byte{2, 's', '3', 9, 'a', 'm', 'a', 'z', 'o', 'n', 'a', 'w', 's', 3, 'c', 'o', 'm', 0},
		},
		{
			name:   "mixed case",
			domain: "MyBucket.S3.us-East-1.amazonaws.com",
			want:   []byte{8, 'm', 'y', 'b', 'u', 'c', 'k', 'e', 't', 2, 's', '3', 9, 'u', 's', '-', 'e', 'a', 's', 't', '-', '1', 9, 'a', 'm', 'a', 'z', 'o', 'n', 'a', 'w', 's', 3, 'c', 'o', 'm', 0},
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "empty after dot strip",
			domain:  ".",
			wantErr: true,
		},
		{
			name:    "double dot",
			domain:  "s3..amazonaws.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeSuffix(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeSuffix(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			// Check wire-format prefix matches
			if !bytes.Equal(got[:len(tt.want)], tt.want) {
				t.Errorf("EncodeSuffix(%q) wire prefix = %v, want %v", tt.domain, got[:len(tt.want)], tt.want)
			}
			// Check remaining bytes are zero
			for i := len(tt.want); i < MaxDNSNameLen; i++ {
				if got[i] != 0 {
					t.Errorf("EncodeSuffix(%q) byte %d = %d, want 0 (zero-padding)", tt.domain, i, got[i])
					break
				}
			}
		})
	}
}

func TestEncodeSuffixMaxLabel(t *testing.T) {
	// 63-byte label (max allowed)
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 63 chars
	_, err := EncodeSuffix(label + ".com")
	if err != nil {
		t.Fatalf("63-byte label should be valid: %v", err)
	}

	// 64-byte label (too long)
	label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 chars
	_, err = EncodeSuffix(label + ".com")
	if err == nil {
		t.Fatal("64-byte label should be invalid")
	}
}

func TestDecodeSuffix(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"simple", "s3.amazonaws.com"},
		{"regional", "s3.us-west-2.amazonaws.com"},
		{"single", "localhost"},
		{"deep", "a.b.c.d.e.f.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeSuffix(tt.domain)
			if err != nil {
				t.Fatalf("EncodeSuffix(%q) failed: %v", tt.domain, err)
			}
			decoded, err := DecodeSuffix(encoded)
			if err != nil {
				t.Fatalf("DecodeSuffix failed: %v", err)
			}
			if decoded != tt.domain {
				t.Errorf("roundtrip: got %q, want %q", decoded, tt.domain)
			}
		})
	}
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		pattern      string
		wantSuffix   string
		wantWildcard bool
	}{
		{"*.s3.amazonaws.com", "s3.amazonaws.com", true},
		{"s3.amazonaws.com", "s3.amazonaws.com", false},
		{"*.com", "com", true},
		{"example.com", "example.com", false},
	}

	for _, tt := range tests {
		suffix, isWild := ParsePattern(tt.pattern)
		if suffix != tt.wantSuffix || isWild != tt.wantWildcard {
			t.Errorf("ParsePattern(%q) = (%q, %v), want (%q, %v)",
				tt.pattern, suffix, isWild, tt.wantSuffix, tt.wantWildcard)
		}
	}
}
