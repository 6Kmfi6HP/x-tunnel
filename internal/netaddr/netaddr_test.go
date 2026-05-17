package netaddr

import "testing"

func TestValidateHostPort(t *testing.T) {
	valid := []string{
		"127.0.0.1:8080",
		"[::1]:8080",
		"example.com:443",
	}
	for _, in := range valid {
		if err := ValidateHostPort(in); err != nil {
			t.Fatalf("ValidateHostPort(%q) returned error: %v", in, err)
		}
	}

	invalid := []string{
		":8080",
		"bad host:8080",
		"example.com:0",
		"example.com:65536",
		"example.com:",
	}
	for _, in := range invalid {
		if err := ValidateHostPort(in); err == nil {
			t.Fatalf("ValidateHostPort(%q) accepted invalid address", in)
		}
	}
}

func TestValidateListenHostPortAllowsEmptyHost(t *testing.T) {
	if err := ValidateListenHostPort(":8080"); err != nil {
		t.Fatalf("ValidateListenHostPort accepted empty host listener before refactor; got %v", err)
	}
}

func TestValidateListenHostPortAllowZero(t *testing.T) {
	if err := ValidateListenHostPortAllowZero("127.0.0.1:0"); err != nil {
		t.Fatalf("ValidateListenHostPortAllowZero rejected port 0: %v", err)
	}
	if err := ValidateListenHostPort("127.0.0.1:0"); err == nil {
		t.Fatal("ValidateListenHostPort accepted port 0")
	}
}

func TestHostnameHelpers(t *testing.T) {
	if got := NormalizeTargetHost("Example.COM."); got != "example.com" {
		t.Fatalf("NormalizeTargetHost = %q", got)
	}
	if !ValidHostname("api.example.com") {
		t.Fatal("ValidHostname rejected valid hostname")
	}
	if ValidHostname("-bad.example.com") {
		t.Fatal("ValidHostname accepted invalid hostname")
	}
	if err := ValidateHostnameOrIP("2001:db8::1"); err != nil {
		t.Fatalf("ValidateHostnameOrIP rejected IPv6 literal: %v", err)
	}
}
