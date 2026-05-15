package main

import (
	"bytes"
	"testing"
)

func BenchmarkSmuxOpenHeaderRoundTrip(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeSmuxOpenHeader(&buf, streamKindTCP, IPStrategyPv4Pv6, "example.com:443"); err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := readSmuxOpenHeader(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChunkRoundTrip(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1400)
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeChunk(&buf, payload); err != nil {
			b.Fatal(err)
		}
		if _, err := readChunk(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPReplyRoundTrip(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 1200)
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeUDPReply(&buf, "127.0.0.1:5353", payload); err != nil {
			b.Fatal(err)
		}
		if _, _, err := readUDPReply(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPOpenStatusRoundTrip(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := writeTCPOpenStatus(&buf, tcpOpenStatusError, "target rejected"); err != nil {
			b.Fatal(err)
		}
		if _, _, err := readTCPOpenStatus(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTargetPolicyAllowsCIDR(b *testing.B) {
	policy, err := parseTargetPolicy("10.0.0.0/8,192.168.0.0/16", "10.0.9.0/24", "", "")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if ok, _ := policy.Allows("10.1.2.3:443"); !ok {
			b.Fatal("target unexpectedly rejected")
		}
	}
}

func BenchmarkTargetPolicyAllowsHost(b *testing.B) {
	policy, err := parseTargetPolicy("", "", "api.example.com,*.svc.example.com", "blocked.example.com")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if ok, _ := policy.Allows("edge.svc.example.com:443"); !ok {
			b.Fatal("target unexpectedly rejected")
		}
	}
}

func BenchmarkBuildDNSQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := buildDNSQuery("example.com", typeHTTPS); err != nil {
			b.Fatal(err)
		}
	}
}
