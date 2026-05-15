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
