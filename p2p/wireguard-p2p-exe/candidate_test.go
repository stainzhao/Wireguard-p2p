package main

import (
	"net"
	"testing"
)

func TestUsableGlobalIPv6(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"2001:4860:4860::8888", true},
		{"fe80::1", false},
		{"fd00::1", false},
		{"::1", false},
		{"192.168.1.1", false},
	}
	for _, test := range tests {
		if got := isUsableGlobalIPv6(net.ParseIP(test.address)); got != test.want {
			t.Fatalf("isUsableGlobalIPv6(%s)=%v want %v", test.address, got, test.want)
		}
	}
}

func TestDedupeCandidates(t *testing.T) {
	input := []Candidate{
		{Type: "lan4", Endpoint: "192.168.1.2:51820"},
		{Type: "lan4", Endpoint: "192.168.1.2:51820"},
		{Type: "host6", Endpoint: "[2001:db8::1]:51820"},
	}
	got := dedupeCandidates(input)
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
}
