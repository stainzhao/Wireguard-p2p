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
		{Type: "host6", Endpoint: "[2001:4860:4860::8888]:51820"},
	}
	got := dedupeCandidates(input)
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
}

func TestBuildProbeCandidatesFiltersRemoteLAN(t *testing.T) {
	advertised := []Candidate{
		{Type: "lan4", Family: "udp4", Endpoint: "192.168.0.10:51820", Priority: 1000},
		{Type: "host6", Family: "udp6", Endpoint: "[2001:4860:4860::8888]:51820", Priority: 900},
	}
	got := buildProbeCandidates(advertised, "8.8.8.8:40000", "192.168.0.10:51820", false, true)
	if candidateTypeForEndpoint(got, "192.168.0.10:51820") != "" {
		t.Fatal("remote LAN candidate should be filtered")
	}
	if candidateTypeForEndpoint(got, "[2001:4860:4860::8888]:51820") != "host6" {
		t.Fatal("IPv6 candidate missing")
	}
	if candidateTypeForEndpoint(got, "8.8.8.8:40000") != "observed4" {
		t.Fatal("observed4 fallback missing")
	}
}

func TestBuildProbeCandidatesKeepsLANOnSameNAT(t *testing.T) {
	got := buildProbeCandidates(nil, "8.8.8.8:40000", "192.168.0.10:51820", true, false)
	if len(got) < 2 || got[0].Type != "lan4" {
		t.Fatalf("unexpected candidates: %+v", got)
	}
}

func TestBuildProbeCandidatesSkipsIPv6WithoutLocalIPv6(t *testing.T) {
	advertised := []Candidate{
		{Type: "host6", Family: "udp6", Endpoint: "[2001:4860:4860::8888]:51820", Priority: 900},
	}
	got := buildProbeCandidates(advertised, "8.8.8.8:40000", "", false, false)
	if candidateTypeForEndpoint(got, "[2001:4860:4860::8888]:51820") != "" {
		t.Fatal("host6 should be skipped without local IPv6 capability")
	}
	if candidateTypeForEndpoint(got, "8.8.8.8:40000") != "observed4" {
		t.Fatal("observed4 fallback missing")
	}
}
