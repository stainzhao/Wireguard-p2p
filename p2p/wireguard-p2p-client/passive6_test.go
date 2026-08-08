package main

import (
	"testing"
	"time"
)

func TestPassiveObserved6Ready(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name string
		peer localPeer
		want bool
	}{
		{
			name: "fresh global ipv6",
			peer: localPeer{Endpoint: "[2001:4860:4860::8888]:33967", LatestHandshake: now},
			want: true,
		},
		{
			name: "stale ipv6 handshake",
			peer: localPeer{Endpoint: "[2001:4860:4860::8888]:33967", LatestHandshake: now - 6},
			want: false,
		},
		{
			name: "ipv4 is not observed6",
			peer: localPeer{Endpoint: "8.8.8.8:33967", LatestHandshake: now},
			want: false,
		},
		{
			name: "special amt prefix is rejected",
			peer: localPeer{Endpoint: "[2001:3::1]:33967", LatestHandshake: now},
			want: false,
		},
		{
			name: "missing handshake",
			peer: localPeer{Endpoint: "[2001:4860:4860::8888]:33967", LatestHandshake: 0},
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := passiveObserved6Ready(test.peer, now); got != test.want {
				t.Fatalf("passiveObserved6Ready()=%v want %v", got, test.want)
			}
		})
	}
}
