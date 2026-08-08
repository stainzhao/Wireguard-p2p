package main

import (
	"testing"
	"time"
)

func TestIPv4PunchPriorities(t *testing.T) {
	if candidateDefaultPriority("mapped4") != 800 {
		t.Fatal("mapped4 priority changed")
	}
	if candidateDefaultPriority("observed4") != 700 {
		t.Fatal("observed4 priority must be 700")
	}
	if candidateDefaultPriority("predicted4") != 500 {
		t.Fatal("predicted4 priority must be 500")
	}
}

func TestIPv4PunchWindows(t *testing.T) {
	if probeWindowForCandidate(Candidate{Type: "observed4"}) != 8*time.Second {
		t.Fatal("observed4 must use the simultaneous IPv4 window")
	}
	if probeWindowForCandidate(Candidate{Type: "predicted4"}) != 1500*time.Millisecond {
		t.Fatal("predicted4 window must stay bounded")
	}
}
