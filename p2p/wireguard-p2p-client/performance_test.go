package main

import (
	"testing"
	"time"
)

func TestPerformanceRecoveryBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{1, 15 * time.Second},
		{2, 30 * time.Second},
		{3, time.Minute},
		{4, 5 * time.Minute},
		{8, 5 * time.Minute},
	}
	for _, test := range tests {
		if got := retryDelay(test.failures); got != test.want {
			t.Fatalf("retryDelay(%d) = %s, want %s", test.failures, got, test.want)
		}
	}
}

func TestPerformanceControlIntervals(t *testing.T) {
	if version != "7.15.4" {
		t.Fatalf("version = %q, want 7.15.4", version)
	}
	if activeInterval > 10*time.Second {
		t.Fatalf("active interval too slow for fast topology recovery: %s", activeInterval)
	}
	if stableInterval > 20*time.Second {
		t.Fatalf("stable interval too slow for restart detection: %s", stableInterval)
	}
	if maxFailureDelay > 30*time.Second {
		t.Fatalf("coordinator retry cap too slow: %s", maxFailureDelay)
	}
	if failureCooldown > 5*time.Minute {
		t.Fatalf("direct retry cooldown too slow: %s", failureCooldown)
	}
}
