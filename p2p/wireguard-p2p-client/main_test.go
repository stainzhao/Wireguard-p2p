package main

import (
	"testing"
	"time"
)

func TestEndpointIP(t *testing.T) {
	tests := map[string]string{
		"211.71.91.89:51820":       "211.71.91.89",
		"[2001:db8::1]:51820":      "2001:db8::1",
		"192.168.0.134:35422":      "192.168.0.134",
		"missing-port":             "",
		"2001:db8::1:invalid-port": "",
	}
	for input, want := range tests {
		if got := endpointIP(input); got != want {
			t.Errorf("endpointIP(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestContains(t *testing.T) {
	values := []string{"10.0.0.2/32", "10.0.0.5/32"}
	if !contains(values, "10.0.0.5/32") {
		t.Fatal("expected value to be found")
	}
	if contains(values, "10.0.0.8/32") {
		t.Fatal("unexpected value was found")
	}
}

func TestRetryDelayEntersCooldown(t *testing.T) {
	tests := map[int]time.Duration{
		1:  time.Minute,
		2:  2 * time.Minute,
		3:  30 * time.Minute,
		20: 30 * time.Minute,
	}
	for failures, want := range tests {
		if got := retryDelay(failures); got != want {
			t.Errorf("retryDelay(%d) = %s, want %s", failures, got, want)
		}
	}
}

func TestRecordProbeFailure(t *testing.T) {
	state := &peerState{Mode: "probe", Started: 900, BaselineHandshake: 123}
	if delay := recordProbeFailure(state, 1000); delay != time.Minute {
		t.Fatalf("first delay = %s", delay)
	}
	if state.Mode != "idle" || state.Started != 0 || state.BaselineHandshake != 0 || state.RetryAfter != 1060 {
		t.Fatalf("unexpected state after first failure: %+v", state)
	}
	recordProbeFailure(state, 1060)
	delay := recordProbeFailure(state, 1180)
	if delay != failureCooldown || state.RetryAfter != 2980 {
		t.Fatalf("cooldown was not applied: delay=%s state=%+v", delay, state)
	}
}
