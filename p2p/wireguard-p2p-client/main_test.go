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
		1:  15 * time.Second,
		2:  30 * time.Second,
		3:  time.Minute,
		4:  5 * time.Minute,
		20: 5 * time.Minute,
	}
	for failures, want := range tests {
		if got := retryDelay(failures); got != want {
			t.Errorf("retryDelay(%d) = %s, want %s", failures, got, want)
		}
	}
}

func TestRecordProbeFailure(t *testing.T) {
	state := &peerState{Mode: "probe", Started: 900, BaselineHandshake: 123}
	if delay := recordProbeFailure(state, 1000); delay != 15*time.Second {
		t.Fatalf("first delay = %s", delay)
	}
	if state.Mode != "idle" || state.Started != 0 || state.BaselineHandshake != 0 || state.RetryAfter != 1015 {
		t.Fatalf("unexpected state after first failure: %+v", state)
	}
	if delay := recordProbeFailure(state, 1060); delay != 30*time.Second || state.RetryAfter != 1090 {
		t.Fatalf("unexpected state after second failure: delay=%s state=%+v", delay, state)
	}
	if delay := recordProbeFailure(state, 1180); delay != time.Minute || state.RetryAfter != 1240 {
		t.Fatalf("unexpected state after third failure: delay=%s state=%+v", delay, state)
	}
	delay := recordProbeFailure(state, 1240)
	if delay != failureCooldown || state.RetryAfter != 1540 {
		t.Fatalf("cooldown was not applied: delay=%s state=%+v", delay, state)
	}
}

func TestServerInstanceChanged(t *testing.T) {
	if serverInstanceChanged("", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("first observation must not look like a reboot")
	}
	if serverInstanceChanged("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("same instance must remain stable")
	}
	if !serverInstanceChanged("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("changed instance must trigger fast recovery")
	}
	if got := newInstanceID(); len(got) != 32 {
		t.Fatalf("instance id length = %d, want 32", len(got))
	}
}

func TestServerInitiatorOwnsPair(t *testing.T) {
	if !serverInitiatorOwnsPair("10.0.0.2", "10.0.0.5") {
		t.Fatal("lower overlay IP should own the server pair")
	}
	if serverInitiatorOwnsPair("10.0.0.5", "10.0.0.2") {
		t.Fatal("higher overlay IP must not duplicate-control the pair")
	}
	if serverInitiatorOwnsPair("10.0.0.2", "10.0.0.2") {
		t.Fatal("server must never target itself")
	}
}
