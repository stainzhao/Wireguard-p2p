package main

import "testing"

func TestCoordinatorDirectIndependenceGate(t *testing.T) {
	if coordinatorSupportsDirectIndependence("7.3.0") {
		t.Fatal("v7.3 coordinator must keep the 15s compatibility interval")
	}
	if !coordinatorSupportsDirectIndependence("7.4.0") {
		t.Fatal("v7.4 coordinator should enable stable sync")
	}
	if !coordinatorSupportsDirectIndependence("8.0.0") {
		t.Fatal("future major versions should enable stable sync")
	}
}

func TestStableDirectUsesQuietSyncInterval(t *testing.T) {
	a := &app{
		coordinatorVersion: "7.4.0",
		states: map[string]*peerState{
			"server": {Mode: "direct"},
		},
	}
	if got := a.loopInterval(); got != stableInterval {
		t.Fatalf("stable interval=%v want %v", got, stableInterval)
	}
	a.states["server"].WorkerRunning = true
	if got := a.loopInterval(); got != activeInterval {
		t.Fatalf("active interval=%v want %v", got, activeInterval)
	}
}
