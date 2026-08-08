package main

import (
	"strconv"
	"time"
)

const (
	passiveIPv6WatchWindow = 15 * time.Second
	passiveIPv6FreshAge    = 5 * time.Second
)

func passiveObserved6Ready(peer localPeer, now int64) bool {
	if peer.LatestHandshake <= 0 || peer.Endpoint == "" {
		return false
	}
	age := now - peer.LatestHandshake
	if age < 0 || age > int64(passiveIPv6FreshAge/time.Second) {
		return false
	}
	return observedTypeForEndpoint(peer.Endpoint) == "observed6"
}

// watchPassiveIPv6 promotes a route-less peer as soon as an authenticated
// inbound WireGuard handshake teaches us its NAT66-translated IPv6 endpoint.
// The watcher is intentionally short-lived; normal candidate retries remain
// responsible for later recovery if this fast window misses.
func (a *app) watchPassiveIPv6(key, serverIP string, generation int64) {
	deadline := time.Now().Add(passiveIPv6WatchWindow)
	for time.Now().Before(deadline) {
		time.Sleep(probePollInterval)

		a.mu.Lock()
		state := a.states[key]
		armed := state != nil && state.Generation == generation && state.Mode == "passive6" && !state.WorkerRunning
		a.mu.Unlock()
		if !armed {
			return
		}

		peer, exists := a.localPeer(key)
		if !exists || !passiveObserved6Ready(peer, time.Now().Unix()) {
			continue
		}

		a.mu.Lock()
		state = a.states[key]
		if state == nil || state.Generation != generation || state.Mode != "passive6" || state.WorkerRunning {
			a.mu.Unlock()
			return
		}
		_, err := a.wg("set", a.interfaceName, "peer", key,
			"allowed-ips", serverIP+"/32",
			"endpoint", peer.Endpoint,
			"persistent-keepalive", strconv.Itoa(keepalive))
		if err != nil {
			a.mu.Unlock()
			return
		}
		state.Mode = "direct"
		state.Endpoint = peer.Endpoint
		state.SelectedType = "observed6"
		state.Failures = 0
		state.RetryAfter = 0
		state.WorkerRunning = false
		state.Started = 0
		state.BaselineHandshake = 0
		a.mu.Unlock()
		a.log("P2P OK " + serverIP + " via observed6 " + peer.Endpoint + " (fast passive)")
		return
	}
}
