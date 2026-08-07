package main

import (
	"strconv"
	"time"
)

const (
	candidateProbeWindow   = 2 * time.Second
	probePollInterval      = 250 * time.Millisecond
	probeKeepalive         = 1
	simultaneousIPv6Window = 8 * time.Second
)

func probeWindowForCandidate(candidate Candidate) time.Duration {
	if candidate.Type == "reflexive6" {
		return simultaneousIPv6Window
	}
	return candidateProbeWindow
}

func (a *app) reconcilePeers(peers []apiPeer, ownKey string) error {
	var ours *apiPeer
	for i := range peers {
		if peers[i].Key == ownKey {
			ours = &peers[i]
			break
		}
	}
	if ours == nil || ours.Endpoint == "" {
		return errDeviceNotRegistered
	}

	ourNAT := endpointIP(ours.Endpoint)
	allowIPv6 := false
	for _, candidate := range ours.Candidates {
		if candidate.Type == "host6" {
			allowIPv6 = true
			break
		}
	}
	locals, err := a.localPeers()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	active := make(map[string]bool)

	for _, peer := range peers {
		serverIP, isServer := serverKeys[peer.Key]
		if !isServer || peer.Endpoint == "" || peer.LatestHandshake == 0 {
			continue
		}
		if time.Duration(now-peer.LatestHandshake)*time.Second > onlineMaxAge {
			continue
		}

		sameNAT := ourNAT != "" && endpointIP(peer.Endpoint) == ourNAT
		candidates := buildProbeCandidates(peer.Candidates, peer.Endpoint, peer.LanEndpoint, sameNAT, allowIPv6)
		if len(candidates) == 0 {
			continue
		}
		active[peer.Key] = true
		signature := candidateSignature(candidates)
		local, exists := locals[peer.Key]
		launch := false
		generation := int64(0)

		a.mu.Lock()
		state := a.states[peer.Key]
		if state == nil {
			state = &peerState{Mode: "idle", Generation: 1}
			a.states[peer.Key] = state
		}
		state.Candidates = append([]Candidate(nil), candidates...)

		direct := exists && contains(local.AllowedIPs, serverIP+"/32")
		signatureChanged := state.CandidateSignature != signature
		if signatureChanged {
			state.CandidateSignature = signature
			state.Generation++
			state.Failures = 0
			state.RetryAfter = 0
			state.WorkerRunning = false

			if direct && local.LatestHandshake > 0 && now-local.LatestHandshake <= int64(directMaxAge/time.Second) &&
				(candidateEndpointExists(candidates, local.Endpoint) || observedTypeForEndpoint(local.Endpoint) == "observed6") {
				state.Mode = "direct"
				state.Endpoint = local.Endpoint
				state.SelectedType = candidateTypeForEndpoint(candidates, local.Endpoint)
				if state.SelectedType == "" {
					state.SelectedType = observedTypeForEndpoint(local.Endpoint)
				}
				a.mu.Unlock()
				continue
			}
			if exists {
				_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
				exists = false
				direct = false
			}
			state.Mode = "idle"
			state.Endpoint = ""
			state.SelectedType = ""
			state.Started = 0
			a.log("Candidates changed for " + serverIP + "; retrying now.")
		}

		if direct {
			if local.LatestHandshake > 0 && now-local.LatestHandshake <= int64(directMaxAge/time.Second) {
				state.Mode = "direct"
				state.Endpoint = local.Endpoint
				if state.SelectedType == "" {
					state.SelectedType = candidateTypeForEndpoint(candidates, local.Endpoint)
					if state.SelectedType == "" {
						state.SelectedType = observedTypeForEndpoint(local.Endpoint)
					}
				}
				state.WorkerRunning = false
				a.mu.Unlock()
				continue
			}
			_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
			state.Generation++
			state.Mode = "idle"
			state.Endpoint = ""
			state.SelectedType = ""
			state.WorkerRunning = false
			state.Started = 0
			state.RetryAfter = 0
			a.log("Fallback " + serverIP + " to VPS; starting candidate probe.")
			exists = false
		}

		// A peer behind IPv6 translation may actively contact us even when it has no
		// publishable host6 candidate.  If WireGuard learned a fresh global IPv6
		// endpoint while this peer was passively armed, promote it immediately.
		if !direct && exists && local.LatestHandshake > 0 && now-local.LatestHandshake <= int64(onlineMaxAge/time.Second) {
			learnedType := observedTypeForEndpoint(local.Endpoint)
			if learnedType == "observed6" {
				_, err := a.wg("set", a.interfaceName, "peer", peer.Key,
					"allowed-ips", serverIP+"/32",
					"endpoint", local.Endpoint,
					"persistent-keepalive", strconv.Itoa(keepalive))
				if err == nil {
					state.Mode = "direct"
					state.Endpoint = local.Endpoint
					state.SelectedType = learnedType
					state.Failures = 0
					state.RetryAfter = 0
					state.WorkerRunning = false
					a.mu.Unlock()
					a.log("P2P OK " + serverIP + " via observed6 " + local.Endpoint)
					continue
				}
			}
		}

		if state.Mode == "probe" && state.WorkerRunning {
			a.mu.Unlock()
			continue
		}
		if now >= state.RetryAfter && !state.WorkerRunning {
			state.WorkerRunning = true
			state.Mode = "probe"
			generation = state.Generation
			launch = true
		}
		a.mu.Unlock()

		if launch {
			go a.runProbeWorker(peer.Key, serverIP, generation)
		}
	}

	for key := range serverKeys {
		if active[key] {
			continue
		}
		a.mu.Lock()
		if state := a.states[key]; state != nil {
			state.Generation++
			state.WorkerRunning = false
		}
		if _, exists := locals[key]; exists {
			_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
		}
		delete(a.states, key)
		a.mu.Unlock()
	}
	return nil
}

func (a *app) runProbeWorker(key, serverIP string, generation int64) {
	candidates, ok := a.probeSnapshot(key, generation)
	if !ok || len(candidates) == 0 {
		a.finishProbeCancelled(key, generation)
		return
	}

	for _, candidate := range candidates {
		if !a.probeGenerationCurrent(key, generation) {
			return
		}
		if candidate.Type == "reflexive6" {
			a.log("Simultaneous IPv6 punch " + serverIP + " via " + candidate.Endpoint + ".")
		}
		local, _ := a.localPeer(key)
		baseline := local.LatestHandshake

		a.mu.Lock()
		state := a.states[key]
		if state == nil || state.Generation != generation || !state.WorkerRunning {
			a.mu.Unlock()
			return
		}
		_, err := a.wg("set", a.interfaceName, "peer", key,
			"endpoint", candidate.Endpoint,
			"persistent-keepalive", strconv.Itoa(probeKeepalive))
		if err != nil {
			a.mu.Unlock()
			continue
		}
		state.Endpoint = candidate.Endpoint
		state.SelectedType = candidate.Type
		state.Started = time.Now().Unix()
		state.BaselineHandshake = baseline
		a.mu.Unlock()

		deadline := time.Now().Add(probeWindowForCandidate(candidate))
		for time.Now().Before(deadline) {
			time.Sleep(probePollInterval)
			if !a.probeGenerationCurrent(key, generation) {
				return
			}
			local, exists := a.localPeer(key)
			if !exists || local.LatestHandshake <= baseline {
				continue
			}

			actualEndpoint := local.Endpoint
			if actualEndpoint == "" {
				actualEndpoint = candidate.Endpoint
			}
			selectedType := candidateTypeForEndpoint(candidates, actualEndpoint)
			if selectedType == "" {
				selectedType = observedTypeForEndpoint(actualEndpoint)
			}
			if selectedType == "" {
				selectedType = candidate.Type
			}

			a.mu.Lock()
			state := a.states[key]
			if state == nil || state.Generation != generation || !state.WorkerRunning {
				a.mu.Unlock()
				return
			}
			_, err := a.wg("set", a.interfaceName, "peer", key,
				"allowed-ips", serverIP+"/32",
				"endpoint", actualEndpoint,
				"persistent-keepalive", strconv.Itoa(keepalive))
			if err != nil {
				a.mu.Unlock()
				return
			}
			state.Mode = "direct"
			state.Endpoint = actualEndpoint
			state.SelectedType = selectedType
			state.Failures = 0
			state.RetryAfter = 0
			state.WorkerRunning = false
			state.Started = 0
			a.mu.Unlock()
			a.log("P2P OK " + serverIP + " via " + selectedType + " " + actualEndpoint)
			return
		}
	}

	a.mu.Lock()
	state := a.states[key]
	if state == nil || state.Generation != generation || !state.WorkerRunning {
		a.mu.Unlock()
		return
	}

	// If this Windows node has native IPv6 but the remote peer has no host6,
	// keep a route-less peer armed after active probes fail.  An authenticated
	// inbound WireGuard handshake can then teach us the remote NAT66 endpoint.
	passiveIPv6 := len(globalIPv6Addresses()) > 0 && !candidateListHasType(candidates, "host6")
	_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
	if passiveIPv6 {
		_, _ = a.wg("set", a.interfaceName, "peer", key, "persistent-keepalive", "0")
	}
	delay := recordProbeFailure(state, time.Now().Unix())
	state.WorkerRunning = false
	state.Endpoint = ""
	state.SelectedType = ""
	if passiveIPv6 {
		state.Mode = "passive6"
	}
	a.mu.Unlock()
	if passiveIPv6 {
		go a.watchPassiveIPv6(key, serverIP, generation)
		a.log("Candidate probe failed " + serverIP + "; passive IPv6 listener armed; fast IPv6 retry expected within seconds; fallback retry in " + delay.String() + ".")
	} else {
		a.log("Candidate probe failed " + serverIP + "; retry in " + delay.String() + ".")
	}
}

func (a *app) probeSnapshot(key string, generation int64) ([]Candidate, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.states[key]
	if state == nil || state.Generation != generation || !state.WorkerRunning {
		return nil, false
	}
	return append([]Candidate(nil), state.Candidates...), true
}

func (a *app) probeGenerationCurrent(key string, generation int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.states[key]
	return state != nil && state.Generation == generation && state.WorkerRunning
}

func (a *app) finishProbeCancelled(key string, generation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.states[key]
	if state != nil && state.Generation == generation {
		state.WorkerRunning = false
		if state.Mode == "probe" {
			state.Mode = "idle"
		}
	}
}

func (a *app) localPeer(key string) (localPeer, bool) {
	peers, err := a.localPeers()
	if err != nil {
		return localPeer{}, false
	}
	peer, ok := peers[key]
	return peer, ok
}
