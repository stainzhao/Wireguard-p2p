package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version          = "7.0.0-alpha.1"
	apiBase          = "http://10.0.0.1:8899"
	keepalive        = 25
	onlineMaxAge     = 3 * time.Minute
	directMaxAge     = 3 * time.Minute
	probeTimeout     = 90 * time.Second
	failureCooldown  = 30 * time.Minute
	activeInterval   = 15 * time.Second
	inactiveInterval = 3 * time.Second
	maxFailureDelay  = 60 * time.Second
	errorLogInterval = 5 * time.Minute
)

var serverKeys = map[string]string{
	"YmAf+TDF3vM4QyOjPLbYu51owmIpqJt7osYugYtyhSg=": "10.0.0.5", // 2696
	"XTMmfyf2EWH7prfVCSkcWDOB5Lth5+F+OU8KsgtJhQQ=": "10.0.0.2", // GPU
}

type apiPeer struct {
	Key             string      `json:"key"`
	IP              string      `json:"ip"`
	Endpoint        string      `json:"endpoint"`
	LatestHandshake int64       `json:"latest_handshake"`
	LanEndpoint     string      `json:"lan_endpoint"`
	Candidates      []Candidate `json:"candidates,omitempty"`
}

type apiSyncResponse struct {
	Version string    `json:"version"`
	Peers   []apiPeer `json:"peers"`
}

type localPeer struct {
	Endpoint        string
	AllowedIPs      []string
	LatestHandshake int64
}

type peerState struct {
	Mode       string
	Endpoint   string
	Started    int64
	Failures   int
	RetryAfter int64
}

type app struct {
	preferredInterface string
	interfaceName      string
	wgPath             string
	httpClient         *http.Client
	states             map[string]*peerState
	lastSyncError      string
	lastErrorLog       time.Time
	failureDelay       time.Duration
	nextSyncAttempt    time.Time
	mu                 sync.Mutex
}

func main() {
	preferred := flag.String("interface", "wg0", "preferred WireGuard interface name")
	flag.Parse()
	if !acquireSingleInstance() {
		fmt.Println("WireGuard P2P is already running.")
		waitForEnter()
		return
	}

	if oldTaskExists() {
		fmt.Println("Old scheduled task 'WireGuard P2P Sync' still exists.")
		fmt.Println("Run remove_old_powershell_task.ps1 as Administrator, then start this EXE again.")
		waitForEnter()
		return
	}

	wgPath := filepath.Join(os.Getenv("ProgramFiles"), "WireGuard", "wg.exe")
	if _, err := os.Stat(wgPath); err != nil {
		fmt.Printf("WireGuard wg.exe was not found: %s\n", wgPath)
		waitForEnter()
		return
	}

	a := &app{
		preferredInterface: *preferred,
		wgPath:             wgPath,
		httpClient: &http.Client{
			Timeout:   3 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
		states: make(map[string]*peerState),
	}

	shutdown, cleanupDone := installConsoleCloseHandler()
	defer close(cleanupDone)

	fmt.Printf("WireGuard P2P %s is running. Close this window or press Ctrl+C to stop.\n", version)
	fmt.Println("Dynamic peers are removed on exit, so traffic falls back to the VPS.")

	var next time.Duration
	for {
		select {
		case <-shutdown:
			a.log("Stopping: removing dynamic GPU/2696 peers...")
			a.cleanup()
			a.disconnect()
			a.log("Stopped. VPS fallback remains active.")
			return
		case <-time.After(next):
		}

		iface, err := a.resolveInterface()
		if err != nil {
			if a.interfaceName != "" {
				a.log("WireGuard tunnel is inactive; waiting locally.")
				a.interfaceName = ""
				a.states = make(map[string]*peerState)
			}
			next = inactiveInterval
			continue
		}
		if a.interfaceName != iface {
			a.interfaceName = iface
			a.log("Using WireGuard interface: " + iface)
			a.cleanup()
			a.states = make(map[string]*peerState)
		}

		if time.Now().Before(a.nextSyncAttempt) {
			a.fallbackStaleDirects()
			next = activeInterval
			continue
		}
		if err := a.syncOnce(); err != nil {
			a.fallbackStaleDirects()
			a.reportSyncError(err)
		} else {
			a.reportSyncRecovered()
		}
		next = activeInterval
	}
}

func oldTaskExists() bool {
	cmd := exec.Command("schtasks.exe", "/Query", "/TN", "WireGuard P2P Sync")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func waitForEnter() {
	fmt.Println("Press Enter to close.")
	_, _ = fmt.Scanln()
}

func (a *app) log(message string) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("01-02 15:04:05"), message)
	fmt.Println(line)
}

func (a *app) reportSyncError(err error) {
	now := time.Now()
	message := err.Error()
	if message != a.lastSyncError || now.Sub(a.lastErrorLog) >= errorLogInterval {
		a.log("Sync failed: " + message)
		a.lastSyncError = message
		a.lastErrorLog = now
	}
	if a.failureDelay == 0 {
		a.failureDelay = activeInterval
	} else {
		a.failureDelay *= 2
		if a.failureDelay > maxFailureDelay {
			a.failureDelay = maxFailureDelay
		}
	}
	a.nextSyncAttempt = now.Add(a.failureDelay)
}

func (a *app) reportSyncRecovered() {
	if a.lastSyncError != "" {
		a.log("Sync recovered.")
	}
	a.lastSyncError = ""
	a.lastErrorLog = time.Time{}
	a.failureDelay = 0
	a.nextSyncAttempt = time.Time{}
}

func (a *app) wg(args ...string) (string, error) {
	cmd := exec.Command(a.wgPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (a *app) resolveInterface() (string, error) {
	out, err := a.wg("show", "interfaces")
	if err != nil {
		return "", err
	}
	interfaces := strings.Fields(out)
	for _, name := range interfaces {
		if name == a.preferredInterface {
			return name, nil
		}
	}
	if len(interfaces) == 1 {
		return interfaces[0], nil
	}
	return "", errors.New("no unambiguous WireGuard interface")
}

func (a *app) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.interfaceName == "" {
		return
	}
	for key := range serverKeys {
		_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
	}
}

func (a *app) syncOnce() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	ownKey, err := a.wg("show", a.interfaceName, "public-key")
	if err != nil {
		return err
	}
	listenPortText, err := a.wg("show", a.interfaceName, "listen-port")
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(listenPortText)
	if err != nil {
		return errors.New("invalid WireGuard listen port")
	}
	ip := localIPv4()
	if ip == "" {
		return errors.New("no private LAN IPv4 address")
	}
	candidates := gatherLocalCandidates(port, ip)
	peers, err := a.apiSync(ip, port, candidates)
	if err != nil {
		return err
	}
	var ours *apiPeer
	for i := range peers {
		if peers[i].Key == ownKey {
			ours = &peers[i]
			break
		}
	}
	if ours == nil || ours.Endpoint == "" {
		return errors.New("this device is not registered/online on the VPS")
	}
	ourNAT := endpointIP(ours.Endpoint)
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
		candidate, kind := peer.Endpoint, "WAN"
		if endpointIP(peer.Endpoint) == ourNAT {
			candidate, kind = peer.LanEndpoint, "LAN"
		}
		if candidate == "" {
			continue
		}
		active[peer.Key] = true
		state := a.states[peer.Key]
		if state == nil {
			state = &peerState{Mode: "idle", Endpoint: candidate}
			a.states[peer.Key] = state
		}
		local, exists := locals[peer.Key]
		if state.Endpoint != candidate {
			if exists {
				_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
				exists = false
			}
			state.Mode = "idle"
			state.Endpoint = candidate
			state.Started = 0
			state.Failures = 0
			state.RetryAfter = 0
			a.log("Endpoint changed for " + serverIP + "; retrying now.")
		}

		if exists && contains(local.AllowedIPs, serverIP+"/32") {
			state.Mode = "direct"
			if local.LatestHandshake > 0 && now-local.LatestHandshake <= int64(directMaxAge/time.Second) {
				if local.Endpoint != candidate {
					_, err = a.wg("set", a.interfaceName, "peer", peer.Key, "endpoint", candidate, "persistent-keepalive", strconv.Itoa(keepalive))
					if err != nil {
						return err
					}
					state.Endpoint = candidate
				}
				continue
			}
			_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
			exists = false
			state.Mode = "idle"
			state.Started = 0
			state.Failures = 0
			state.RetryAfter = 0
			a.log("Fallback " + serverIP + " to VPS; continuing probe.")
		}

		if exists && state.Mode == "probe" {
			if local.Endpoint != candidate {
				_, err = a.wg("set", a.interfaceName, "peer", peer.Key, "endpoint", candidate, "persistent-keepalive", strconv.Itoa(keepalive))
				if err != nil {
					return err
				}
				state.Endpoint, state.Started = candidate, now
			}
			if local.LatestHandshake > 0 && local.LatestHandshake >= state.Started-2 {
				_, err = a.wg("set", a.interfaceName, "peer", peer.Key, "allowed-ips", serverIP+"/32", "endpoint", candidate, "persistent-keepalive", strconv.Itoa(keepalive))
				if err != nil {
					return err
				}
				state.Mode = "direct"
				state.Failures = 0
				state.RetryAfter = 0
				a.log("P2P OK " + serverIP + " via " + kind + " " + candidate)
				continue
			}
			if now-state.Started >= int64(probeTimeout/time.Second) {
				_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
				exists = false
				delay := recordProbeFailure(state, now)
				a.log("Probe timeout " + serverIP + "; retry in " + delay.String() + ".")
			}
			continue
		}

		if exists {
			_, _ = a.wg("set", a.interfaceName, "peer", peer.Key, "remove")
			exists = false
		}
		if state.Mode == "idle" && now < state.RetryAfter {
			continue
		}

		_, err = a.wg("set", a.interfaceName, "peer", peer.Key, "endpoint", candidate, "persistent-keepalive", strconv.Itoa(keepalive))
		if err != nil {
			return err
		}
		state.Mode, state.Endpoint, state.Started = "probe", candidate, now
		state.RetryAfter = 0
		a.log("Probe " + serverIP + " via " + kind + " " + candidate)
	}

	for key := range serverKeys {
		if active[key] {
			continue
		}
		if _, exists := locals[key]; exists {
			_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
		}
		delete(a.states, key)
	}
	return nil
}

func (a *app) fallbackStaleDirects() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.interfaceName == "" {
		return
	}
	locals, err := a.localPeers()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for key, serverIP := range serverKeys {
		peer, exists := locals[key]
		if !exists || !contains(peer.AllowedIPs, serverIP+"/32") {
			continue
		}
		if peer.LatestHandshake > 0 && now-peer.LatestHandshake <= int64(directMaxAge/time.Second) {
			continue
		}
		_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
		delete(a.states, key)
		a.log("Fallback " + serverIP + " to VPS during coordinator outage.")
	}
}

func (a *app) localPeers() (map[string]localPeer, error) {
	out, err := a.wg("show", a.interfaceName, "dump")
	if err != nil {
		return nil, err
	}
	result := make(map[string]localPeer)
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for _, line := range lines[1:] {
		field := strings.Split(line, "\t")
		if len(field) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(field[4], 10, 64)
		allowed := []string{}
		if field[3] != "(none)" && field[3] != "" {
			allowed = strings.Split(field[3], ",")
		}
		endpoint := field[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		result[field[0]] = localPeer{Endpoint: endpoint, AllowedIPs: allowed, LatestHandshake: handshake}
	}
	return result, nil
}

func (a *app) apiGet(path string, output any) error {
	request, _ := http.NewRequest(http.MethodGet, apiBase+path, nil)
	response, err := a.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("API GET returned %s", response.Status)
	}
	return json.NewDecoder(response.Body).Decode(output)
}

func (a *app) apiSync(lanIP string, listenPort int, candidates []Candidate) ([]apiPeer, error) {
	payload := map[string]any{
		"protocol":    7,
		"lan_ip":      lanIP,
		"listen_port": listenPort,
		"candidates":  candidates,
	}
	body, _ := json.Marshal(payload)
	for _, path := range []string{"/connect", "/sync"} {
		request, _ := http.NewRequest(http.MethodPost, apiBase+path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response, err := a.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusNotFound {
			response.Body.Close()
			continue
		}
		if response.StatusCode != http.StatusOK {
			status := response.Status
			response.Body.Close()
			return nil, fmt.Errorf("API %s returned %s", path, status)
		}
		var result apiSyncResponse
		decodeErr := json.NewDecoder(response.Body).Decode(&result)
		response.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		return result.Peers, nil
	}

	if err := a.apiPost("/announce", payload, nil); err != nil {
		return nil, err
	}
	var peers []apiPeer
	if err := a.apiGet("/", &peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func (a *app) disconnect() {
	if a.interfaceName == "" {
		return
	}
	_ = a.apiPost("/disconnect", map[string]any{}, nil)
}

func (a *app) apiPost(path string, input, output any) error {
	body, _ := json.Marshal(input)
	request, _ := http.NewRequest(http.MethodPost, apiBase+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := a.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("API POST returned %s", response.Status)
	}
	if output != nil {
		return json.NewDecoder(response.Body).Decode(output)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return nil
}

func endpointIP(endpoint string) string {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	index := strings.LastIndex(endpoint, ":")
	if index <= 0 {
		return ""
	}
	return strings.Trim(endpoint[:index], "[]")
}

func localIPv4() string {
	connection, err := net.Dial("udp4", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer connection.Close()
	address, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok || address.IP == nil {
		return ""
	}
	if !address.IP.IsPrivate() {
		return ""
	}
	return address.IP.String()
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func retryDelay(failures int) time.Duration {
	switch failures {
	case 1:
		return time.Minute
	case 2:
		return 2 * time.Minute
	default:
		return failureCooldown
	}
}

func recordProbeFailure(state *peerState, now int64) time.Duration {
	state.Failures++
	delay := retryDelay(state.Failures)
	state.Mode = "idle"
	state.Started = 0
	state.RetryAfter = now + int64(delay/time.Second)
	return delay
}
