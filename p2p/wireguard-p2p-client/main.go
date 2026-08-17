package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version          = "7.15.0"
	apiBase          = "http://10.0.0.1:8899"
	keepalive        = 25
	onlineMaxAge     = 3 * time.Minute
	directMaxAge     = 3 * time.Minute
	failureCooldown  = 5 * time.Minute
	activeInterval   = 10 * time.Second
	stableInterval   = 20 * time.Second
	inactiveInterval = 3 * time.Second
	maxFailureDelay  = 30 * time.Second
	errorLogInterval = 5 * time.Minute
)

var (
	errDeviceNotRegistered = errors.New("this device is not registered/online on the VPS")
)

func newInstanceID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err == nil {
		return fmt.Sprintf("%x", value)
	}
	return fmt.Sprintf("%032x", uint64(time.Now().UnixNano()))
}

func serverInstanceChanged(previous, current string) bool {
	return current != "" && previous != "" && previous != current
}

type apiPeer struct {
	Key             string      `json:"key"`
	IP              string      `json:"ip"`
	Role            string      `json:"role"`
	InstanceID      string      `json:"instance_id"`
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
	Mode               string
	Endpoint           string
	SelectedType       string
	Candidates         []Candidate
	CandidateSignature string
	PeerInstanceID     string
	Started            int64
	BaselineHandshake  int64
	Failures           int
	RetryAfter         int64
	Generation         int64
	WorkerRunning      bool
}

type app struct {
	preferredInterface string
	interfaceName      string
	wgPath             string
	instanceID         string
	httpClient         *http.Client
	states             map[string]*peerState
	serverKeys         map[string]string
	lastSyncError      string
	lastErrorLog       time.Time
	failureDelay       time.Duration
	nextSyncAttempt    time.Time
	coordinatorVersion string
	mu                 sync.Mutex
	wgMu               sync.Mutex
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			fmt.Println(version)
			return
		case "update":
			force := len(os.Args) > 2 && os.Args[2] == "--force"
			if err := runUpdate(force); err != nil {
				fmt.Fprintln(os.Stderr, "Update failed:", err)
				os.Exit(1)
			}
			return
		}
	}

	preferred := flag.String("interface", "wg0", "preferred WireGuard interface name")
	flag.Parse()
	if !acquireSingleInstance() {
		fmt.Println("WireGuard P2P client is already running or the runtime lock is unavailable.")
		platformPauseOnFatal()
		return
	}

	if err := legacyClientConflict(); err != nil {
		fmt.Println(err)
		platformPauseOnFatal()
		return
	}

	wgPath, err := resolveWGExecutable()
	if err != nil {
		fmt.Println(err)
		platformPauseOnFatal()
		return
	}

	a := &app{
		preferredInterface: *preferred,
		wgPath:             wgPath,
		instanceID:         newInstanceID(),
		httpClient: &http.Client{
			Timeout:   3 * time.Second,
			Transport: &http.Transport{Proxy: nil},
		},
		states:     make(map[string]*peerState),
		serverKeys: make(map[string]string),
	}

	shutdown, cleanupDone := installConsoleCloseHandler()
	defer close(cleanupDone)
	platformClientStarted(a)
	defer platformClientStopped()

	fmt.Printf("WireGuard P2P %s client is running on %s. Press Ctrl+C to stop.\n", version, platformLabel())
	fmt.Println("VPS relay remains available while direct candidates are tested in the background.")

	var next time.Duration
	for {
		select {
		case <-shutdown:
			a.log("Stopping: removing dynamic direct server peers...")
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
				a.mu.Lock()
				a.states = make(map[string]*peerState)
				a.mu.Unlock()
			}
			next = inactiveInterval
			continue
		}
		if a.interfaceName != iface {
			a.interfaceName = iface
			a.log("Using WireGuard interface: " + iface)
			a.cleanup()
			a.mu.Lock()
			a.states = make(map[string]*peerState)
			a.mu.Unlock()
		}

		if time.Now().Before(a.nextSyncAttempt) {
			a.fallbackStaleDirects()
			next = a.loopInterval()
			continue
		}
		if err := a.syncOnce(); err != nil {
			a.fallbackStaleDirects()
			a.reportSyncError(err)
		} else {
			a.reportSyncRecovered()
		}
		next = a.loopInterval()
	}
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

func coordinatorSupportsDirectIndependence(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return false
	}
	return major > 7 || (major == 7 && minor >= 4)
}

func (a *app) stableDirectsHealthy() bool {
	if !coordinatorSupportsDirectIndependence(a.coordinatorVersion) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	hasState := false
	for _, state := range a.states {
		if state == nil {
			continue
		}
		hasState = true
		if state.Mode != "direct" || state.WorkerRunning {
			return false
		}
	}
	return hasState
}

func (a *app) loopInterval() time.Duration {
	interval := activeInterval
	if a.stableDirectsHealthy() {
		interval = stableInterval
	}
	if !a.nextSyncAttempt.IsZero() {
		until := time.Until(a.nextSyncAttempt)
		if until > 0 && until < interval {
			return until
		}
	}
	return interval
}

func (a *app) wg(args ...string) (string, error) {
	a.wgMu.Lock()
	defer a.wgMu.Unlock()
	cmd := exec.Command(a.wgPath, args...)
	configurePlatformCommand(cmd)
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
	for key, state := range a.states {
		state.Generation++
		state.WorkerRunning = false
		_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
	}
	for key := range a.serverKeys {
		_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
	}
}

func (a *app) syncOnce() error {
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
	return a.reconcilePeers(peers, ownKey)
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
	for key, serverIP := range a.serverKeys {
		peer, exists := locals[key]
		if !exists || !contains(peer.AllowedIPs, serverIP+"/32") {
			continue
		}
		if peer.LatestHandshake > 0 && now-peer.LatestHandshake <= int64(directMaxAge/time.Second) {
			continue
		}
		_, _ = a.wg("set", a.interfaceName, "peer", key, "remove")
		if state := a.states[key]; state != nil {
			state.Generation++
			state.WorkerRunning = false
			state.Mode = "idle"
			state.Endpoint = ""
			state.SelectedType = ""
			state.RetryAfter = 0
		}
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
		"instance_id": a.instanceID,
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
		a.coordinatorVersion = result.Version
		return result.Peers, nil
	}

	a.coordinatorVersion = ""
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

func serverInitiatorOwnsPair(localIP, remoteIP string) bool {
	local := net.ParseIP(localIP).To4()
	remote := net.ParseIP(remoteIP).To4()
	if local == nil || remote == nil || bytes.Equal(local, remote) {
		return false
	}
	return bytes.Compare(local, remote) < 0
}

func endpointIP(endpoint string) string {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	return ""
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
		return 15 * time.Second
	case 2:
		return 30 * time.Second
	case 3:
		return time.Minute
	default:
		return failureCooldown
	}
}

func recordProbeFailure(state *peerState, now int64) time.Duration {
	state.Failures++
	delay := retryDelay(state.Failures)
	state.Mode = "idle"
	state.Started = 0
	state.BaselineHandshake = 0
	state.RetryAfter = now + int64(delay/time.Second)
	return delay
}
