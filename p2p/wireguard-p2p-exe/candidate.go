package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	candidatePriorityLAN4      = 1000
	candidatePriorityHost6     = 900
	candidatePriorityMapped4   = 800
	candidatePriorityObserved4 = 600
	candidatePriorityPredict4  = 400
	maxProbeCandidates         = 5
)

type Candidate struct {
	Type     string `json:"type"`
	Family   string `json:"family"`
	Endpoint string `json:"endpoint"`
	Priority int    `json:"priority"`
	Verified bool   `json:"verified,omitempty"`
}

func gatherLocalCandidates(listenPort int, lanIP string) []Candidate {
	result := make([]Candidate, 0, 4)
	if ip := net.ParseIP(lanIP); ip != nil && ip.To4() != nil && ip.IsPrivate() {
		result = append(result, Candidate{
			Type:     "lan4",
			Family:   "udp4",
			Endpoint: net.JoinHostPort(ip.String(), strconv.Itoa(listenPort)),
			Priority: candidatePriorityLAN4,
		})
	}

	for _, ip := range globalIPv6Addresses() {
		result = append(result, Candidate{
			Type:     "host6",
			Family:   "udp6",
			Endpoint: net.JoinHostPort(ip.String(), strconv.Itoa(listenPort)),
			Priority: candidatePriorityHost6,
		})
	}

	result = dedupeCandidates(result)
	sortCandidates(result)
	return result
}

func globalIPv6Addresses() []net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	result := make([]net.IP, 0, 2)
	seen := make(map[string]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if !isUsableGlobalIPv6(ip) {
				continue
			}
			key := ip.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, ip)
		}
	}
	return result
}

func isUsableGlobalIPv6(ip net.IP) bool {
	return ip != nil &&
		ip.To4() == nil &&
		ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast()
}

func candidateDefaultPriority(candidateType string) int {
	switch candidateType {
	case "lan4":
		return candidatePriorityLAN4
	case "host6":
		return candidatePriorityHost6
	case "mapped4":
		return candidatePriorityMapped4
	case "observed4":
		return candidatePriorityObserved4
	case "predicted4":
		return candidatePriorityPredict4
	default:
		return 0
	}
}

func normalizeCandidate(candidate Candidate) (Candidate, bool) {
	host, portText, err := net.SplitHostPort(candidate.Endpoint)
	if err != nil {
		return Candidate{}, false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return Candidate{}, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Candidate{}, false
	}

	switch candidate.Type {
	case "lan4":
		if ip.To4() == nil || !ip.IsPrivate() {
			return Candidate{}, false
		}
	case "host6":
		if !isUsableGlobalIPv6(ip) {
			return Candidate{}, false
		}
	case "mapped4", "observed4", "predicted4":
		if ip.To4() == nil {
			return Candidate{}, false
		}
	default:
		return Candidate{}, false
	}

	if ip.To4() != nil {
		candidate.Family = "udp4"
		ip = ip.To4()
	} else {
		candidate.Family = "udp6"
	}
	candidate.Endpoint = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	if candidate.Priority <= 0 {
		candidate.Priority = candidateDefaultPriority(candidate.Type)
	}
	return candidate, true
}

func buildProbeCandidates(advertised []Candidate, publicEndpoint, lanEndpoint string, sameNAT, allowIPv6 bool) []Candidate {
	all := make([]Candidate, 0, len(advertised)+2)
	for _, candidate := range advertised {
		if candidate.Type == "host6" && !allowIPv6 {
			continue
		}
		if candidate.Type == "lan4" && !sameNAT {
			continue
		}
		if normalized, ok := normalizeCandidate(candidate); ok {
			all = append(all, normalized)
		}
	}

	if sameNAT && lanEndpoint != "" {
		if candidate, ok := normalizeCandidate(Candidate{
			Type: "lan4", Endpoint: lanEndpoint, Priority: candidatePriorityLAN4,
		}); ok {
			all = append(all, candidate)
		}
	}
	if publicEndpoint != "" {
		if candidate, ok := normalizeCandidate(Candidate{
			Type: "observed4", Endpoint: publicEndpoint, Priority: candidatePriorityObserved4, Verified: true,
		}); ok {
			all = append(all, candidate)
		}
	}

	all = dedupeProbeCandidates(all)
	sortCandidates(all)
	if len(all) <= maxProbeCandidates {
		return all
	}

	selected := append([]Candidate(nil), all[:maxProbeCandidates]...)
	observed := Candidate{}
	hasObserved := false
	for _, candidate := range all {
		if candidate.Type == "observed4" {
			observed = candidate
			hasObserved = true
			break
		}
	}
	if hasObserved && candidateTypeForEndpoint(selected, observed.Endpoint) == "" {
		selected[len(selected)-1] = observed
		sortCandidates(selected)
	}
	return selected
}

func sortCandidates(candidates []Candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority == candidates[j].Priority {
			return candidates[i].Endpoint < candidates[j].Endpoint
		}
		return candidates[i].Priority > candidates[j].Priority
	})
}

func dedupeCandidates(input []Candidate) []Candidate {
	result := make([]Candidate, 0, len(input))
	seen := make(map[string]bool)
	for _, candidate := range input {
		if candidate.Endpoint == "" || candidate.Type == "" {
			continue
		}
		key := candidate.Type + "|" + candidate.Endpoint
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, candidate)
	}
	return result
}

func dedupeProbeCandidates(input []Candidate) []Candidate {
	result := make([]Candidate, 0, len(input))
	seen := make(map[string]bool)
	sortCandidates(input)
	for _, candidate := range input {
		if candidate.Endpoint == "" || seen[candidate.Endpoint] {
			continue
		}
		seen[candidate.Endpoint] = true
		result = append(result, candidate)
	}
	return result
}

func candidateSignature(candidates []Candidate) string {
	parts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		parts = append(parts, candidate.Type+"|"+candidate.Endpoint)
	}
	return strings.Join(parts, ";")
}

func candidateTypeForEndpoint(candidates []Candidate, endpoint string) string {
	for _, candidate := range candidates {
		if candidate.Endpoint == endpoint {
			return candidate.Type
		}
	}
	return ""
}

func candidateEndpointExists(candidates []Candidate, endpoint string) bool {
	return candidateTypeForEndpoint(candidates, endpoint) != ""
}
