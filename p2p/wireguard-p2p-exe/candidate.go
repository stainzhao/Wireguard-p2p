package main

import (
	"net"
	"sort"
	"strconv"
)

const (
	candidatePriorityLAN4      = 1000
	candidatePriorityHost6     = 900
	candidatePriorityMapped4   = 800
	candidatePriorityObserved4 = 600
	candidatePriorityPredict4  = 400
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
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})
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
