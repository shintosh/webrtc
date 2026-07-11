// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"net"
	"testing"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	p2pCandidateExpectedBound = 6
	p2pCandidateBudget        = 8
)

func p2pCandidateClasses(g *ICEGatherer) []ICECandidateType {
	types := g.resolveCandidateTypes()
	if len(types) == 0 {
		return []ICECandidateType{ICECandidateTypeHost, ICECandidateTypeSrflx, ICECandidateTypeRelay}
	}

	result := make([]ICECandidateType, 0, len(types))
	for _, typ := range types {
		switch typ {
		case ice.CandidateTypeHost:
			result = append(result, ICECandidateTypeHost)
		case ice.CandidateTypeServerReflexive:
			result = append(result, ICECandidateTypeSrflx)
		case ice.CandidateTypeRelay:
			result = append(result, ICECandidateTypeRelay)
		default:
		}
	}

	return result
}

func p2pCandidateCountWithinBudget(count int) bool {
	return count <= p2pCandidateBudget
}

func TestP2PCandidateBoundUsesExistingPreConstructionSeams(t *testing.T) {
	eligibleIPv4 := net.ParseIP("192.0.2.1")
	eligibleIPv6 := net.ParseIP("2001:db8::1")
	se := SettingEngine{}
	se.SetNetworkTypes([]NetworkType{NetworkTypeUDP4, NetworkTypeUDP6})
	se.SetInterfaceFilter(func(name string) bool { return name == "p2p0" })
	se.SetIPFilter(func(ip net.IP) bool { return ip.Equal(eligibleIPv4) || ip.Equal(eligibleIPv6) })

	assert.Equal(t, []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6}, se.candidates.ICENetworkTypes)
	assert.True(t, se.candidates.InterfaceFilter("p2p0"))
	assert.False(t, se.candidates.InterfaceFilter("unbounded0"))
	assert.True(t, se.candidates.IPFilter(eligibleIPv4))
	assert.True(t, se.candidates.IPFilter(eligibleIPv6))
	assert.False(t, se.candidates.IPFilter(net.ParseIP("192.0.2.2")))
	assert.Nil(t, se.iceUDPMux)
	assert.Nil(t, se.iceTCPMux)
	assert.Empty(t, se.candidates.addressRewriteRules)

	gatherer, err := NewAPI(WithSettingEngine(se)).NewICEGatherer(ICEGatherOptions{
		ICEServers: []ICEServer{{
			URLs:       []string{"stun:192.0.2.10:3478", "turn:192.0.2.20:3478?transport=udp"},
			Username:   "user",
			Credential: "pass",
		}},
		ICEGatherPolicy: ICETransportPolicyAll,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, gatherer.Close()) })

	var stunURLs, turnURLs int
	for _, uri := range gatherer.validatedServers {
		switch uri.Scheme {
		case stun.SchemeTypeSTUN, stun.SchemeTypeSTUNS:
			stunURLs++
		case stun.SchemeTypeTURN, stun.SchemeTypeTURNS:
			turnURLs++
		}
	}
	assert.Equal(t, 1, stunURLs)
	assert.Equal(t, 1, turnURLs)
	assert.Len(t, p2pCandidateClasses(gatherer), 3)
	assert.Equal(t, p2pCandidateExpectedBound, 2*len(p2pCandidateClasses(gatherer)))
}

func TestP2PCandidateBoundPolicyAndMDNSMatrix(t *testing.T) {
	tests := map[string]struct {
		policy          ICETransportPolicy
		configure       func(*SettingEngine)
		wantClasses     int
		wantMDNSMode    ice.MulticastDNSMode
		wantMaxEndpoint int
	}{
		"hosted all": {
			policy: ICETransportPolicyAll,
			configure: func(se *SettingEngine) {
				se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
			},
			wantClasses:     3,
			wantMDNSMode:    ice.MulticastDNSModeDisabled,
			wantMaxEndpoint: 6,
		},
		"desktop all": {
			policy:          ICETransportPolicyAll,
			configure:       func(*SettingEngine) {},
			wantClasses:     3,
			wantMDNSMode:    ice.MulticastDNSModeQueryOnly,
			wantMaxEndpoint: 6,
		},
		"no host": {
			policy:          ICETransportPolicyNoHost,
			configure:       func(*SettingEngine) {},
			wantClasses:     2,
			wantMDNSMode:    ice.MulticastDNSModeQueryOnly,
			wantMaxEndpoint: 4,
		},
		"relay only": {
			policy:          ICETransportPolicyRelay,
			configure:       func(*SettingEngine) {},
			wantClasses:     1,
			wantMDNSMode:    ice.MulticastDNSModeQueryOnly,
			wantMaxEndpoint: 2,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			se := SettingEngine{}
			test.configure(&se)
			gatherer, err := NewAPI(WithSettingEngine(se)).NewICEGatherer(ICEGatherOptions{
				ICEGatherPolicy: test.policy,
			})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, gatherer.Close()) })

			classes := p2pCandidateClasses(gatherer)
			assert.Len(t, classes, test.wantClasses)
			assert.Equal(t, test.wantMDNSMode, gatherer.sanitizedMDNSMode())
			// mDNS replaces the host address representation; it does not add a
			// second host class or increase the source multiplier.
			assert.Equal(t, test.wantMaxEndpoint, 2*len(classes))
			assert.LessOrEqual(t, 2*len(classes), p2pCandidateExpectedBound)
		})
	}

	assert.True(t, p2pCandidateCountWithinBudget(7), "one endpoint of measured drift headroom")
	assert.True(t, p2pCandidateCountWithinBudget(8), "two endpoints of measured drift headroom")
	assert.False(t, p2pCandidateCountWithinBudget(9), "ninth endpoint blocks activation")
}
