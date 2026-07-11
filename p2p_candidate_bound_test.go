// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v4/test"
	"github.com/pion/transport/v4/vnet"
	"github.com/pion/turn/v5"
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

func TestP2PCandidateBoundBehavioralGatherMatrix(t *testing.T) { //nolint:cyclop
	lim := test.TimeOut(30 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		serverIP   = "10.0.0.1"
		firstIP    = "10.0.0.2"
		secondIP   = "10.0.0.3"
		serverPort = 3478
		realm      = "pion.ly"
		username   = "user"
		password   = "pass"
	)

	loggerFactory := logging.NewDefaultLoggerFactory()
	router, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "10.0.0.0/24",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	serverNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{serverIP}})
	require.NoError(t, err)
	clientNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{firstIP, secondIP}})
	require.NoError(t, err)
	require.NoError(t, router.AddNet(serverNet))
	require.NoError(t, router.AddNet(clientNet))
	require.NoError(t, router.Start())
	defer func() { assert.NoError(t, router.Stop()) }()

	listener, err := serverNet.ListenPacket("udp4", net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
	require.NoError(t, err)
	authKey := turn.GenerateAuthKey(username, realm, password)
	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(attributes *turn.RequestAttributes) (string, []byte, bool) {
			if attributes.Username == username && attributes.Realm == realm {
				return attributes.Username, authKey, true
			}

			return "", nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(serverIP),
				Address:      "0.0.0.0",
				Net:          serverNet,
			},
		}},
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	defer func() { assert.NoError(t, turnServer.Close()) }()

	iceServers := []ICEServer{{
		URLs: []string{
			fmt.Sprintf("stun:%s:%d", serverIP, serverPort),
			fmt.Sprintf("turn:%s:%d?transport=udp", serverIP, serverPort),
		},
		Username:   username,
		Credential: password,
	}}
	se := SettingEngine{}
	se.SetNet(clientNet)
	se.SetNetworkTypes([]NetworkType{NetworkTypeUDP4})
	se.SetIPFilter(func(ip net.IP) bool {
		return ip.Equal(net.ParseIP(firstIP)) || ip.Equal(net.ParseIP(secondIP))
	})
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)

	candidates := gatherCandidatesWithSettingEngine(t, se, ICEGatherOptions{
		ICEServers:      iceServers,
		ICEGatherPolicy: ICETransportPolicyAll,
	})
	type endpoint struct {
		protocol ICEProtocol
		address  string
		port     uint16
	}
	unique := make(map[endpoint]struct{}, len(candidates))
	byClass := make(map[ICECandidateType]int)
	for _, candidate := range candidates {
		require.Equal(t, ICEProtocolUDP, candidate.Protocol)
		key := endpoint{
			protocol: candidate.Protocol,
			address:  candidate.Address,
			port:     candidate.Port,
		}
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		byClass[candidate.Typ]++
	}

	assert.Equal(t, 2, byClass[ICECandidateTypeHost])
	// Pion gathers srflx candidates from TURN URLs as well as STUN URLs.
	// One of each URL therefore creates two srflx candidates per source.
	assert.Equal(t, 4, byClass[ICECandidateTypeSrflx])
	assert.Equal(t, 2, byClass[ICECandidateTypeRelay])
	assert.Equal(t, p2pCandidateBudget, len(unique))
	assert.Greater(t, len(unique), p2pCandidateExpectedBound)
	assert.True(t, p2pCandidateCountWithinBudget(len(unique)))
}

func TestP2PCandidateDesktopMDNSRepresentation(t *testing.T) {
	se := SettingEngine{}
	se.SetNetworkTypes([]NetworkType{NetworkTypeUDP4})
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryAndGather)

	candidates := gatherCandidatesWithSettingEngine(t, se, ICEGatherOptions{})
	hostCandidates := 0
	for _, candidate := range candidates {
		if candidate.Typ != ICECandidateTypeHost {
			continue
		}
		hostCandidates++
		assert.True(t, strings.HasSuffix(candidate.Address, ".local"), candidate.Address)
	}
	assert.Positive(t, hostCandidates)
}
