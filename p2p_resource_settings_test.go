// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/sctp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSCTPAssociationPairFromSettings(
	t *testing.T,
	leftSE, rightSE SettingEngine,
) (*sctp.Association, *sctp.Association) {
	t.Helper()

	leftConn, rightConn := net.Pipe()
	t.Cleanup(func() {
		assert.NoError(t, leftConn.Close())
		assert.NoError(t, rightConn.Close())
	})

	start := func(se SettingEngine, conn net.Conn) <-chan struct {
		association *sctp.Association
		err         error
	} {
		result := make(chan struct {
			association *sctp.Association
			err         error
		}, 1)
		go func() {
			transport := NewAPI(WithSettingEngine(se)).NewSCTPTransport(nil)
			opts := append([]sctp.ClientOption{sctp.WithNetConn(conn)}, transport.optionalSCTPClientOptions()...)
			association, err := sctp.ClientWithOptions(opts...)
			result <- struct {
				association *sctp.Association
				err         error
			}{association: association, err: err}
		}()

		return result
	}

	leftResult, rightResult := start(leftSE, leftConn), start(rightSE, rightConn)
	var left, right *sctp.Association
	for side, result := range map[string]<-chan struct {
		association *sctp.Association
		err         error
	}{"left": leftResult, "right": rightResult} {
		select {
		case got := <-result:
			require.NoError(t, got.err, side)
			require.NotNil(t, got.association, side)
			if side == "left" {
				left = got.association
			} else {
				right = got.association
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s SCTP association did not start", side)
		}
	}
	t.Cleanup(func() {
		left.Abort("test complete")
		right.Abort("test complete")
	})

	return left, right
}

func assertSCTPResourceLimitClosed(t *testing.T, err error) {
	t.Helper()
	assert.Error(t, err)
}

func TestSettingEngineSCTPResourceOptionsReachTransport(t *testing.T) {
	tests := map[string]struct {
		configure func(*SettingEngine)
		assert    func(*testing.T, SettingEngine)
	}{
		"stream limits": {
			configure: func(se *SettingEngine) { se.SetSCTPStreamLimits(2, 3) },
			assert: func(t *testing.T, se SettingEngine) {
				assert.Equal(t, uint16(2), se.sctp.maxInboundStreams)
				assert.Equal(t, uint16(3), se.sctp.maxOutboundStreams)
			},
		},
		"inbound message": {
			configure: func(se *SettingEngine) { se.SetSCTPMaxInboundMessageSize(16 * 1024) },
			assert: func(t *testing.T, se SettingEngine) {
				assert.Equal(t, uint32(16*1024), se.sctp.maxInboundMessageSize)
			},
		},
		"retained chunks": {
			configure: func(se *SettingEngine) { se.SetSCTPMaxRetainedPayloadChunks(1024) },
			assert: func(t *testing.T, se SettingEngine) {
				assert.Equal(t, uint32(1024), se.sctp.maxRetainedPayloadChunks)
			},
		},
		"reassembly entries": {
			configure: func(se *SettingEngine) { se.SetSCTPMaxReassemblyQueueEntries(64) },
			assert: func(t *testing.T, se SettingEngine) {
				assert.Equal(t, uint32(64), se.sctp.maxReassemblyQueueEntries)
			},
		},
		"interleaving disabled": {
			configure: func(se *SettingEngine) { se.EnableSCTPMessageInterleaving(false) },
			assert: func(t *testing.T, se SettingEngine) {
				assert.False(t, se.sctp.enableMessageInterleaving)
				assert.True(t, se.sctp.enableMessageInterleavingSet)
			},
		},
		"equal service": {
			configure: func(se *SettingEngine) { se.SetSCTPInterleavingEqualService() },
			assert: func(t *testing.T, se SettingEngine) {
				assert.True(t, se.sctp.equalServiceScheduler)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			se := SettingEngine{}
			test.configure(&se)
			test.assert(t, se)

			transport := NewAPI(WithSettingEngine(se)).NewSCTPTransport(nil)
			assert.Len(t, transport.optionalSCTPClientOptions(), 1)
		})
	}
}

func TestSettingEngineSCTPResourceOptionsRemainDisabledByDefault(t *testing.T) {
	transport := NewAPI().NewSCTPTransport(nil)
	assert.Empty(t, transport.optionalSCTPClientOptions())
}

func TestSettingEngineSCTPStreamLimitBehavior(t *testing.T) {
	se := SettingEngine{}
	se.SetSCTPStreamLimits(2, 2)
	left, _ := newSCTPAssociationPairFromSettings(t, se, se)

	_, err := left.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = left.OpenStream(1, sctp.PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = left.OpenStream(2, sctp.PayloadTypeWebRTCBinary)
	assert.ErrorIs(t, err, sctp.ErrOutboundStreamLimitExceeded)
}

func TestSettingEngineSCTPInterleavingPolicyBehavior(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			se := SettingEngine{}
			se.EnableSCTPMessageInterleaving(enabled)
			left, right := newSCTPAssociationPairFromSettings(t, se, se)

			leftMetadata, ok := left.Metadata()
			require.True(t, ok)
			rightMetadata, ok := right.Metadata()
			require.True(t, ok)
			assert.Equal(t, enabled, leftMetadata.MessageInterleavingEnabled)
			assert.Equal(t, enabled, rightMetadata.MessageInterleavingEnabled)
		})
	}
}

func TestSettingEngineSCTPMaxInboundMessageBehavior(t *testing.T) {
	rightSE := SettingEngine{}
	rightSE.SetSCTPMaxInboundMessageSize(1)
	left, right := newSCTPAssociationPairFromSettings(t, SettingEngine{}, rightSE)

	leftStream, err := left.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = leftStream.WriteSCTP([]byte("too large"), sctp.PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	rightStream, err := right.AcceptStream()
	require.NoError(t, err)
	require.NoError(t, rightStream.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err = rightStream.ReadSCTP(make([]byte, 32))
	assertSCTPResourceLimitClosed(t, err)
}

func TestSettingEngineSCTPQueuedResourceBehavior(t *testing.T) {
	tests := map[string]struct {
		configure func(*SettingEngine)
		cause     string
	}{
		"reassembly entries": {
			configure: func(se *SettingEngine) { se.SetSCTPMaxReassemblyQueueEntries(1) },
			cause:     "reassembly queue i-data message identifier limit exceeded",
		},
		"retained chunks": {
			configure: func(se *SettingEngine) { se.SetSCTPMaxRetainedPayloadChunks(1) },
			cause:     "association retained payload chunk limit exceeded",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rightSE := SettingEngine{}
			test.configure(&rightSE)
			left, right := newSCTPAssociationPairFromSettings(t, SettingEngine{}, rightSE)

			leftStream, err := left.OpenStream(0, sctp.PayloadTypeWebRTCBinary)
			require.NoError(t, err)
			_, err = leftStream.WriteSCTP([]byte("first"), sctp.PayloadTypeWebRTCBinary)
			require.NoError(t, err)
			_, err = leftStream.WriteSCTP([]byte("second"), sctp.PayloadTypeWebRTCBinary)
			require.NoError(t, err)
			require.NoError(t, leftStream.SetReadDeadline(time.Now().Add(time.Second)))
			_, _, err = leftStream.ReadSCTP(make([]byte, 1))
			assertSCTPResourceLimitClosed(t, err)
			assert.Contains(t, err.Error(), test.cause)
			rightStream, err := right.AcceptStream()
			require.NoError(t, err)
			require.NoError(t, rightStream.SetReadDeadline(time.Now().Add(time.Second)))
			buffer := make([]byte, 32)
			n, _, err := rightStream.ReadSCTP(buffer)
			if err == nil {
				assert.Equal(t, "first", string(buffer[:n]))
				_, _, err = rightStream.ReadSCTP(buffer)
			}
			assertSCTPResourceLimitClosed(t, err)
		})
	}
}

func TestPeerConnectionDataChannelLifetimeLimitLocal(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	dc, err := pc.CreateDataChannel("first", nil)
	require.NoError(t, err)
	require.NoError(t, dc.Close())

	_, err = pc.CreateDataChannel("second", nil)
	assert.ErrorIs(t, err, ErrDataChannelLifetimeLimit)
}

func TestPeerConnectionDataChannelLifetimeLimitDoesNotReuseExplicitID(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	negotiated := true
	id := uint16(0)
	dc, err := pc.CreateDataChannel("first", &DataChannelInit{ID: &id, Negotiated: &negotiated})
	require.NoError(t, err)
	require.NoError(t, dc.Close())

	_, err = pc.CreateDataChannel("same-id", &DataChannelInit{ID: &id, Negotiated: &negotiated})
	assert.ErrorIs(t, err, ErrDataChannelLifetimeLimit)
}

func TestPeerConnectionDataChannelLifetimeLimitIgnoresInvalidAttempt(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	maxPacketLifeTime, maxRetransmits := uint16(1), uint16(1)
	_, err = pc.CreateDataChannel("invalid", &DataChannelInit{
		MaxPacketLifeTime: &maxPacketLifeTime,
		MaxRetransmits:    &maxRetransmits,
	})
	assert.ErrorIs(t, err, ErrRetransmitsOrPacketLifeTime)

	_, err = pc.CreateDataChannel("valid", nil)
	assert.NoError(t, err)
}

func TestPeerConnectionDataChannelLifetimeLimitConcurrent(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	const attempts = 16
	var (
		wg       sync.WaitGroup
		accepted atomic.Uint32
		rejected atomic.Uint32
	)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, createErr := pc.CreateDataChannel("concurrent", nil)
			switch {
			case createErr == nil:
				accepted.Add(1)
			case errors.Is(createErr, ErrDataChannelLifetimeLimit):
				rejected.Add(1)
			default:
				assert.NoError(t, createErr)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, uint32(1), accepted.Load())
	assert.Equal(t, uint32(attempts-1), rejected.Load())
}

func TestPeerConnectionDataChannelReservationRollsBackBeforeAdmission(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	pc, err := NewAPI(WithSettingEngine(se)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	transport := pc.SCTP()
	require.True(t, transport.reserveDataChannel())
	assert.False(t, transport.admitDataChannel(), "provisional reservation must consume capacity")
	transport.finishDataChannelReservation(false)
	assert.True(t, transport.admitDataChannel(), "failed construction or ACK must return provisional capacity")

	transport.lock.RLock()
	assert.Equal(t, uint32(1), transport.dataChannelsAdmitted)
	assert.Zero(t, transport.dataChannelsPending)
	transport.lock.RUnlock()
}

func TestPeerConnectionDataChannelLifetimeLimitCombinesLocalAndRemote(t *testing.T) {
	answerSE := SettingEngine{}
	answerSE.SetDataChannelLifetimeLimit(2)
	offerPC, err := NewPeerConnection(Configuration{})
	require.NoError(t, err)
	answerPC, err := NewAPI(WithSettingEngine(answerSE)).NewPeerConnection(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { closePairNow(t, offerPC, answerPC) })
	negotiated := true
	answerID := uint16(100)
	_, err = answerPC.CreateDataChannel("local", &DataChannelInit{ID: &answerID, Negotiated: &negotiated})
	require.NoError(t, err)

	var observed atomic.Uint32
	accepted := make(chan struct{})
	answerPC.OnDataChannel(func(*DataChannel) {
		if observed.Add(1) == 1 {
			close(accepted)
		}
	})
	rejected := make(chan error, 1)
	answerPC.SCTP().OnError(func(err error) {
		if errors.Is(err, ErrDataChannelLifetimeLimit) {
			rejected <- err
		}
	})

	_, err = offerPC.CreateDataChannel("first", nil)
	require.NoError(t, err)
	_, err = offerPC.CreateDataChannel("second", nil)
	require.NoError(t, err)
	require.NoError(t, signalPairWithOptions(offerPC, answerPC, withDisableInitialDataChannel(true)))

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("first remote data channel was not accepted")
	}
	select {
	case err = <-rejected:
		assert.ErrorIs(t, err, ErrDataChannelLifetimeLimit)
	case <-time.After(5 * time.Second):
		t.Fatal("second remote data channel was not rejected")
	}
	assert.Equal(t, uint32(1), observed.Load())
	answerPC.SCTP().lock.RLock()
	assert.Equal(t, uint32(2), answerPC.SCTP().dataChannelsAdmitted)
	answerPC.SCTP().lock.RUnlock()
}

func TestPeerConnectionDataChannelLifetimeLimitAllowsOffererAndAnswerer(t *testing.T) {
	se := SettingEngine{}
	se.SetDataChannelLifetimeLimit(1)
	offerPC, answerPC, err := NewAPI(WithSettingEngine(se)).newPair(Configuration{})
	require.NoError(t, err)
	t.Cleanup(func() { closePairNow(t, offerPC, answerPC) })

	negotiated := true
	offerID, answerID := uint16(0), uint16(1)
	_, err = offerPC.CreateDataChannel("offer", &DataChannelInit{ID: &offerID, Negotiated: &negotiated})
	require.NoError(t, err)
	_, err = answerPC.CreateDataChannel("answer", &DataChannelInit{ID: &answerID, Negotiated: &negotiated})
	require.NoError(t, err)
	require.NoError(t, signalPairWithOptions(offerPC, answerPC, withDisableInitialDataChannel(true)))
}
