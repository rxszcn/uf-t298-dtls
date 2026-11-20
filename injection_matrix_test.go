// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"testing"
	"time"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injectedPlaintextRecord builds a fixed DTLS 1.2 plaintext record with the
// given content type, epoch and payload. The 13-byte header plus payload makes
// the smallest case (2-byte payload) exactly the 15-byte injected record from
// the reported incident.
func injectedPlaintextRecord(t *testing.T, contentType protocol.ContentType, epoch uint16, payload []byte) []byte {
	t.Helper()
	raw, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
		ContentType: contentType,
		Version:     protocol.Version1_2,
		Epoch:       epoch,
	}, payload)
	require.NoError(t, err)

	return raw
}

// waitForHandshakeResult collects a handshake result, treating timeout as failure.
func waitForHandshakeResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not settle within the timeout")

		return nil
	}
}

// TestInjectionMatrixHandshakeDiscard covers unauthenticated input that must
// converge by dropping the record instead of terminating the handshake:
// unknown fixed content types (incl. RRC 27) and DTLS 1.3 ciphertext-range
// records landing on a DTLS 1.2 connection, plus frame-level corruption.
func TestInjectionMatrixHandshakeDiscard(t *testing.T) {
	cases := []struct {
		name    string
		payload func(t *testing.T) []byte
	}{
		{
			name: "UnknownContentTypeRRC27",
			payload: func(t *testing.T) []byte {
				// The exact incident input: 15 bytes, content type 27, epoch 0.
				return injectedPlaintextRecord(t, protocol.ContentTypeReturnRoutabilityCheck, 0, []byte{0x00, 0x01})
			},
		},
		{
			name: "UnknownContentTypeReserved24",
			payload: func(t *testing.T) []byte {
				return injectedPlaintextRecord(t, protocol.ContentType(24), 0, []byte{0x00, 0x01})
			},
		},
		{
			name: "CiphertextRangeSameShape",
			payload: func(t *testing.T) []byte {
				// Same overall shape as the fixed record but first byte 0x20 puts
				// it in the DTLS 1.3 ciphertext interval, which the 1.2 connection
				// rejects by record form and drops before content dispatch.
				record := injectedPlaintextRecord(t, protocol.ContentTypeHandshake, 0, []byte{0x00, 0x01})
				record[0] = 0x20

				return record
			},
		},
		{
			name: "FrameLevelCorruption",
			payload: func(t *testing.T) []byte {
				// Declared length exceeds the bytes actually present: a framing
				// error, discarded on the existing frame-level path.
				record := injectedPlaintextRecord(t, protocol.ContentTypeHandshake, 0, []byte{0x00, 0x01})
				record[len(record)-1] = 0x7f

				return record[:len(record)-1]
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, cb := packetPipe()
			t.Cleanup(func() {
				_ = ca.Close()
				_ = cb.Close()
			})
			cert, err := selfsign.GenerateSelfSigned()
			require.NoError(t, err)

			serverCh := make(chan error, 1)
			var serverConn *Conn
			go func() {
				serverConn, err = Server(cb, cb.RemoteAddr(), WithCertificates(cert),
					WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2))
				if err == nil {
					err = serverConn.HandshakeContext(context.Background())
				}
				serverCh <- err
			}()

			client, err := Client(ca, ca.RemoteAddr(), WithInsecureSkipVerify(true),
				WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2))
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			// Inject while the certificate handshake is in flight.
			_, err = ca.WriteTo(tc.payload(t), cb.LocalAddr())
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			clientErr := client.HandshakeContext(ctx)
			serverErr := waitForHandshakeResult(t, serverCh)

			require.NoError(t, clientErr, "client handshake must survive the discarded record")
			require.NoError(t, serverErr, "server handshake must survive the discarded record")
			assert.False(t, errors.Is(serverErr, dtlserrors.ErrLengthMismatch),
				"no length-class error unrelated to the injected record may surface")
			if serverConn != nil {
				_ = serverConn.Close()
			}
		})
	}
}

// TestInjectedRRC27EpochZeroRecordBothEndsSucceed is the exact reported
// construction: a single 15-byte plaintext record with content type 27
// (ReturnRoutabilityCheck), epoch 0 and a 2-byte payload, injected from the
// client side while a DTLS 1.2 certificate handshake is in flight.
//
// Before the fix both handshakes failed with errors that never pointed at the
// injected record:
//
//	server: "handshake failed: data length and declared length do not match"
//	        (the RRC payload is 2 bytes, not the required 9, so Unmarshal
//	         returned ErrLengthMismatch and a fatal decode_error alert was sent)
//	client: the fatal alert / connection teardown surfaced as either
//	        "handshake failed: alert: Alert Fatal: DecodeError" or, when the
//	        transport closed first, "conn is closed"
//
// After the fix the record is unauthenticated and unattributable, so it is
// dropped and both handshakes complete with nil errors and no length-class
// error anywhere.
func TestInjectedRRC27EpochZeroRecordBothEndsSucceed(t *testing.T) {
	ca, cb := packetPipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	serverCh := make(chan error, 1)
	var serverConn *Conn
	go func() {
		serverConn, err = Server(cb, cb.RemoteAddr(), WithCertificates(cert),
			WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2))
		if err == nil {
			err = serverConn.HandshakeContext(context.Background())
		}
		serverCh <- err
	}()

	client, err := Client(ca, ca.RemoteAddr(), WithInsecureSkipVerify(true),
		WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	injected := injectedPlaintextRecord(t, protocol.ContentTypeReturnRoutabilityCheck, 0, []byte{0x00, 0x01})
	require.Len(t, injected, 15, "the incident record is exactly 15 bytes")
	require.Equal(t, byte(protocol.ContentTypeReturnRoutabilityCheck), injected[0])
	require.Equal(t, []byte{0x00, 0x00}, injected[3:5], "epoch is zero")

	_, err = ca.WriteTo(injected, cb.LocalAddr())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientErr := client.HandshakeContext(ctx)
	serverErr := waitForHandshakeResult(t, serverCh)

	require.NoError(t, clientErr, "client handshake must complete")
	require.NoError(t, serverErr, "server handshake must complete")
	assert.False(t, errors.Is(clientErr, dtlserrors.ErrLengthMismatch))
	assert.False(t, errors.Is(serverErr, dtlserrors.ErrLengthMismatch))
	if serverConn != nil {
		_ = serverConn.Close()
	}
}

// TestInjectionMatrixAuthenticatedProtocolError verifies that after the
// handshake is established the pre-auth discard gate is bypassed and an
// authenticated protocol error keeps its existing fatal-alert semantics:
// on a connection without negotiated RRC, an RRC record is rejected with
// UnexpectedMessage instead of being silently dropped. The dispatch is driven
// through handleRecordContent because an epoch-zero record is independently
// discarded by the post-handshake old-epoch rule before content dispatch.
func TestInjectionMatrixAuthenticatedProtocolError(t *testing.T) {
	ca, cb := packetPipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	client, server := handshakePair(t,
		[]ClientOption{WithInsecureSkipVerify(true), WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2)},
		[]ServerOption{WithCertificates(cert), WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2)},
	)
	require.NoError(t, client.configErr)
	require.NoError(t, client.handshakeError)
	require.NoError(t, server.configErr)
	require.NoError(t, server.handshakeError)
	t.Cleanup(func() { _ = server.conn.Close() })

	require.True(t, server.conn.isHandshakeCompletedSuccessfully())
	// RRC is not negotiated on this pair: this is a genuine authenticated
	// protocol error, not unauthenticated input.
	message := &protocol.ReturnRoutabilityCheck{MessageType: protocol.ReturnRoutabilityCheckPathChallenge}
	_, outcome, handleErr := server.conn.handleRecordContent(
		context.Background(),
		message,
		incomingPacketState{
			number:            protocol.RecordNumber{Epoch: 1},
			markPacketAsValid: func() bool { return true },
		},
		ca.RemoteAddr(),
		nil,
	)
	assert.ErrorIs(t, handleErr, dtlserrors.ErrUnexpectedPostHandshakeMessage)
	require.NotNil(t, outcome.responseAlert)
	assert.Equal(t, alert.Fatal, outcome.responseAlert.Level)
	assert.Equal(t, alert.UnexpectedMessage, outcome.responseAlert.Description)
}
