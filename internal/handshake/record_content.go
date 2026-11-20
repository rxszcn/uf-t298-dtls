// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"github.com/pion/dtls/v4/pkg/protocol"
)

// IsUnauthenticatedPlaintextContentType reports whether a fixed (legacy)
// DTLSPlaintext record carrying contentType on an epoch-zero record can be
// attributed to any protocol state reachable before authentication completes.
//
// It only classifies non-unified content types: the DTLS 1.3 ciphertext range
// (32..63, see protocol.IsDTLS13Ciphertext) is decided exclusively by record
// form and is never consulted here, so the two judgment intervals cannot cross.
//
// Returns false (attributable) for every content type with an epoch-zero
// handler on an unauthenticated connection — handshake, alert,
// ChangeCipherSpec, ACK, ConnectionID, and ApplicationData (the latter is
// queued as early data). It returns true only for content that no pre-auth
// state can own, which today is the post-handshake ReturnRoutabilityCheck
// (27) plus any unknown/reserved value. Such input is unauthenticated, so the
// connection converges by dropping it instead of terminating the handshake.
// Once the handshake is established the caller bypasses this classifier and the
// record keeps its existing (fatal-alert) semantics.
func IsUnauthenticatedPlaintextContentType(contentType protocol.ContentType) bool {
	if protocol.IsDTLS13Ciphertext(contentType) {
		return false
	}

	switch contentType {
	case protocol.ContentTypeChangeCipherSpec,
		protocol.ContentTypeAlert,
		protocol.ContentTypeHandshake,
		protocol.ContentTypeApplicationData,
		protocol.ContentTypeConnectionID,
		protocol.ContentTypeACK:
		return false
	default:
		// ContentTypeReturnRoutabilityCheck (27) is only valid after the
		// handshake as an authenticated, negotiated post-handshake message;
		// unknown/reserved values have no pre-auth owner either.
		return true
	}
}
