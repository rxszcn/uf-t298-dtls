// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"testing"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestIsUnauthenticatedPlaintextContentType(t *testing.T) {
	// Every content type with an epoch-zero handler on an unauthenticated
	// connection stays attributable and keeps its existing path.
	attributable := []protocol.ContentType{
		protocol.ContentTypeChangeCipherSpec,
		protocol.ContentTypeAlert,
		protocol.ContentTypeHandshake,
		protocol.ContentTypeApplicationData,
		protocol.ContentTypeConnectionID,
		protocol.ContentTypeACK,
	}
	for _, contentType := range attributable {
		assert.False(t, IsUnauthenticatedPlaintextContentType(contentType),
			"content type %d must remain attributable before authentication", contentType)
	}

	// The post-handshake-only RRC type and unknown/reserved fixed-header values
	// cannot be owned by any pre-handshake protocol state.
	unattributable := []protocol.ContentType{
		protocol.ContentTypeReturnRoutabilityCheck, // 27
		0,  // zero is never a valid fixed content type
		24, // unassigned gap
		28, 29, 30, 31,
	}
	for _, contentType := range unattributable {
		assert.True(t, IsUnauthenticatedPlaintextContentType(contentType),
			"content type %d must be unattributable before authentication", contentType)
	}

	// The DTLS 1.3 ciphertext interval (32..63) is decided solely by record form
	// and must never be claimed by the fixed plaintext classifier, keeping the two
	// judgment intervals from crossing.
	for ct := protocol.ContentType(32); ct < 64; ct++ {
		assert.True(t, protocol.IsDTLS13Ciphertext(ct))
		assert.False(t, IsUnauthenticatedPlaintextContentType(ct),
			"ciphertext-range content type %d is not a plaintext decision", ct)
	}
}
