package main

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	quicTriggerPacketSize = 1200
	quicCIDLen            = 8
	quicLongHeaderByte    = 0xc0
)

var quicGreaseVersion = [4]byte{0x1a, 0x2a, 0x3a, 0x4a}

// buildVNTriggerPacket constructs a 1200-byte QUIC long-header packet
// using a grease version (RFC 9000 §15) so any RFC-compliant QUIC server
// must respond with a Version Negotiation packet (RFC 9000 §6).
// The 1200-byte size satisfies the anti-amplification floor (RFC 9000 §14.1).
func buildVNTriggerPacket(dcid, scid []byte) []byte {
	pkt := make([]byte, quicTriggerPacketSize)
	pkt[0] = quicLongHeaderByte
	copy(pkt[1:5], quicGreaseVersion[:])
	pkt[5] = byte(len(dcid))
	copy(pkt[6:6+len(dcid)], dcid)
	off := 6 + len(dcid)
	pkt[off] = byte(len(scid))
	copy(pkt[off+1:off+1+len(scid)], scid)
	return pkt
}

// validateVNResponse checks that packet is a syntactically valid Version
// Negotiation response per RFC 9000 §17.2.1, and that its DCID echoes the
// SCID we sent. The DCID echo is what filters out stray UDP packets and
// ICMP errors that happen to arrive on this socket.
func validateVNResponse(packet, sentSCID []byte) error {
	if len(packet) < 7 {
		return fmt.Errorf("invalid VN response: too short (%d bytes)", len(packet))
	}
	if packet[0]&0x80 == 0 {
		return errors.New("invalid VN response: not a long-header packet")
	}
	for i := 1; i <= 4; i++ {
		if packet[i] != 0 {
			return errors.New("invalid VN response: version field is not zero")
		}
	}
	dcidLen := int(packet[5])
	if len(packet) < 6+dcidLen {
		return errors.New("invalid VN response: truncated DCID")
	}
	dcid := packet[6 : 6+dcidLen]
	if !bytes.Equal(dcid, sentSCID) {
		return errors.New("invalid VN response: DCID does not match sent SCID")
	}
	return nil
}
