package main

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
