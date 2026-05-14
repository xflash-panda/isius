package main

import (
	"bytes"
	"testing"
)

func TestBuildVNTriggerPacketLength(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	pkt := buildVNTriggerPacket(dcid, scid)
	if len(pkt) != 1200 {
		t.Fatalf("packet length = %d, want 1200", len(pkt))
	}
}

func TestBuildVNTriggerPacketHeader(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	pkt := buildVNTriggerPacket(dcid, scid)
	if pkt[0] != 0xc0 {
		t.Fatalf("first byte = 0x%02x, want 0xc0", pkt[0])
	}
}

func TestBuildVNTriggerPacketVersion(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	pkt := buildVNTriggerPacket(dcid, scid)
	want := []byte{0x1a, 0x2a, 0x3a, 0x4a}
	if !bytes.Equal(pkt[1:5], want) {
		t.Fatalf("version = %x, want %x", pkt[1:5], want)
	}
}

func TestBuildVNTriggerPacketCIDs(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xaa}, 8)
	scid := bytes.Repeat([]byte{0xbb}, 8)
	pkt := buildVNTriggerPacket(dcid, scid)
	if pkt[5] != 8 {
		t.Fatalf("DCID len = %d, want 8", pkt[5])
	}
	if !bytes.Equal(pkt[6:14], dcid) {
		t.Fatalf("DCID at offset 6 = %x, want %x", pkt[6:14], dcid)
	}
	if pkt[14] != 8 {
		t.Fatalf("SCID len = %d, want 8", pkt[14])
	}
	if !bytes.Equal(pkt[15:23], scid) {
		t.Fatalf("SCID at offset 15 = %x, want %x", pkt[15:23], scid)
	}
}

// makeValidVNResponse builds a syntactically valid VN response that echoes
// dcid back as the response's DCID (per RFC 9000 §17.2.1, the server swaps
// DCID/SCID in the VN response).
func makeValidVNResponse(dcid []byte) []byte {
	serverSCID := bytes.Repeat([]byte{0xee}, 8)
	pkt := []byte{0xc0, 0x00, 0x00, 0x00, 0x00}
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(serverSCID)))
	pkt = append(pkt, serverSCID...)
	return pkt
}

func TestValidateVNResponseValid(t *testing.T) {
	sentSCID := bytes.Repeat([]byte{0x42}, 8)
	pkt := makeValidVNResponse(sentSCID)
	if err := validateVNResponse(pkt, sentSCID); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateVNResponseTooShort(t *testing.T) {
	if err := validateVNResponse([]byte{0xc0, 0, 0, 0, 0}, nil); err == nil {
		t.Fatal("expected error for too-short response")
	}
}

func TestValidateVNResponseNotLongHeader(t *testing.T) {
	sentSCID := bytes.Repeat([]byte{0x42}, 8)
	pkt := makeValidVNResponse(sentSCID)
	pkt[0] = 0x40 // clear long-header bit
	if err := validateVNResponse(pkt, sentSCID); err == nil {
		t.Fatal("expected error for non-long-header response")
	}
}

func TestValidateVNResponseNonZeroVersion(t *testing.T) {
	sentSCID := bytes.Repeat([]byte{0x42}, 8)
	pkt := makeValidVNResponse(sentSCID)
	pkt[4] = 0x01 // any non-zero byte in version field
	if err := validateVNResponse(pkt, sentSCID); err == nil {
		t.Fatal("expected error for non-zero version")
	}
}

func TestValidateVNResponseDCIDMismatch(t *testing.T) {
	pkt := makeValidVNResponse(bytes.Repeat([]byte{0x11}, 8))
	sentSCID := bytes.Repeat([]byte{0x99}, 8)
	if err := validateVNResponse(pkt, sentSCID); err == nil {
		t.Fatal("expected error for DCID mismatch")
	}
}
