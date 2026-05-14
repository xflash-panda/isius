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
