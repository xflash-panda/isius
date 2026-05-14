package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	dcid := bytes.Repeat([]byte{0xaa}, quicCIDLen)
	scid := bytes.Repeat([]byte{0xbb}, quicCIDLen)
	pkt := buildVNTriggerPacket(dcid, scid)

	dcidLenOff := 5
	dcidOff := dcidLenOff + 1
	scidLenOff := dcidOff + quicCIDLen
	scidOff := scidLenOff + 1

	if pkt[dcidLenOff] != quicCIDLen {
		t.Fatalf("DCID len = %d, want %d", pkt[dcidLenOff], quicCIDLen)
	}
	if !bytes.Equal(pkt[dcidOff:dcidOff+quicCIDLen], dcid) {
		t.Fatalf("DCID at offset %d = %x, want %x", dcidOff, pkt[dcidOff:dcidOff+quicCIDLen], dcid)
	}
	if pkt[scidLenOff] != quicCIDLen {
		t.Fatalf("SCID len = %d, want %d", pkt[scidLenOff], quicCIDLen)
	}
	if !bytes.Equal(pkt[scidOff:scidOff+quicCIDLen], scid) {
		t.Fatalf("SCID at offset %d = %x, want %x", scidOff, pkt[scidOff:scidOff+quicCIDLen], scid)
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

func TestValidateVNResponseTruncatedDCID(t *testing.T) {
	// dcidLen=4 claims 4 bytes of DCID, but only 1 byte follows.
	pkt := []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x04, 0xaa}
	if err := validateVNResponse(pkt, nil); err == nil {
		t.Fatal("expected error for truncated DCID")
	}
}

type fakeUDPConn struct {
	mu          sync.Mutex
	written     []byte
	onRead      func(written []byte) ([]byte, error)
	readBlock   chan struct{}
	deadline    time.Time
	closeCalled atomic.Bool
}

func (f *fakeUDPConn) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.written = append(f.written, b...)
	f.mu.Unlock()
	return len(b), nil
}

func (f *fakeUDPConn) Read(b []byte) (int, error) {
	if f.readBlock != nil {
		<-f.readBlock
		return 0, errors.New("fake conn closed")
	}
	f.mu.Lock()
	written := append([]byte(nil), f.written...)
	f.mu.Unlock()
	data, err := f.onRead(written)
	if err != nil {
		return 0, err
	}
	n := copy(b, data)
	return n, nil
}

func (f *fakeUDPConn) SetDeadline(t time.Time) error {
	f.deadline = t
	return nil
}

func (f *fakeUDPConn) Close() error {
	if f.closeCalled.CompareAndSwap(false, true) {
		if f.readBlock != nil {
			close(f.readBlock)
		}
	}
	return nil
}

type fakeUDPDialer struct {
	conn *fakeUDPConn
}

func (d *fakeUDPDialer) DialUDP(_ string, _, _ *net.UDPAddr) (udpConn, error) {
	return d.conn, nil
}

// echoVN extracts the SCID from a written VN-trigger packet and produces
// a valid VN response that echoes it back as the response's DCID.
func echoVN(written []byte) ([]byte, error) {
	if len(written) < 7+2*quicCIDLen {
		return nil, errors.New("written packet too short to extract SCID")
	}
	dcidLen := int(written[5])
	scidLenOff := 6 + dcidLen
	scidLen := int(written[scidLenOff])
	scid := written[scidLenOff+1 : scidLenOff+1+scidLen]

	serverSCID := bytes.Repeat([]byte{0xee}, 8)
	resp := []byte{0xc0, 0x00, 0x00, 0x00, 0x00}
	resp = append(resp, byte(len(scid)))
	resp = append(resp, scid...)
	resp = append(resp, byte(len(serverSCID)))
	resp = append(resp, serverSCID...)
	return resp, nil
}

func TestProbeQUICSuccess(t *testing.T) {
	fc := &fakeUDPConn{onRead: echoVN}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rtt, err := probeQUIC(ctx, dialer, addr)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("expected rtt > 0, got %v", rtt)
	}
}

func TestProbeQUICInvalidResponse(t *testing.T) {
	fc := &fakeUDPConn{onRead: func([]byte) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03}, nil
	}}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := probeQUIC(ctx, dialer, addr)
	if err == nil {
		t.Fatal("expected error for invalid response")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected error to mention 'invalid', got %v", err)
	}
}

func TestProbeQUICTimeout(t *testing.T) {
	fc := &fakeUDPConn{readBlock: make(chan struct{})}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := probeQUIC(ctx, dialer, addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("probeQUIC did not honor deadline: elapsed %v", elapsed)
	}
}
