package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
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

// udpDialer abstracts UDP dialing so probeQUIC can be tested with a
// fake connection. The production implementation is realUDPDialer.
type udpDialer interface {
	DialUDP(network string, laddr, raddr *net.UDPAddr) (udpConn, error)
}

// udpConn is the minimal interface probeQUIC needs from a UDP socket.
// *net.UDPConn satisfies it implicitly.
type udpConn interface {
	Write(b []byte) (int, error)
	Read(b []byte) (int, error)
	SetDeadline(t time.Time) error
	Close() error
}

type realUDPDialer struct{}

func (realUDPDialer) DialUDP(network string, laddr, raddr *net.UDPAddr) (udpConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

// probeQUIC sends a VN-trigger packet to addr and waits for a valid
// Version Negotiation response. Returns the round-trip time on success.
// The probe deadline is taken from ctx.Deadline() if set; ctx cancellation
// causes probeQUIC to close the conn and return promptly without leaving
// a goroutine that touches the conn after return.
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) (time.Duration, error) {
	network := "udp4"
	if addr.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := dialer.DialUDP(network, nil, addr)
	if err != nil {
		return 0, fmt.Errorf("udp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	dcid := make([]byte, quicCIDLen)
	scid := make([]byte, quicCIDLen)
	if _, err := rand.Read(dcid); err != nil {
		return 0, err
	}
	if _, err := rand.Read(scid); err != nil {
		return 0, err
	}
	pkt := buildVNTriggerPacket(dcid, scid)

	if d, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(d); err != nil {
			return 0, err
		}
	}

	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return 0, fmt.Errorf("udp write: %w", err)
	}

	type readResult struct {
		buf []byte
		n   int
		err error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		resultCh <- readResult{buf: buf, n: n, err: err}
	}()

	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-resultCh
		return 0, ctx.Err()
	case r := <-resultCh:
		if r.err != nil {
			return 0, fmt.Errorf("udp read: %w", r.err)
		}
		rtt := time.Since(start)
		if err := validateVNResponse(r.buf[:r.n], scid); err != nil {
			return 0, err
		}
		return rtt, nil
	}
}

func handleCheckQUIC(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	mainTimeout := quicTimeout
	if r.Header.Get("X-Timeout") != "" {
		i, err := strconv.ParseInt(r.Header.Get("X-Timeout"), 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse X-Timeout: %v", err))
			return
		}
		mainTimeout = time.Second * time.Duration(i)
	}

	if vars["ip"] == "" {
		userErrorJSON(w, fmt.Errorf("no IP Address Specified"))
		return
	}
	if vars["port"] == "" {
		userErrorJSON(w, fmt.Errorf("no Port number Specified"))
		return
	}
	port, err := strconv.Atoi(vars["port"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("could not parse port number: %v", err))
		return
	}

	ip, err := parseIP(vars["ip"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("could not parse IP: %v", err))
		return
	}

	udpAddr := &net.UDPAddr{IP: ip.IP, Port: port}

	ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
	defer cancel()

	start := time.Now()
	_, err = probeQUIC(ctx, realUDPDialer{}, udpAddr)
	duration := time.Since(start)

	if err != nil {
		outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
		return
	}
	outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
}
