# check_quic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `/check_quic/{ip}/{port}` HTTP endpoint that probes UDP reachability via a RFC 9000 §6 Version Negotiation trigger packet — single-target, no `quic-go` dependency, mirrors the shape of `/check_tcp`.

**Architecture:** New file [checkquic.go](checkquic.go) holds three pure helpers (`buildVNTriggerPacket`, `validateVNResponse`, `probeQUIC`) plus the `handleCheckQUIC` handler. Probe IO is abstracted through `udpDialer`/`udpConn` interfaces so tests inject a fake conn — same pattern as `pinger` in [checkping.go](checkping.go). Tests in [checkquic_test.go](checkquic_test.go) cover packet construction (Layer 1), response validation (Layer 2), and probe orchestration (Layer 3, including ctx cancel discipline).

**Tech Stack:** Go 1.25, stdlib only (`net`, `crypto/rand`, `encoding/binary`, `bytes`, `errors`, `context`, `time`), `github.com/gorilla/mux` (already a dep). No new module dependencies.

**Spec:** [docs/superpowers/specs/2026-05-14-check-quic-vn-probe-design.md](../specs/2026-05-14-check-quic-vn-probe-design.md)

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `checkquic.go` | new | constants, interfaces, `buildVNTriggerPacket`, `validateVNResponse`, `probeQUIC`, `realUDPDialer`, `handleCheckQUIC` |
| `checkquic_test.go` | new | Layer 1–3 tests with `fakeUDPConn` / `fakeUDPDialer` / `echoVN` helpers |
| `main.go` | modify | add `quicTimeout = 3 * time.Second` constant; register `/check_quic/{ip}/{port:[0-9]+}` route next to `/check_tcp` |
| `README.md` | modify | document the new endpoint and its VN-reachability semantics |

`go.mod` / `go.sum` are NOT modified.

---

## Task 1: Packet construction (`buildVNTriggerPacket`)

**Files:**
- Create: `checkquic.go`
- Create: `checkquic_test.go`

- [ ] **Step 1: Write failing tests for packet construction**

Create `checkquic_test.go` with these four tests:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run TestBuildVNTriggerPacket -v`

Expected: FAIL with `undefined: buildVNTriggerPacket`.

- [ ] **Step 3: Create checkquic.go skeleton with buildVNTriggerPacket**

Create `checkquic.go` with this initial content (handler / probe / interfaces will be added in later tasks):

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestBuildVNTriggerPacket -v`

Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add checkquic.go checkquic_test.go
git commit -m "feat(check_quic): add VN-trigger packet builder"
```

---

## Task 2: Response validation (`validateVNResponse`)

**Files:**
- Modify: `checkquic.go`
- Modify: `checkquic_test.go`

- [ ] **Step 1: Write failing tests for response validation**

Append to `checkquic_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run TestValidateVNResponse -v`

Expected: FAIL with `undefined: validateVNResponse`.

- [ ] **Step 3: Add validateVNResponse to checkquic.go**

Add `bytes`, `errors`, `fmt` imports and append this function:

```go
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
```

The full imports block at the top of `checkquic.go` should now be:

```go
import (
	"bytes"
	"errors"
	"fmt"
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestValidate -v`

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add checkquic.go checkquic_test.go
git commit -m "feat(check_quic): add VN response validator"
```

---

## Task 3: Probe orchestration — happy path

**Files:**
- Modify: `checkquic.go`
- Modify: `checkquic_test.go`

- [ ] **Step 1: Add probeQUIC happy-path test plus fake helpers**

Append to `checkquic_test.go`:

```go
import (
	// ...existing imports...
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

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
	if len(written) < 23 {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestProbeQUICSuccess -v`

Expected: FAIL with `undefined: probeQUIC` and `undefined: udpConn`.

- [ ] **Step 3: Add interfaces and probeQUIC to checkquic.go**

Update `checkquic.go` imports:

```go
import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"
)
```

Append these definitions to `checkquic.go`:

```go
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
```

Note: `bytes` and `errors` are already imported from Task 2. `context`, `crypto/rand`, `net`, `time` are added now.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestProbeQUICSuccess -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add checkquic.go checkquic_test.go
git commit -m "feat(check_quic): add probeQUIC happy-path with fake-conn injection"
```

---

## Task 4: Probe — invalid response

**Files:**
- Modify: `checkquic_test.go`

- [ ] **Step 1: Add invalid-response test**

Append to `checkquic_test.go`:

```go
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
```

Add `"strings"` to the test file's imports (if not already present).

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./... -run TestProbeQUICInvalidResponse -v`

Expected: PASS (no implementation change needed — `validateVNResponse` already returns an error containing "invalid" for short packets).

- [ ] **Step 3: Commit**

```bash
git add checkquic_test.go
git commit -m "test(check_quic): cover invalid VN response path"
```

---

## Task 5: Probe — timeout via ctx deadline

**Files:**
- Modify: `checkquic_test.go`

- [ ] **Step 1: Add timeout test**

Append to `checkquic_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./... -run TestProbeQUICTimeout -v`

Expected: PASS. `probeQUIC` already selects on `ctx.Done()`, so this test should pass without code changes; it pins the behavior as a regression guard.

- [ ] **Step 3: Commit**

```bash
git add checkquic_test.go
git commit -m "test(check_quic): pin ctx deadline behavior in probeQUIC"
```

---

## Task 6: Probe — context cancel discipline

**Files:**
- Modify: `checkquic_test.go`

- [ ] **Step 1: Add cancel-on-context test**

Append to `checkquic_test.go`:

```go
// TestProbeQUICCancelOnContextDone proves probeQUIC must return promptly
// when its ctx is cancelled mid-Read, and must not leave a goroutine that
// uses the conn after probeQUIC has returned. Mirrors the discipline
// pinned by TestProbePingNoCallAfterReturn for the ping path.
func TestProbeQUICCancelOnContextDone(t *testing.T) {
	fc := &fakeUDPConn{readBlock: make(chan struct{})}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := probeQUIC(ctx, dialer, addr)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("probeQUIC did not return promptly after ctx cancellation")
	}

	// fc.closeCalled must be true — probeQUIC's defer Close OR its
	// ctx.Done() branch must have closed the conn before returning.
	if !fc.closeCalled.Load() {
		t.Fatal("fake conn was not closed by probeQUIC")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./... -run TestProbeQUICCancelOnContextDone -v`

Expected: PASS. The `<-resultCh` drain in `probeQUIC`'s ctx.Done() branch (Task 3) guarantees no goroutine touches the conn after return.

- [ ] **Step 3: Run full test suite**

Run: `go test ./...`

Expected: all tests pass (4 buildVN + 5 validate + 4 probeQUIC + the two existing tcp/ping tests).

- [ ] **Step 4: Commit**

```bash
git add checkquic_test.go
git commit -m "test(check_quic): pin ctx-cancel cleanup in probeQUIC"
```

---

## Task 7: HTTP handler + route registration

**Files:**
- Modify: `checkquic.go`
- Modify: `main.go:31` (add `quicTimeout` const)
- Modify: `main.go:154` (add route)

- [ ] **Step 1: Add quicTimeout constant to main.go**

Open [main.go](main.go). After the existing `const monTimeout = 300 * time.Second` line (line 31), add:

```go
const quicTimeout = 3 * time.Second
```

Resulting block:

```go
const pingTimeout = 1 * time.Second
const pingInterval = 10 * time.Millisecond
const monTimeout = 300 * time.Second
const quicTimeout = 3 * time.Second
```

- [ ] **Step 2: Register route in main.go**

In [main.go](main.go) at line 154, after the existing `check_tcp` registration:

```go
m.Handle(mount+"/check_tcp/{ip}/{port:[0-9]+}", http.HandlerFunc(handleCheckTCP))
```

Add immediately below:

```go
m.Handle(mount+"/check_quic/{ip}/{port:[0-9]+}", http.HandlerFunc(handleCheckQUIC))
```

- [ ] **Step 3: Add handleCheckQUIC to checkquic.go**

Update `checkquic.go` imports to add `net/http`, `strconv`, and `github.com/gorilla/mux`:

```go
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
```

Append the handler:

```go
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
```

`bytes` and `errors` are no longer used directly in `checkquic.go` after this change — wait, they are: `bytes.Equal` in `validateVNResponse`, `errors.New` in `validateVNResponse`. Imports stay.

- [ ] **Step 4: Run full test suite**

Run: `go test ./...`

Expected: all tests pass.

- [ ] **Step 5: Run lint and fmt**

Run: `make fmt && make lint`

Expected: no output, exit 0.

- [ ] **Step 6: Build the binary to confirm route registration compiles**

Run: `make`

Expected: `./isius` binary produced, no errors.

- [ ] **Step 7: Commit**

```bash
git add checkquic.go main.go
git commit -m "feat(check_quic): wire handler and register /check_quic/{ip}/{port}"
```

---

## Task 8: README documentation, manual smoke test, final gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read current README to understand documentation style**

Run: `cat README.md`

Inspect how `/check_tcp` is documented; match that style and section ordering for `/check_quic`.

- [ ] **Step 2: Add /check_quic section to README.md**

Insert after the `/check_tcp` section. Suggested content:

```markdown
### `/check_quic/{ip}/{port}`

Probes UDP reachability of a QUIC speaker. Sends a single QUIC long-header
packet using a grease version (RFC 9000 §15) and waits for the
RFC 9000 §6 Version Negotiation response. No QUIC handshake / TLS / SNI is
performed, so any RFC-compliant QUIC server (HTTP/3, TUIC, Hysteria, Naive,
…) responds.

- `ip`: hostname or IPv4/IPv6 literal.
- `port`: UDP port.
- `X-Timeout` header: integer seconds, default 3.

Returns OK (HTTP 200, code 0) when a valid VN response is received,
CRITICAL (HTTP 500, code 2) otherwise.

**Semantics — important.** This is a *reachability* probe, not a
*blockability* probe. It catches the common GFW QUIC blocking patterns
(wholesale UDP/443 drop, IP/port blocklist, long-header DPI). It cannot
detect handshake-content-based selective blocking (where a censor decrypts
the Initial packet and drops based on SNI / ALPN / version=v1) or
QoS / throttling.

Example:

    curl -i http://localhost:3000/check_quic/cloudflare-quic.com/443
```

- [ ] **Step 3: Build and start the binary for smoke testing**

Run in one terminal:

```bash
make && ./isius -l 0.0.0.0 -p 3000
```

- [ ] **Step 4: Smoke test — public QUIC service (positive)**

Run in a second terminal:

```bash
curl -i http://localhost:3000/check_quic/cloudflare-quic.com/443
```

Expected: HTTP 200, body `{"code":0,"metric":"duration:0.xxx","errors":[]}`.

- [ ] **Step 5: Smoke test — TUIC nodes (positive, real targets)**

Run:

```bash
curl -i http://localhost:3000/check_quic/32ru.cloudfrontcdn.com/4430
curl -i http://localhost:3000/check_quic/40ua.cloudfrontcdn.com/4430
```

Expected: both return HTTP 200 with `code:0`.

- [ ] **Step 6: Smoke test — port that does not speak QUIC (negative)**

Run:

```bash
curl -i http://localhost:3000/check_quic/1.1.1.1/9999
```

Expected: HTTP 500, body `{"code":2,...,"errors":["..."]}`. Should return within ~3s (default timeout), not hang.

- [ ] **Step 7: Smoke test — X-Timeout override**

Run:

```bash
time curl -i -H "X-Timeout: 1" http://localhost:3000/check_quic/1.1.1.1/9999
```

Expected: HTTP 500 within ~1s. Confirms `X-Timeout` overrides the 3s default.

- [ ] **Step 8: Smoke test — bad input (UNKNOWN path)**

Run:

```bash
curl -i http://localhost:3000/check_quic/cloudflare-quic.com/abc
```

Expected: HTTP 400, body `{"code":3,"metric":"bad request","errors":["could not parse port number: ..."]}`.

- [ ] **Step 9: Stop the dev binary**

In the first terminal: `Ctrl-C`.

- [ ] **Step 10: Final lint, fmt, test gate**

Run:

```bash
make fmt && make lint && make check
```

Expected: all clean, exit 0.

- [ ] **Step 11: Commit README**

```bash
git add README.md
git commit -m "docs: document /check_quic endpoint and its reachability semantics"
```

---

## Done criteria

- All 13 new tests pass alongside the 4 existing tests under `go test ./...`.
- `make fmt && make lint && make check` clean.
- `./isius` exposes `/check_quic/{ip}/{port}`, returns OK against
  `cloudflare-quic.com:443` and the two TUIC targets, returns CRITICAL
  against a non-QUIC port within `X-Timeout` (or 3s default).
- README documents the endpoint and explicitly calls out the
  reachability-vs-blockability distinction.
- No new entries in `go.mod`.

## Self-review checklist (run before handoff)

- Spec coverage: every requirement in the spec maps to a task — route
  shape (Task 7), default timeout (Tasks 7, 8), packet construction
  (Task 1), validation (Task 2), probe orchestration (Tasks 3–6),
  handler integration (Task 7), docs and limitations (Task 8). ✓
- Placeholder scan: every code block is complete; no TBD / TODO. ✓
- Type consistency: `udpDialer`, `udpConn`, `realUDPDialer`,
  `fakeUDPConn`, `fakeUDPDialer`, `echoVN`, `probeQUIC`,
  `buildVNTriggerPacket`, `validateVNResponse`, `handleCheckQUIC`,
  `quicTimeout`, `quicCIDLen`, `quicGreaseVersion`, `quicLongHeaderByte`,
  `quicTriggerPacketSize` — names used consistently across all tasks. ✓
