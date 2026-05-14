# check_quic Retransmit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/check_quic/{ip}/{port}` reliable enough as an external monitoring API by performing up to 3 sequential VN-trigger attempts internally, returning OK on any single success and CRITICAL only on full failure. The external contract (route, status codes, request shape) is unchanged; the metric string format gains `success:M,attempts:N,duration:X.XXX`.

**Architecture:** Five tasks build the retry incrementally. Task 1 refactors `probeQUIC`'s return type from `(time.Duration, error)` to a `quicProbeResult` struct (no behavior change). Tasks 2–4 add the loop, the inter-attempt gap, and per-attempt deadline arithmetic, each pinned by tests that fail before and pass after. Task 5 documents the new metric and runs the empirical 5-node × 10-round smoke battery to validate the false-negative reduction. The single-attempt body is extracted into `probeQUICAttempt`, called by `probeQUIC` in a loop with ctx-aware short-circuiting.

**Tech Stack:** Go 1.25, stdlib only (`net`, `crypto/rand`, `errors`, `bytes`, `context`, `time`, `fmt`, `sync`, `sync/atomic`), `github.com/gorilla/mux`. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-14-check-quic-retransmit-design.md](../specs/2026-05-14-check-quic-retransmit-design.md)

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `main.go` | modify | add `quicProbeAttempts`, `quicProbeAttemptDeadline`, `quicProbeAttemptGap` constants |
| `checkquic.go` | modify | add `quicProbeResult` type; split `probeQUIC` into outer loop + `probeQUICAttempt` helper; add `computeAttemptDeadline`; update `handleCheckQUIC` metric |
| `checkquic_test.go` | modify | adapt 4 existing `TestProbeQUIC*` tests to the new return type |
| `checkquic_retransmit_test.go` | new | retry-specific tests + `multiAttemptFakeDialer` helper |
| `README.md` | modify | document new `success:M,attempts:N` metric format |

`go.mod` / `go.sum` are NOT modified.

---

## Task 1: Return-type refactor (no behavior change)

**Files:**
- Modify: `main.go` (add 3 constants)
- Modify: `checkquic.go` (add `quicProbeResult` type, extract `probeQUICAttempt`, rewrite `probeQUIC` body, update `handleCheckQUIC` metric)
- Modify: `checkquic_test.go` (adapt 4 existing tests)

After this task: probeQUIC still does exactly one attempt per call, identical wire behavior to today. Only the Go-level return type changes (struct instead of two values) and the HTTP metric string changes (`success:1,attempts:1,duration:...` instead of `duration:...`).

- [ ] **Step 1: Add three constants to main.go**

In [main.go](../../../main.go), find the existing `const quicTimeout = 3 * time.Second` line and add three new constants directly after it:

```go
const quicTimeout = 3 * time.Second
const quicProbeAttempts = 3
const quicProbeAttemptDeadline = 800 * time.Millisecond
const quicProbeAttemptGap = 100 * time.Millisecond
```

- [ ] **Step 2: Adapt `TestProbeQUICSuccess` in `checkquic_test.go`**

Replace the existing test body so it matches the new return type. Find:

```go
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

Replace the call and assertions with:

```go
func TestProbeQUICSuccess(t *testing.T) {
	fc := &fakeUDPConn{onRead: echoVN}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result := probeQUIC(ctx, dialer, addr)
	if result.successes != 1 {
		t.Fatalf("expected 1 success, got %d (errs=%v)", result.successes, result.errs)
	}
	if result.rtt <= 0 {
		t.Fatalf("expected rtt > 0, got %v", result.rtt)
	}
}
```

- [ ] **Step 3: Adapt `TestProbeQUICInvalidResponse` in `checkquic_test.go`**

Replace the existing test body with:

```go
func TestProbeQUICInvalidResponse(t *testing.T) {
	fc := &fakeUDPConn{onRead: func([]byte) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03}, nil
	}}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result := probeQUIC(ctx, dialer, addr)
	if result.successes != 0 {
		t.Fatalf("expected 0 successes, got %d", result.successes)
	}
	if len(result.errs) == 0 {
		t.Fatal("expected at least one error")
	}
	last := result.errs[len(result.errs)-1]
	if !strings.Contains(last.Error(), "invalid") {
		t.Fatalf("expected last error to mention 'invalid', got %v", last)
	}
}
```

The "len(errs) == 0" check tolerates Tasks 2-4's future change from 1 attempt to 3 attempts (where errs grows from 1 to 3 entries).

- [ ] **Step 4: Adapt `TestProbeQUICTimeout` in `checkquic_test.go`**

Replace with:

```go
func TestProbeQUICTimeout(t *testing.T) {
	fc := &fakeUDPConn{readBlock: make(chan struct{})}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	result := probeQUIC(ctx, dialer, addr)
	elapsed := time.Since(start)

	if result.successes != 0 {
		t.Fatal("expected 0 successes on timeout")
	}
	if len(result.errs) == 0 {
		t.Fatal("expected at least one error")
	}
	last := result.errs[len(result.errs)-1]
	if !errors.Is(last, context.DeadlineExceeded) {
		t.Fatalf("expected last err DeadlineExceeded, got %v", last)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("probeQUIC did not honor deadline: elapsed %v", elapsed)
	}
}
```

- [ ] **Step 5: Adapt `TestProbeQUICCancelOnContextDone` in `checkquic_test.go`**

Replace with:

```go
func TestProbeQUICCancelOnContextDone(t *testing.T) {
	fc := &fakeUDPConn{readBlock: make(chan struct{})}
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan quicProbeResult, 1)
	go func() {
		done <- probeQUIC(ctx, dialer, addr)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case result := <-done:
		if result.successes != 0 {
			t.Fatal("expected 0 successes after cancel")
		}
		if len(result.errs) == 0 {
			t.Fatal("expected at least one error")
		}
		last := result.errs[len(result.errs)-1]
		if !errors.Is(last, context.Canceled) {
			t.Fatalf("expected last err Canceled, got %v", last)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("probeQUIC did not return promptly after ctx cancellation")
	}

	if !fc.closeCalled.Load() {
		t.Fatal("fake conn was not closed by probeQUIC")
	}
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `go test ./... -run TestProbeQUIC -v`

Expected: COMPILE ERROR (`probeQUIC` still returns `(time.Duration, error)`, not `quicProbeResult`).

- [ ] **Step 7: Add `quicProbeResult` type and rewrite `probeQUIC` in `checkquic.go`**

Find the existing `probeQUIC` function (around line 90 of `checkquic.go`). Above it, add the result type and a single-attempt helper. Replace `probeQUIC`'s body with a thin wrapper that calls the helper once:

```go
// quicProbeResult collects the outcome of one probeQUIC call, which may
// run up to quicProbeAttempts internal attempts. successes is 0 or 1
// (any single success short-circuits). attempts is how many attempts
// were actually made. rtt is the RTT of the successful attempt (zero
// when successes == 0). errs holds the per-attempt errors when an
// attempt failed; on full failure len(errs) == attempts.
type quicProbeResult struct {
	successes int
	attempts  int
	rtt       time.Duration
	errs      []error
}

// probeQUIC performs one external probe of addr. Internally it may run
// up to quicProbeAttempts VN-trigger attempts and short-circuits on the
// first valid Version Negotiation response.
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) quicProbeResult {
	rtt, err := probeQUICAttempt(ctx, dialer, addr)
	if err != nil {
		return quicProbeResult{successes: 0, attempts: 1, errs: []error{err}}
	}
	return quicProbeResult{successes: 1, attempts: 1, rtt: rtt}
}

// probeQUICAttempt performs exactly one VN-trigger send/recv cycle.
// Returns the wire RTT on success, or an error describing the failure.
// The function honors ctx for cancellation and ctx.Deadline (if set)
// for the socket deadline.
func probeQUICAttempt(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) (time.Duration, error) {
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

The body of `probeQUICAttempt` is identical to the body of today's `probeQUIC` (lines 93-150 of the current file). The new wrapper at top is the only behavioral entry point.

- [ ] **Step 8: Update `handleCheckQUIC` to use the new metric format**

Find `handleCheckQUIC` in `checkquic.go`. Locate the block:

```go
start := time.Now()
_, err = probeQUIC(ctx, realUDPDialer{}, udpAddr)
duration := time.Since(start)

if err != nil {
	outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
	return
}
outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
```

Replace with:

```go
start := time.Now()
result := probeQUIC(ctx, realUDPDialer{}, udpAddr)
duration := time.Since(start)

metric := fmt.Sprintf("success:%d,attempts:%d,duration:%f",
	result.successes, result.attempts, duration.Seconds())

if result.successes == 0 {
	outJSON(w, CRITICAL, metric, result.errs...)
	return
}
outJSON(w, OK, metric)
```

The `_, err = probeQUIC(...)` declaration above the block becomes invalid because `err` is no longer assigned. Make sure you delete the `_` and `err =` parts entirely, replacing with `result := probeQUIC(...)`.

- [ ] **Step 9: Run tests to verify they pass**

Run: `go test ./...`

Expected: all 18 tests pass (4 buildVN + 6 validateVN + 4 probeQUIC + 3 ping + 1 tcp).

- [ ] **Step 10: Run lint**

Run: `make fmt && make lint`

Expected: 0 issues.

- [ ] **Step 11: Commit**

```bash
git add main.go checkquic.go checkquic_test.go
git commit -m "refactor(check_quic): return quicProbeResult struct from probeQUIC"
```

---

## Task 2: Retry loop with short-circuit and ctx guard

**Files:**
- Modify: `checkquic.go` (rewrite the wrapper `probeQUIC` to loop)
- Create: `checkquic_retransmit_test.go` (multiAttemptFakeDialer + 3 tests)

After this task: probeQUIC loops up to `quicProbeAttempts` times, short-circuits on first success, checks ctx before each attempt. No inter-attempt gap yet (Task 3) and no per-attempt deadline math yet (Task 4) — each attempt still uses ctx.Deadline directly.

- [ ] **Step 1: Create `checkquic_retransmit_test.go` with multiAttemptFakeDialer + first three tests**

Create a new file `/Users/alex/code/go/xflash-panda/isius/checkquic_retransmit_test.go` with this content:

```go
package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// multiAttemptFakeDialer returns a sequence of pre-configured fakeUDPConn
// instances, one per DialUDP call. After the configured conns are exhausted
// it returns an error so the test fails loudly rather than silently reusing
// a closed conn.
type multiAttemptFakeDialer struct {
	mu    sync.Mutex
	conns []*fakeUDPConn
	index int
}

func (d *multiAttemptFakeDialer) DialUDP(_ string, _, _ *net.UDPAddr) (udpConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.index >= len(d.conns) {
		return nil, fmt.Errorf("multiAttemptFakeDialer: exhausted at index %d", d.index)
	}
	c := d.conns[d.index]
	d.index++
	return c, nil
}

func (d *multiAttemptFakeDialer) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.index
}

func newGarbageConn() *fakeUDPConn {
	return &fakeUDPConn{onRead: func([]byte) ([]byte, error) {
		return []byte{0x00, 0x01, 0x02, 0x03}, nil
	}}
}

func newEchoConn() *fakeUDPConn {
	return &fakeUDPConn{onRead: echoVN}
}

func TestProbeQUICAllAttemptsFail(t *testing.T) {
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{
		newGarbageConn(), newGarbageConn(), newGarbageConn(),
	}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := probeQUIC(ctx, dialer, addr)

	if result.successes != 0 {
		t.Fatalf("expected 0 successes, got %d", result.successes)
	}
	if result.attempts != quicProbeAttempts {
		t.Fatalf("expected %d attempts, got %d", quicProbeAttempts, result.attempts)
	}
	if len(result.errs) != quicProbeAttempts {
		t.Fatalf("expected %d errs, got %d (%v)", quicProbeAttempts, len(result.errs), result.errs)
	}
	if dialer.calls() != quicProbeAttempts {
		t.Fatalf("expected dialer called %d times, got %d", quicProbeAttempts, dialer.calls())
	}
}

func TestProbeQUICFirstFailsSecondSucceeds(t *testing.T) {
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{
		newGarbageConn(), newEchoConn(), newGarbageConn(),
	}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := probeQUIC(ctx, dialer, addr)

	if result.successes != 1 {
		t.Fatalf("expected 1 success, got %d (errs=%v)", result.successes, result.errs)
	}
	if result.attempts != 2 {
		t.Fatalf("expected 2 attempts (short-circuit on success), got %d", result.attempts)
	}
	if len(result.errs) != 1 {
		t.Fatalf("expected 1 err from the first failed attempt, got %d", len(result.errs))
	}
	if dialer.calls() != 2 {
		t.Fatalf("expected dialer called 2 times, got %d", dialer.calls())
	}
}

func TestProbeQUICEachAttemptUsesFreshSocket(t *testing.T) {
	c1 := newGarbageConn()
	c2 := newGarbageConn()
	c3 := newGarbageConn()
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{c1, c2, c3}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = probeQUIC(ctx, dialer, addr)

	for i, c := range []*fakeUDPConn{c1, c2, c3} {
		if !c.closeCalled.Load() {
			t.Fatalf("conn %d was not closed", i+1)
		}
	}
	// Sanity: the multi dialer was exhausted (index advanced to 3).
	if dialer.calls() != 3 {
		t.Fatalf("expected 3 dial calls, got %d", dialer.calls())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run "TestProbeQUICAllAttemptsFail|TestProbeQUICFirstFailsSecondSucceeds|TestProbeQUICEachAttemptUsesFreshSocket" -v`

Expected: All three FAIL — current `probeQUIC` only does one attempt, so:
- `AllAttemptsFail` will see `attempts=1` (want 3)
- `FirstFailsSecondSucceeds` will see `successes=0, attempts=1` (want successes=1, attempts=2)
- `EachAttemptUsesFreshSocket` will see only c1.closeCalled=true and a "multiAttemptFakeDialer: exhausted at index 1" error from the dialer the second time — wait, actually since only one attempt happens, only c1 is dialed and only c1.closeCalled becomes true. The test will fail on `c2 was not closed`.

- [ ] **Step 3: Replace the `probeQUIC` wrapper in `checkquic.go` with a loop**

Find the current wrapper added in Task 1:

```go
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) quicProbeResult {
	rtt, err := probeQUICAttempt(ctx, dialer, addr)
	if err != nil {
		return quicProbeResult{successes: 0, attempts: 1, errs: []error{err}}
	}
	return quicProbeResult{successes: 1, attempts: 1, rtt: rtt}
}
```

Replace it with:

```go
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) quicProbeResult {
	var result quicProbeResult
	for attempt := 1; attempt <= quicProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			result.attempts = attempt
			result.errs = append(result.errs, err)
			return result
		}
		rtt, err := probeQUICAttempt(ctx, dialer, addr)
		if err == nil {
			result.successes = 1
			result.attempts = attempt
			result.rtt = rtt
			return result
		}
		result.errs = append(result.errs, err)
	}
	result.attempts = quicProbeAttempts
	return result
}
```

Behavior:
- ctx already done before any attempt → returns immediately with that attempt counted, ctx.Err in errs.
- Any attempt succeeds → short-circuit, attempts = which attempt succeeded, errs has the prior failures only.
- All N attempts fail → attempts = N, errs has N entries.

- [ ] **Step 4: Run new tests to verify they pass**

Run: `go test ./... -run "TestProbeQUICAllAttemptsFail|TestProbeQUICFirstFailsSecondSucceeds|TestProbeQUICEachAttemptUsesFreshSocket" -v`

Expected: 3 PASS.

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `go test ./...`

Expected: all 21 tests pass (18 from before + 3 new). Pay special attention: `TestProbeQUICInvalidResponse` may now show `attempts=3` because each garbage attempt fails. The assertions written in Task 1 tolerate this (only check `successes==0` and "last err contains 'invalid'"). If a test fails unexpectedly, do NOT loosen the test — investigate whether the loop or guard logic is wrong.

- [ ] **Step 6: Run lint**

Run: `make fmt && make lint`

Expected: 0 issues.

- [ ] **Step 7: Commit**

```bash
git add checkquic.go checkquic_retransmit_test.go
git commit -m "feat(check_quic): retry up to 3 attempts, short-circuit on first success"
```

---

## Task 3: Inter-attempt gap

**Files:**
- Modify: `checkquic.go` (add gap between failed attempts)
- Modify: `checkquic_retransmit_test.go` (add 2 tests)

- [ ] **Step 1: Add the two gap tests to `checkquic_retransmit_test.go`**

Append to `checkquic_retransmit_test.go`:

```go
func TestProbeQUICAttemptGapHonored(t *testing.T) {
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{
		newGarbageConn(), newGarbageConn(), newGarbageConn(),
	}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_ = probeQUIC(ctx, dialer, addr)
	elapsed := time.Since(start)

	// Three attempts means two inter-attempt gaps. The fake conn returns
	// instantly so attempt time itself is negligible — the floor is just
	// 2 * gap.
	minExpected := 2 * quicProbeAttemptGap
	if elapsed < minExpected {
		t.Fatalf("expected elapsed >= %v (2 gaps), got %v", minExpected, elapsed)
	}
}

func TestProbeQUICShortCircuitsOnFirstSuccess(t *testing.T) {
	// Echo on first attempt; even though c2/c3 are also configured, they
	// must not be dialed and no gap should be applied.
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{
		newEchoConn(), newGarbageConn(), newGarbageConn(),
	}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	result := probeQUIC(ctx, dialer, addr)
	elapsed := time.Since(start)

	if result.successes != 1 {
		t.Fatalf("expected success on first attempt, got %d successes (errs=%v)", result.successes, result.errs)
	}
	if result.attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", result.attempts)
	}
	// Without any gap, this should be much faster than even one gap.
	if elapsed >= quicProbeAttemptGap {
		t.Fatalf("expected elapsed < %v (no gap on first success), got %v", quicProbeAttemptGap, elapsed)
	}
}
```

- [ ] **Step 2: Run tests to verify the gap test fails and short-circuit test passes**

Run: `go test ./... -run "TestProbeQUICAttemptGapHonored|TestProbeQUICShortCircuitsOnFirstSuccess" -v`

Expected:
- `TestProbeQUICAttemptGapHonored`: FAIL (no gap implemented yet, elapsed will be near zero).
- `TestProbeQUICShortCircuitsOnFirstSuccess`: PASS (loop already short-circuits).

- [ ] **Step 3: Add the inter-attempt gap to `probeQUIC` in `checkquic.go`**

Replace the `probeQUIC` body with:

```go
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) quicProbeResult {
	var result quicProbeResult
	for attempt := 1; attempt <= quicProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			result.attempts = attempt
			result.errs = append(result.errs, err)
			return result
		}
		rtt, err := probeQUICAttempt(ctx, dialer, addr)
		if err == nil {
			result.successes = 1
			result.attempts = attempt
			result.rtt = rtt
			return result
		}
		result.errs = append(result.errs, err)
		// Inter-attempt gap: not applied after a successful attempt
		// (we already returned above) and not after the last attempt
		// (no point sleeping when there is nothing more to do).
		if attempt < quicProbeAttempts {
			select {
			case <-ctx.Done():
				result.attempts = attempt
				result.errs = append(result.errs, ctx.Err())
				return result
			case <-time.After(quicProbeAttemptGap):
			}
		}
	}
	result.attempts = quicProbeAttempts
	return result
}
```

The gap is implemented with a `select` so ctx cancellation/deadline interrupts it promptly.

- [ ] **Step 4: Run gap tests to verify they pass**

Run: `go test ./... -run "TestProbeQUICAttemptGapHonored|TestProbeQUICShortCircuitsOnFirstSuccess" -v`

Expected: both PASS.

- [ ] **Step 5: Run full test suite**

Run: `go test ./...`

Expected: all 23 tests pass (21 + 2 new).

- [ ] **Step 6: Run lint**

Run: `make fmt && make lint`

Expected: 0 issues.

- [ ] **Step 7: Commit**

```bash
git add checkquic.go checkquic_retransmit_test.go
git commit -m "feat(check_quic): apply inter-attempt gap between failed retries"
```

---

## Task 4: Per-attempt deadline derived from ctx

**Files:**
- Modify: `checkquic.go` (add `computeAttemptDeadline`, use child ctx per attempt)
- Modify: `checkquic_retransmit_test.go` (add 2 tests)

After this task: each attempt's socket deadline is `min(quicProbeAttemptDeadline, fair_share_of_remaining_ctx)`. With default `quicTimeout = 3s`, attempts use the 800ms cap. With `X-Timeout: 1`, attempts share the 1s budget.

- [ ] **Step 1: Add the two deadline tests to `checkquic_retransmit_test.go`**

Append to `checkquic_retransmit_test.go`:

```go
func TestProbeQUICAttemptDeadlineCappedAtConstantWhenLoose(t *testing.T) {
	fc := newEchoConn()
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	beforeProbe := time.Now()
	_ = probeQUIC(ctx, dialer, addr)

	// With a loose ctx (10s) the per-attempt deadline must be capped at
	// quicProbeAttemptDeadline (800ms). The fake conn captures the most
	// recent SetDeadline call.
	deadlineSet := fc.deadline
	delta := deadlineSet.Sub(beforeProbe)
	if delta > quicProbeAttemptDeadline+50*time.Millisecond {
		t.Fatalf("expected per-attempt deadline ~%v, got %v from probe start", quicProbeAttemptDeadline, delta)
	}
	if delta < quicProbeAttemptDeadline-50*time.Millisecond {
		t.Fatalf("expected per-attempt deadline ~%v, got %v from probe start", quicProbeAttemptDeadline, delta)
	}
}

func TestProbeQUICAttemptDeadlineDerivedFromCtxWhenTight(t *testing.T) {
	fc := newEchoConn()
	dialer := &fakeUDPDialer{conn: fc}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	// 1s ctx budget. With 3 attempts and 2 gaps of 100ms each:
	//   per-attempt = (1s - 200ms) / 3 = 266ms
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	beforeProbe := time.Now()
	_ = probeQUIC(ctx, dialer, addr)

	deadlineSet := fc.deadline
	delta := deadlineSet.Sub(beforeProbe)
	expected := (1*time.Second - 2*quicProbeAttemptGap) / time.Duration(quicProbeAttempts)
	if delta > expected+50*time.Millisecond {
		t.Fatalf("expected per-attempt deadline ~%v (derived from tight ctx), got %v", expected, delta)
	}
	if delta < expected-50*time.Millisecond {
		t.Fatalf("expected per-attempt deadline ~%v (derived from tight ctx), got %v", expected, delta)
	}
}
```

Both tests use the single-conn `fakeUDPDialer` (not multiAttempt) because attempt 1 succeeds via echoVN — short-circuits before attempts 2/3.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./... -run "TestProbeQUICAttemptDeadline" -v`

Expected: Both FAIL. Currently `probeQUICAttempt` calls `conn.SetDeadline(d)` where `d = ctx.Deadline()`. With ctx=10s, `delta` will be near 10s (way over 800ms cap). With ctx=1s, `delta` will be ~1s (way over the 266ms fair share).

- [ ] **Step 3: Add `computeAttemptDeadline` and rewrite `probeQUIC` to use a child ctx per attempt**

In `checkquic.go`, add this helper above `probeQUIC` (after `quicProbeResult`):

```go
// computeAttemptDeadline returns how long the current attempt may run.
// It is the smaller of quicProbeAttemptDeadline and the parent ctx's
// fair share of remaining time, where "fair share" allocates the
// remaining wall clock budget equally across the attempts that have
// not yet started, after subtracting the inter-attempt gaps that
// would still be applied.
//
// If the parent ctx has no deadline, the constant cap is returned.
// If the computed share is non-positive (parent ctx already past its
// deadline), zero is returned and the caller should give up.
func computeAttemptDeadline(parent context.Context, currentAttempt int) time.Duration {
	if currentAttempt < 1 || currentAttempt > quicProbeAttempts {
		return 0
	}
	remainingAttempts := quicProbeAttempts - currentAttempt + 1
	d, ok := parent.Deadline()
	if !ok {
		return quicProbeAttemptDeadline
	}
	remainingGaps := time.Duration(remainingAttempts-1) * quicProbeAttemptGap
	budget := time.Until(d) - remainingGaps
	if budget <= 0 {
		return 0
	}
	share := budget / time.Duration(remainingAttempts)
	if share > quicProbeAttemptDeadline {
		return quicProbeAttemptDeadline
	}
	return share
}
```

Then replace `probeQUIC`'s body to use a child ctx per attempt:

```go
func probeQUIC(ctx context.Context, dialer udpDialer, addr *net.UDPAddr) quicProbeResult {
	var result quicProbeResult
	for attempt := 1; attempt <= quicProbeAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			result.attempts = attempt
			result.errs = append(result.errs, err)
			return result
		}
		attemptDeadline := computeAttemptDeadline(ctx, attempt)
		if attemptDeadline <= 0 {
			result.attempts = attempt
			result.errs = append(result.errs, context.DeadlineExceeded)
			return result
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptDeadline)
		rtt, err := probeQUICAttempt(attemptCtx, dialer, addr)
		cancel()
		if err == nil {
			result.successes = 1
			result.attempts = attempt
			result.rtt = rtt
			return result
		}
		result.errs = append(result.errs, err)
		if attempt < quicProbeAttempts {
			select {
			case <-ctx.Done():
				result.attempts = attempt
				result.errs = append(result.errs, ctx.Err())
				return result
			case <-time.After(quicProbeAttemptGap):
			}
		}
	}
	result.attempts = quicProbeAttempts
	return result
}
```

Important: `probeQUICAttempt` is unchanged. It uses `attemptCtx.Deadline()` (which is now the per-attempt deadline) for its socket deadline. The behavior of the existing inner code is correct as-is.

- [ ] **Step 4: Run deadline tests to verify they pass**

Run: `go test ./... -run "TestProbeQUICAttemptDeadline" -v`

Expected: both PASS.

- [ ] **Step 5: Run full test suite**

Run: `go test ./...`

Expected: all 25 tests pass (23 + 2 new).

- [ ] **Step 6: Run lint**

Run: `make fmt && make lint`

Expected: 0 issues.

- [ ] **Step 7: Commit**

```bash
git add checkquic.go checkquic_retransmit_test.go
git commit -m "feat(check_quic): derive per-attempt deadline from ctx, capped at constant"
```

---

## Task 5: README update + manual smoke + final lint

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the `## QUIC` section in `README.md`**

Find the existing `## QUIC` section in [README.md](../../../README.md). Replace its body (everything between `## QUIC` and the next section header or end of file) with:

```markdown
## QUIC

`/check_quic/{ip}/{port:[0-9]+}`

Sends up to 3 sequential QUIC long-header packets with a *grease* version
(RFC 9000 §15) and waits for the RFC 9000 §6 Version Negotiation response.
The probe short-circuits on the first valid VN response. No QUIC handshake,
TLS, or SNI is performed, so any RFC-compliant QUIC server (HTTP/3, TUIC,
Hysteria, Naive, ...) responds.

Default `X-Timeout` is 3 seconds. Internal retry parameters are fixed:
3 attempts, 800ms per-attempt deadline, 100ms inter-attempt gap. Per-attempt
deadlines automatically shrink so the total stays within `X-Timeout`.

```
% curl -v -H 'X-Timeout: 3' localhost:3000/check_quic/cloudflare-quic.com/443
> GET /check_quic/cloudflare-quic.com/443 HTTP/1.1
> X-Timeout: 3
>
< HTTP/1.1 200 OK
< Content-Length: 64
< Content-Type: text/plain; charset=utf-8
<
{"code":0,"metric":"success:1,attempts:1,duration:0.180432","errors":[]}
```

When at least one VN response is received, isius returns 200 OK and code 0.
The metric `success:M,attempts:N,duration:X.XXX` exposes how many of the
attempts succeeded and how many ran. On full failure, isius returns 500 and
code 2 with one error per failed attempt.

**Semantics — important.** This is a *reachability* probe, not a *blockability*
probe. Internal retries reduce false negatives caused by UDP packet loss
(empirically 50%+ on jittery proxy paths drops to <15%), but the probe still
catches the common GFW QUIC blocking patterns (wholesale UDP/443 drop,
IP/port blocklist, long-header DPI). It cannot detect handshake-content
selective blocking (where a censor decrypts the Initial packet and drops
based on SNI / ALPN / version=v1) or QoS / throttling.
```

- [ ] **Step 2: Build the binary**

Run: `make`

Expected: `./isius` binary built.

- [ ] **Step 3: Start the server in the background**

Run:

```bash
lsof -ti:3000 2>/dev/null | xargs kill 2>/dev/null
sleep 1
./isius -l 127.0.0.1 -p 3000 > /tmp/isius-rtsmoke.log 2>&1 &
echo $! > /tmp/isius-rtsmoke.pid
sleep 1
```

If port 3000 is in use, substitute a free port (e.g., 13000) below.

- [ ] **Step 4: Run the 5-node × 10-round smoke battery**

Run:

```bash
declare -a TARGETS=(
  "26ca.cloudfrontcdn.com:4430:CA"
  "22tr.cloudfrontcdn.com:4430:TR"
  "32ru.cloudfrontcdn.com:4430:RU"
  "33vn.cloudfrontcdn.com:4430:VN"
  "34id.cloudfrontcdn.com:4430:ID"
)
for target in "${TARGETS[@]}"; do
  host=$(echo "$target" | cut -d: -f1)
  port=$(echo "$target" | cut -d: -f2)
  name=$(echo "$target" | cut -d: -f3)
  echo "=== $name $host:$port ==="
  ok=0; fail=0
  for i in $(seq 1 10); do
    resp=$(curl -s -m 6 http://127.0.0.1:3000/check_quic/${host}/${port})
    code=$(echo "$resp" | grep -oE '"code":[0-9]+' | head -1 | cut -d: -f2)
    metric=$(echo "$resp" | grep -oE '"metric":"[^"]*"' | head -1)
    if [ "$code" = "0" ]; then
      ok=$((ok+1))
      printf "  R%-2d OK  %s\n" $i "$metric"
    else
      fail=$((fail+1))
      printf "  R%-2d FAIL %s\n" $i "$metric"
    fi
  done
  echo "  -> $ok/10 OK, $fail/10 FAIL"
  echo
done
```

Capture and report the actual numbers.

- [ ] **Step 5: Pass criteria**

Compare to the baseline single-attempt numbers from 2026-05-14 testing:

| Node | Single-attempt (baseline) | Required after retry |
|---|---|---|
| 22tr | 10/10 | 10/10 (no regression) |
| 33vn | 10/10 | 10/10 (no regression) |
| 26ca | 9/10 | ≥ 10/10 |
| 34id | 8/10 | ≥ 10/10 |
| 32ru | 5/10 | ≥ 9/10 |

If `32ru` does not improve to at least 9/10, do NOT modify the code to "fix" it — investigate first. The proxy path may be saturated; record the actual rate and proceed.

- [ ] **Step 6: Stop the server**

Run:

```bash
kill $(cat /tmp/isius-rtsmoke.pid) 2>/dev/null
rm -f /tmp/isius-rtsmoke.pid /tmp/isius-rtsmoke.log
```

- [ ] **Step 7: Run the final gate**

Run: `make fmt && make lint && make check`

Expected: all clean, exit 0.

- [ ] **Step 8: Commit**

```bash
git add README.md
git commit -m "docs(check_quic): document retry behavior and updated metric format"
```

---

## Done criteria

- All 25 tests pass under `go test ./...` (4 buildVN + 6 validateVN + 4 probeQUIC adapted + 7 retransmit-specific + 3 ping + 1 tcp).
- `make fmt && make lint && make check` clean.
- Smoke battery on 5 Tuic nodes shows the predicted false-negative reduction, with no regression on stable nodes.
- README documents the new metric format and notes the internal retry behavior.
- `go.mod` unchanged.

## Self-review checklist (run before handoff)

- **Spec coverage**: every spec requirement maps to a task — constants (Task 1), struct return type (Task 1), single-attempt extraction (Task 1), loop with short-circuit (Task 2), ctx guard before each attempt (Task 2), inter-attempt gap (Task 3), gap interruptible by ctx (Task 3), per-attempt deadline arithmetic (Task 4), child ctx per attempt (Task 4), handler metric format (Task 1), README docs (Task 5), smoke validation (Task 5). ✓
- **Placeholder scan**: every code block is complete; no TBD / TODO / "implement later". ✓
- **Type consistency**: `quicProbeResult{successes, attempts, rtt, errs}` — same field names used across Tasks 1, 2, 3, 4. `probeQUICAttempt` signature `(ctx, dialer, addr) (time.Duration, error)` — same across Tasks 1, 4. `computeAttemptDeadline(parent, currentAttempt) time.Duration` — defined and used only in Task 4. `multiAttemptFakeDialer` / `newGarbageConn` / `newEchoConn` — defined Task 2, reused in Tasks 3, 4. ✓
