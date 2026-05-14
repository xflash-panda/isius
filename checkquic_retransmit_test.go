package main

import (
	"context"
	"errors"
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
	if dialer.calls() != 3 {
		t.Fatalf("expected 3 dial calls, got %d", dialer.calls())
	}
}

func TestProbeQUICContextAlreadyCancelledBeforeFirstAttempt(t *testing.T) {
	dialer := &multiAttemptFakeDialer{conns: []*fakeUDPConn{
		newGarbageConn(), newGarbageConn(), newGarbageConn(),
	}}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4430}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := probeQUIC(ctx, dialer, addr)

	if dialer.calls() != 0 {
		t.Fatalf("expected 0 dial calls with pre-cancelled ctx, got %d", dialer.calls())
	}
	if result.attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", result.attempts)
	}
	if len(result.errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.errs))
	}
	if !errors.Is(result.errs[0], context.Canceled) {
		t.Fatalf("expected Canceled, got %v", result.errs[0])
	}
}

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
