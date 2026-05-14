package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakePinger struct {
	delay time.Duration
	calls int32
}

func (f *fakePinger) Ping(_ *net.IPAddr, _ time.Duration) (time.Duration, error) {
	atomic.AddInt32(&f.calls, 1)
	time.Sleep(f.delay)
	return 10 * time.Millisecond, nil
}

// TestProbePingReturnsPromptlyOnCancel proves that probePing should not keep
// running long after the parent context is cancelled. The buggy version fires
// off a worker goroutine that ignores ctx and keeps invoking the pinger.
func TestProbePingReturnsPromptlyOnCancel(t *testing.T) {
	f := &fakePinger{delay: 30 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_ = probePing(ctx, f, &net.IPAddr{}, 200, time.Millisecond, time.Second)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("probePing did not honor ctx cancellation: elapsed %v", elapsed)
	}
}

// TestProbePingNoCallAfterReturn proves that probePing must not leave a
// goroutine that continues to call the pinger after probePing has returned.
// In the buggy version, defer pinger.Close() in the handler would race with
// the still-running worker (use-after-close).
func TestProbePingNoCallAfterReturn(t *testing.T) {
	f := &fakePinger{delay: 20 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_ = probePing(ctx, f, &net.IPAddr{}, 200, time.Millisecond, time.Second)
	atReturn := atomic.LoadInt32(&f.calls)

	time.Sleep(300 * time.Millisecond)
	after := atomic.LoadInt32(&f.calls)

	if after != atReturn {
		t.Fatalf("pinger was called after probePing returned: %d -> %d (leaked goroutine, use-after-close risk)", atReturn, after)
	}
}

// TestProbePingCompletesAllOnNoCancel sanity-checks the happy path: when the
// context never fires, all count pings run and aggregate stats are correct.
func TestProbePingCompletesAllOnNoCancel(t *testing.T) {
	f := &fakePinger{delay: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := probePing(ctx, f, &net.IPAddr{}, 5, time.Millisecond, time.Second)
	if r.successes != 5 {
		t.Fatalf("expected 5 successes, got %d", r.successes)
	}
	if r.failures != 0 {
		t.Fatalf("expected 0 failures, got %d", r.failures)
	}
	if len(r.rtts) != 5 {
		t.Fatalf("expected 5 rtts, got %d", len(r.rtts))
	}
}
