package main

import (
	"testing"
	"time"
)

// TestNewTCPDialerUsesMainTimeout pins the invariant that the TCP probe's
// dialer timeout equals the per-request mainTimeout (not the global
// monTimeout default). Regression guard for the prior `Timeout: monTimeout`
// typo, which made X-Timeout values larger than 300s silently capped.
func TestNewTCPDialerUsesMainTimeout(t *testing.T) {
	d := newTCPDialer(7 * time.Second)
	if d.Timeout != 7*time.Second {
		t.Fatalf("dialer.Timeout = %v, want 7s", d.Timeout)
	}
}
