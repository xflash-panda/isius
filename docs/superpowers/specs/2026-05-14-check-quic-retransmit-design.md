# check_quic — Internal Retransmit for Stable External API

**Status:** Approved for implementation
**Date:** 2026-05-14
**Owner:** wwnice-max@outlook.com
**Predecessor:** [2026-05-14-check-quic-vn-probe-design.md](2026-05-14-check-quic-vn-probe-design.md)

## Goal

Make `/check_quic/{ip}/{port}` reliable enough to expose as a stable
external monitoring API. Today the endpoint is a single UDP send + recv,
which is vulnerable to UDP packet loss in a way TCP probes are not (TCP
gets free SYN retransmissions from the kernel; UDP does not). Empirical
data on Tuic CDN nodes through a transparent proxy showed single-shot
miss rates from 0% (stable nodes) up to 50% (jittery nodes). For a
public-facing monitoring API the caller must be able to "ask once, get a
reliable answer" rather than implement N-of-M sampling themselves.

## Non-Goals

- Do not expose `attempts` to callers (no path param, no header). The
  retransmit count and timing are internal implementation details. The
  external contract stays "single-target GET, OK or CRITICAL".
- Do not introduce a WARNING status. Reachability semantic: any one
  successful VN response means the node is reachable. WARNING would
  conflate "reachable with jitter" with "unreachable", which is the
  opposite of what callers need.
- Do not run probes concurrently across multiple sockets. Concurrent
  attempts force the probe to wait for the slowest reply rather than
  short-circuiting on the first success; sequential is faster on the
  happy path.
- Do not change the route or HTTP semantics. Status codes, response
  schema, `X-Timeout` header behavior all remain identical.

## Background — why retransmit

Empirical 10-round results against five Tuic nodes (proxy-relayed UDP):

| Node | Single-shot success | Predicted 3-attempt success |
|---|---|---|
| 22tr | 10/10 (100%) | 100% |
| 33vn | 10/10 (100%) | 100% |
| 26ca | 9/10 (90%) | 99.9% |
| 34id | 8/10 (80%) | 99.2% |
| 32ru | 5/10 (50%) | 87.5% |

The 50% miss on 32ru drops to ~12% with three independent attempts
(assuming independent loss). Real loss has some correlation, so the
actual improvement is somewhat lower, but the order-of-magnitude gain
holds across the range. The cost is at most three 1200-byte UDP sends
per probe — negligible compared to the operator value of fewer false
alarms.

TCP-style "free retransmission" is what `check_tcp` benefits from
implicitly. This change brings `check_quic`'s reliability into the
same envelope without changing its external contract.

## Design

### Probe behavior

`probeQUIC` performs up to N sequential attempts. Each attempt:

1. Opens a fresh UDP socket via `udpDialer.DialUDP`.
2. Generates fresh random DCID/SCID and sends one VN-trigger packet.
3. Sets a per-attempt deadline `quicProbeAttemptDeadline` (or earlier
   if the overall ctx deadline is closer).
4. Waits for one valid VN response.
5. Closes the socket.

Outcomes:

- **Any attempt succeeds**: short-circuit. Return `(success_count,
  attempts_used, total_rtt_from_first_send_to_first_success, nil)`.
- **All N attempts fail**: return `(0, N, total_elapsed,
  joinedErrors)`. The handler maps this to CRITICAL.
- **ctx cancelled mid-attempt**: stop, return `ctx.Err()`. Same cleanup
  discipline as today (close conn, drain reader goroutine, no goroutine
  outlives the call).

Inter-attempt gap of `quicProbeAttemptGap` between failed attempts
spreads probes across time so they are less correlated with bursty
loss. The gap is *not* applied after the last attempt nor after a
successful attempt (short-circuit beats it).

Fresh sockets per attempt: simpler than reusing one socket and
demultiplexing responses against multiple in-flight SCIDs. Three file
descriptors (briefly opened and closed sequentially) cost effectively
nothing.

### Constants

Add to [main.go](../../../main.go) next to the existing `quicTimeout`:

```go
const quicProbeAttempts        = 3
const quicProbeAttemptDeadline = 800 * time.Millisecond
const quicProbeAttemptGap      = 100 * time.Millisecond
```

Total worst-case duration: `3 × 800ms + 2 × 100ms = 2.6s`, which fits
within the 3s default `quicTimeout`. If a caller passes a smaller
`X-Timeout`, the per-attempt deadline shrinks proportionally so the
total stays within the caller's budget (see "Deadline arithmetic"
below).

Reasoning:
- **`attempts = 3`**: covers the bulk of the curve. Going to 5 would
  rescue 32ru-class nodes a bit further but adds 1.6s to worst-case
  latency. Three is the standard for this class of probe.
- **`attemptDeadline = 800ms`**: today's empirical max RTT through the
  proxy was ~344ms; 800ms gives ~2× headroom. Larger paths (intercontinental
  + heavy proxy chain) might need more, but those are exactly the cases
  where the caller can override `X-Timeout`.
- **`attemptGap = 100ms`**: short enough not to dominate the budget,
  long enough to dodge most micro-burst loss patterns.

### Deadline arithmetic

The per-attempt deadline is computed as:

```
attemptDeadline = min(
    quicProbeAttemptDeadline,
    (ctx.Deadline - now - remainingGaps) / remainingAttempts,
)
```

Where `remainingGaps = (remainingAttempts - 1) × quicProbeAttemptGap`.

This ensures:
- A normal call with default `quicTimeout = 3s` uses the constant
  800ms per attempt (3 × 800 + 2 × 100 = 2.6s ≤ 3s).
- A call with `X-Timeout: 1` shrinks per-attempt deadlines so the
  total stays ≤ 1s. Worst case ~266ms per attempt + 2 × 100ms gap ≈ 1s.
- A call with no deadline (theoretical; the handler always wraps with
  `WithTimeout`) falls back to `quicProbeAttemptDeadline`.

If the per-attempt deadline computes to ≤ 0 (caller passed an
absurdly short `X-Timeout`), the probe gives up immediately with
ctx.DeadlineExceeded — same behavior as today's single-attempt code.

### Internal API change

`probeQUIC` signature evolves from returning a single RTT to returning
a small result struct that carries success count and attempts used
(needed by the handler to format the new metric):

```go
type quicProbeResult struct {
    successes int           // 0 or 1; reserved for future >1 if needed
    attempts  int           // how many attempts were actually made
    rtt       time.Duration // RTT of the successful attempt (0 on failure)
    errs      []error       // per-attempt errors (len == attempts on full failure)
}

func probeQUIC(ctx context.Context, dialer udpDialer,
                addr *net.UDPAddr) quicProbeResult
```

`successes` is `int` (not `bool`) to keep the door open for "send N,
require ≥M success" semantics later without another signature change,
but for this change it is only ever 0 or 1.

The function returns the struct rather than `(quicProbeResult, error)`:
the per-attempt errors are *part of the result*, not a separate failure
mode. The handler decides OK vs CRITICAL based on `successes`.

### Handler change

[checkquic.go](../../../checkquic.go) `handleCheckQUIC`:

```go
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

Notes:
- The metric format becomes `success:M,attempts:N,duration:X.XXX`
  for both success and failure responses (failure has success:0).
  This is a backward-incompatible change to the metric string for
  any caller that parses it. Per the goal of this change being for
  a *new* external API, that's acceptable; the README will document
  the new format.
- Multiple per-attempt errors are passed to `outJSON` as the variadic
  `errors` arg, which already supports multiple entries. Each error
  appears in the response's `errors` array.

## Testing — TDD

New file [checkquic_retransmit_test.go](../../../checkquic_retransmit_test.go)
to keep retransmit-specific tests isolated from the existing
[checkquic_test.go](../../../checkquic_test.go) (which is already
~250 lines). Existing tests adapt to the new return type but keep
the same scenarios.

### Existing-test adaptations (in checkquic_test.go)

| Test | Change |
|---|---|
| `TestProbeQUICSuccess` | Assert `result.successes == 1`, `result.attempts == 1`, `result.rtt > 0`, `len(result.errs) == 0`. |
| `TestProbeQUICInvalidResponse` | Assert `result.successes == 0`, `result.attempts == 3`, `result.errs` has 3 entries each containing "invalid". |
| `TestProbeQUICTimeout` | Assert `result.successes == 0`, last err is `context.DeadlineExceeded`. |
| `TestProbeQUICCancelOnContextDone` | Assert ctx-cancel returns promptly, `fc.closeCalled` is true (still applies — applies to the *current* attempt's socket). May need to adapt to multi-socket model: assert that the *last* opened socket was closed. |

### New tests (in checkquic_retransmit_test.go)

`fakeUDPDialer` is enhanced (or a new `multiAttemptFakeDialer` is
introduced) to return a sequence of `fakeUDPConn` instances, one per
attempt. The test specifies behavior per attempt.

| Test | Scenario | Expected |
|---|---|---|
| `TestProbeQUICAllAttemptsSucceed` | First attempt succeeds | successes=1, attempts=1 (short-circuit) |
| `TestProbeQUICFirstFailsSecondSucceeds` | Attempt 1 returns garbage, attempt 2 echoes valid VN | successes=1, attempts=2, errs=[1 entry] |
| `TestProbeQUICAllAttemptsFail` | All 3 attempts return garbage | successes=0, attempts=3, errs=[3 entries] |
| `TestProbeQUICAttemptGapHonored` | All 3 fail with no Read latency | total elapsed ≥ 2 × 100ms (the two inter-attempt gaps) |
| `TestProbeQUICShortCircuitsOnFirstSuccess` | Attempt 1 succeeds quickly | total elapsed < 100ms (gap NOT applied after success) |
| `TestProbeQUICEachAttemptUsesFreshSocket` | Verify dialer is called exactly N times when all fail; each `fakeUDPConn` gets exactly one Write and one Read |
| `TestProbeQUICAttemptDeadlineDerivedFromCtx` | ctx with 1s deadline → per-attempt deadline ~266ms, not 800ms | observable via fake conn's stored deadline |

### Handler-level test

| Test | Scenario | Expected |
|---|---|---|
| `TestHandleCheckQUICMetricFormatOnSuccess` | Hit handler with mock probe returning successes=1, attempts=2 | response body matches `"metric":"success:1,attempts:2,duration:..."` |
| `TestHandleCheckQUICMetricFormatOnFailure` | Mock probe returning successes=0, attempts=3, 3 errs | code=2, metric `"success:0,attempts:3"`, errors array len 3 |

The handler test is new — none exists today, but the metric-format
change is the kind of contract change worth pinning. A small
refactor: extract the probe call as a function variable
`var probeFn = probeQUIC` in package scope so the handler test can
substitute a stub. Alternative: skip the handler test and rely on
manual smoke. **Decision: skip handler test for now**; the metric
format is exercised by smoke and the cost of the test stub
indirection is not worth one assertion.

### Manual smoke (final gate)

Re-run the 5-node × 10-round battery from today's session against the
deployed change. Pass criteria:

- 22tr / 33vn: 10/10 success (must not regress).
- 26ca / 34id: ≥ 10/10 success (improvement expected).
- 32ru: ≥ 9/10 success (large improvement expected; 50% → ~88% on
  paper, with three attempts most rounds should clear).

Record the actual numbers in the smoke section of the implementation
plan when done.

## Files touched

| File | Action |
|---|---|
| `main.go` | add three constants (`quicProbeAttempts`, `quicProbeAttemptDeadline`, `quicProbeAttemptGap`) |
| `checkquic.go` | new `quicProbeResult` type; rewrite `probeQUIC` to loop with deadline arithmetic; update `handleCheckQUIC` to format new metric |
| `checkquic_test.go` | adapt 4 existing `TestProbeQUIC*` tests to the new return type |
| `checkquic_retransmit_test.go` | new file: 6 retransmit-specific tests (+ multiAttemptFakeDialer helper) |
| `README.md` | update `## QUIC` section to document the new metric format |

`go.mod` unchanged.

## Pre-commit gates

`make fmt && make lint && make check` clean. Per CLAUDE.md: commits in
English, no Claude attribution.

## Out of scope (explicit)

- `attempts` / `gap` / `attemptDeadline` as caller-overridable
  parameters. If a power-user needs different values, that's a future
  follow-up; for now those are internal tuning knobs.
- WARNING status for partial success.
- Concurrent (parallel) attempts.
- Caching successful results between probes (would change semantics
  silently).
- Resolving multiple A records and trying each (most CDN edges return
  one IP).
- Per-IP-family attempt mixing (e.g., trying both v4 and v6 for a
  hostname). The probe sticks with whatever `parseIP` returns.
