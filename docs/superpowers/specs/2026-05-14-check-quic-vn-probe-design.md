# check_quic — QUIC Version Negotiation Reachability Probe

**Status:** Approved for implementation
**Date:** 2026-05-14
**Owner:** wwnice-max@outlook.com

## Goal

Add a single-target HTTP endpoint to `isius` that probes whether a remote
host is reachable on UDP with a QUIC-speaking service, by triggering a
RFC 9000 §6 Version Negotiation (VN) response. The endpoint mirrors the
shape and semantics of `/check_tcp` so the upstream monitoring system can
treat QUIC reachability the same way it treats TCP reachability.

## Non-Goals

- Not a full QUIC handshake. We do not perform Initial-packet AEAD or
  TLS 1.3 ClientHello. The probe deliberately does not exercise the
  TLS / ALPN / SNI path of any real QUIC service.
- Not a QUIC throughput, congestion, or 0-RTT test.
- Not a batch endpoint. The codebase has no batch precedent and the
  decision (2026-05-14) is to keep `check_quic` single-target like
  every other probe in `isius`. Upstream callers parallelize across
  N HTTP requests, same as for `/check_tcp`.

## Background — why VN probing

For a "is QUIC reachable?" check, the practical alternatives are:

1. **Full QUIC handshake** via `quic-go`: accurate, but expensive
   (~1–5ms CPU + 50–100KB memory + per-connection goroutines + UDP
   socket lifecycle), and requires a non-trivial dependency. Overkill
   for a reachability probe.

2. **VN trigger** (this design): send one UDP datagram shaped as a
   QUIC long-header packet with a *grease* version
   (`0x?a?a?a?a` per RFC 9000 §15). RFC-compliant servers MUST respond
   with a Version Negotiation packet because they do not recognize the
   version. Cost: one UDP send + one UDP recv. No TLS, no crypto,
   no connection state, no third-party dependency.

The probe answers the question "is the remote endpoint a reachable QUIC
speaker?". It does **not** answer "would a real QUIC v1 ClientHello
succeed?" — see *Known limitations* below.

## Design

### Route

```
GET /check_quic/{ip}/{port:[0-9]+}
```

Registered in `main.go` next to the existing `/check_tcp` route so the
`mount-api-on` prefix and accesslog wrapping behave identically.

### Inputs

| Source | Name | Type | Default | Notes |
|---|---|---|---|---|
| Path | `ip` | string | (required) | Hostname or IPv4/IPv6 literal. Resolved via `parseIP`. |
| Path | `port` | int | (required) | UDP port. |
| Header | `X-Timeout` | int seconds | `quicTimeout = 3s` | Whole-probe deadline including DNS, send, recv. |

A new package-level constant `quicTimeout = 3 * time.Second` lives next
to `pingTimeout` / `monTimeout` in `main.go`. Rationale: VN is one RTT,
so 3s comfortably covers up to a 1.5s round-trip plus DNS, while
avoiding the existing 300s `monTimeout` default that would let blocked
probes hold connections open for five minutes under fan-out load.

### Probe protocol

Outgoing packet — fixed 1200 bytes (RFC 9000 §14.1 anti-amplification
floor):

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 1 | First byte | `0xc0` (long header form + fixed bit + Initial type) |
| 1 | 4 | Version | `0x1a2a3a4a` (grease, RFC 9000 §15) |
| 5 | 1 | DCID Length | `0x08` |
| 6 | 8 | DCID | `crypto/rand` random |
| 14 | 1 | SCID Length | `0x08` |
| 15 | 8 | SCID | `crypto/rand` random |
| 23 | 1177 | Padding | `0x00` |

Response validation — all conditions must hold:

1. Received at least 7 bytes (first byte + version field).
2. First byte high bit (`0x80`) set — long header form.
3. Bytes 1–4 are all zero — VN packet identifier (RFC 9000 §17.2.1).
4. The DCID echoed in the VN response equals the SCID we sent
   (RFC 9000 §17.2.1: server swaps DCID/SCID when responding).

Any failure → `CRITICAL` with an error string explaining which check
failed. This filters ICMP errors and stray UDP packets from being
mistaken for a successful probe.

### Network selection

Mirrors `checkping.go`: after `parseIP` resolves the host, inspect the
resulting IP string for `:` to decide `udp4` vs `udp6`. Hostnames
resolve to IPv4 (per `parseIP`'s default).

### Response shape

Reuses the existing `outJSON` / `userErrorJSON` helpers — output
schema is identical to `/check_tcp`:

| Outcome | HTTP | `code` | `metric` | `errors` |
|---|---|---|---|---|
| VN response received and valid | 200 | 0 (OK) | `duration:0.xxx` | [] |
| Timeout / invalid response / network error | 500 | 2 (CRITICAL) | `duration:0.xxx` | [<reason>] |
| Malformed request (bad port, etc.) | 400 | 3 (UNKNOWN) | `bad request` | [<reason>] |

### Internal structure

`checkquic.go` exports only `handleCheckQUIC`. Internals split for
testability:

```go
// Pure: builds the 1200-byte VN-trigger packet.
func buildVNTriggerPacket(dcid, scid []byte) []byte

// Pure: validates a received datagram against the SCID we sent.
func validateVNResponse(packet, sentSCID []byte) error

// IO: sends the packet, waits for a valid response, returns RTT.
// The probe deadline comes from ctx.Deadline() (the handler wraps
// r.Context() with WithTimeout, which makes a separate timeout param
// redundant).
func probeQUIC(ctx context.Context, dialer udpDialer,
                addr *net.UDPAddr) (time.Duration, error)

// Interfaces for test injection.
type udpDialer interface { ... }
type udpConn interface { ... }
```

`probeQUIC`'s goroutine model follows the same discipline as
`probePing` (see `checkping_test.go`) — it must return promptly on
context cancellation and must not leave a goroutine that touches the
conn after `probeQUIC` returns.

### No third-party dependency

The probe uses only `net`, `crypto/rand`, `encoding/binary`, `errors`,
`fmt`, `time`, `context`. `go.mod` is not modified. No `quic-go`.

## Testing — TDD

Test file `checkquic_test.go`. Layered to maximize deterministic
coverage of the protocol-shaped logic.

### Layer 1 — packet construction (pure)

| Test | Verifies |
|---|---|
| `TestBuildVNTriggerPacketLength` | output is exactly 1200 bytes |
| `TestBuildVNTriggerPacketHeader` | first byte == `0xc0` |
| `TestBuildVNTriggerPacketVersion` | bytes 1–4 == `0x1a2a3a4a` (grease pattern) |
| `TestBuildVNTriggerPacketCIDs` | DCID/SCID length prefixes and contents at correct offsets |

### Layer 2 — response validation (pure)

| Test | Input | Expected |
|---|---|---|
| `TestValidateVNResponseValid` | well-formed VN with DCID == sent SCID | nil |
| `TestValidateVNResponseTooShort` | 5 bytes | error |
| `TestValidateVNResponseNotLongHeader` | first byte high bit clear | error |
| `TestValidateVNResponseNonZeroVersion` | version field == `0x00000001` | error |
| `TestValidateVNResponseDCIDMismatch` | DCID != sent SCID | error |

### Layer 3 — `probeQUIC` with fake `udpConn`

Pattern follows `fakePinger` in `checkping_test.go`:

| Test | Scenario | Expected |
|---|---|---|
| `TestProbeQUICSuccess` | fake conn returns valid VN | RTT > 0, no error |
| `TestProbeQUICTimeout` | fake conn Read blocks past deadline | error contains "timeout" |
| `TestProbeQUICInvalidResponse` | fake conn returns garbage | error contains "invalid" |
| `TestProbeQUICCancelOnContextDone` | ctx cancelled mid-Read | returns promptly, no goroutine touches conn after return |

### Layer 4 — manual smoke (not in CI)

Run after implementation:

```bash
./isius -l 0.0.0.0 -p 3000

# Public QUIC service
curl -i http://localhost:3000/check_quic/cloudflare-quic.com/443

# TUIC nodes (TUIC sits on RFC-compliant QUIC, so VN must work)
curl -i http://localhost:3000/check_quic/32ru.cloudfrontcdn.com/4430
curl -i http://localhost:3000/check_quic/40ua.cloudfrontcdn.com/4430

# Negative — port that does not speak QUIC
curl -i http://localhost:3000/check_quic/1.1.1.1/9999

# X-Timeout override
curl -i -H "X-Timeout: 1" http://localhost:3000/check_quic/40ua.cloudfrontcdn.com/4430
```

CI does not run live UDP probes — flaky and bandwidth-dependent.

### TDD order

Layer 1 → Layer 2 → Layer 3 → wire up `handleCheckQUIC` and route →
manual smoke. Each test red before green.

## Files touched

| File | Action | Notes |
|---|---|---|
| `checkquic.go` | new | handler + helpers + interfaces |
| `checkquic_test.go` | new | Layer 1–3 tests |
| `main.go` | edit | add `quicTimeout` const; register `/check_quic/{ip}/{port}` route next to `/check_tcp` |
| `README.md` | edit | document `/check_quic/{ip}/{port}` and the VN-reachability semantics |

`go.mod` / `go.sum` unchanged.

## Pre-commit gates

`make fmt && make lint && make check` must pass with no warnings.
Per CLAUDE.md: commit messages in English, no Claude attribution.

## Known limitations — must be documented in README

The probe detects QUIC reachability at the network layer. It catches
the GFW blocking patterns that matter in practice (wholesale UDP/443
drop, IP/port blocklist, long-header DPI), which is the bulk of
real-world QUIC blocking. It cannot detect:

- **Selective handshake-content blocking.** A GFW that decrypts the
  Initial packet to inspect SNI / ALPN / version=v1 and drops the real
  handshake while letting grease versions through will produce a false
  OK. This pattern requires significant decryption cost and is not
  common in observed GFW behavior against QUIC, but it is theoretically
  possible.
- **Throttling / QoS.** If the remote works but is rate-limited, the
  probe will report OK — same blind spot as a full-handshake probe.

The endpoint documentation must state that this is a *reachability*
probe, not a *blockability* probe.

## Out of scope (explicit)

- Tunable VN parameters (version, DCID length, padding size) — not
  exposed as path or query params. If needed later, add a separate
  endpoint variant rather than overloading this one.
- Batch endpoint — see *Non-Goals*.
- IPv6 hostname resolution preference — `parseIP` keeps its current
  IPv4-first behavior for hostnames; bare IPv6 literals work because
  they contain `:`.
