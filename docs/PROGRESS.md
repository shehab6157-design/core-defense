# Progress Log

## Phase 0 - Setup + threat model (done 2026-10-01)
- Dev VM: Ubuntu 24.04, Python 3.12, private repo
- Threat model v0.1 (T1-T16, R1-R10)
- T15: key-only SSH, password + root login disabled (verified: Permission denied)

## Phase 1 - Body
### Step 1 - Identities (done 2026-10-01)
- Private CA, per-component certificates (24h default, max 7 days), role in cert
- Blocks: forged CA, expired certs, role impersonation, path-trick names
- Keys stored mode 600, secrets/ excluded from git
- 11 tests passing
- Known gap: CA key unencrypted on dev VM -> fix in Phase 5 (T12)

### Step 2 - Signed messages (done 2026-10-01)
- Every message: sender certificate + signature + timestamp + one-time nonce
- Rejects: altered, forged (foreign CA / stolen cert without key), replayed,
  stale, impersonated, oversized, malformed, wrong role for message type
- Role rules: only brain sends proposals, only barrier sends facts
- 24 tests passing (T5 covered)

### Step 3 - Heartbeat monitor (done 2026-10-01)
- Signed heartbeats every 2s; silence > 6s raises ONE alert
- Measured (simulated): time-to-alert 6.5s after last heartbeat
- Forged heartbeats rejected + logged as evidence (T6 partial)
- Monotonic clock: changing system time cannot hide silence
- 31 tests passing

### Step 3b - Live ring demo (done 2026-10-01)
- 3 real arm processes, signed UDP heartbeats on localhost
- kill -9 on arm-02 at 12:41:30 -> both surviving arms alerted at 12:41:34
  (~4s after kill, 6.1s after last heartbeat), independently, no central server
- Fake "all clear" message rejected + logged as evidence
- Known gap: heartbeats signed but not encrypted yet (mTLS before multi-machine)

### Step 4 - Barrier (done 2026-10-01)
- Untrusted log lines -> strict typed facts (enums, numbers, IPs, known names, pseudonyms)
- No free text can cross: every value matches [a-z0-9_.:-]{1,64}
- Personal usernames/unknown processes/unknown hosts -> keyed pseudonyms
- T1 RESULT: 60 injection payloads (15 attacks x 4 placements, incl. zero-width
  and fullwidth unicode tricks) -> 60 flagged, 0 crossed as text
- 9 benign log lines -> 0 false alarms
- 114 tests passing

### Step 5 - Brain (done 2026-10-01)
- Proposes only; fixed allowlist (watch, collect_evidence, deploy_decoy, limit_access, isolate)
- Unsafe actions cannot even be constructed (tested: disable_monitoring, delete_logs, ...)
- isolate requires two INDEPENDENT sensors (host-log + ring); same log twice = one sensor
- Invalid facts treated as tampering evidence, never as input
- T1 END-TO-END: 60 attacks -> 60 evidence proposals, 0 harmful actions
- T2: arms keep detecting after brain dies (tested)
- 129 tests passing
