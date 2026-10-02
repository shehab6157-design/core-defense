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

### Step 6 - Arms: APIS + MCP proxy adapters (done 2026-10-01)
- APIS arm: network sensor; alerts -> typed 'lateral_movement' facts (confidence 0-100)
- MCP arm: agent sensor; agent/tool names pseudonymized, free text never read,
  tier/signal consistency check rejects tampered records
- Brain fix: only SUSPICIOUS events count as sensor evidence (normal logs never do, T7)
- Four independent sensors: host-log, network, agent, ring
- Full attack chain test: brute force -> login -> hijacked agent -> lateral movement
  -> arm killed => watch, limit_access, then isolate confirmed by 2, 3, then 4 sensors
- 159 tests passing

## PHASE 1 COMPLETE (2026-10-01)
Open items carried forward:
- Barrier not yet OS-sandboxed (restricted user + systemd limits)
- Ring traffic signed but not encrypted (mTLS before multi-machine)
- CA key unencrypted on dev VM (Phase 5, T12)

## Phase 2 - Reflexes + Trust
### Step 2a - Action executor (done 2026-10-01)
- Every action reversible, expiring (isolate 10 min ... watch 1 h) unless renewed or pinned
- Plain-language explanations from fixed templates only (no input text)
- Escalate stronger-first-then-undo-weaker (no protection gap); never downgrade
- Dry-run backend only (no firewall changes yet)

### Step 2b - Quorum gate (done 2026-10-01)
- Arms run their OWN brain copy and verify every proposal before acting
- isolate needs 2+ claimed sensors confirmed locally; limit_access needs 1+
- Also checks: trusted brain, not replayed, valid proposal, responsible host
- RESULT: stolen brain key -> 20 signed harmful proposals -> 0 executed, 20 refusals logged

### Step 2c - Protected assets + circuit breaker (done 2026-10-01)
- Strong actions on protected hosts held for signed operator approval
- Max 3 strong actions / 10 min network-wide; breaker trips and stays tripped until operator reset
- Only trusted operator identity can approve/deny/reset; replays rejected
- RESULT: mass-isolation attack -> 20 requests -> 3 executed, 17 held, breaker tripped

### Step 2d - Tamper-evident audit trail (done 2026-10-01)
- Hash-chained append-only log (mode 600, fsync); edits/deletes/reorders detected at exact entry
- Truncation detected via anchor (head kept elsewhere) - honest limit documented + tested
- Gate, executor, safety layer wired via audited subclasses (tested logic unchanged)
- Full Phase 2 story audited: accept, stolen-key refusal, protected hold, operator approval, expiry
- Tamper demo: editing entry 3 to hide an attack -> chain breaks at entry 3
- 214 tests passing

## PHASE 2 CORE COMPLETE (2026-10-01)
Open items carried forward:
- Executor uses dry-run backend; real firewall backend (never locking out operator) still to build
- Audit anchor not yet shared with ring peers (truncation check needs an external head)

## Phase 3 - Innate immunity
### Step 3a - Damage detection / Danger Theory (done 2026-10-01)
- Damage signals independent of any CVE: server spawns shell (process sensor),
  account added to admin group (host logs), mass file changes (file sensor)
- Process + file sensor adapters: known names readable, others pseudonymized, malformed rejected
- 6 normal process patterns + normal file activity -> 0 false alarms
- ZERO-DAY STORY: no signature -> server spawns shell (limit_access) ->
  ransomware-like file burst (isolate, confirmed by process + file)

### Step 3b - Alert pheromones + tolerance (done 2026-10-01)
- Alert strength decays (half-life 10 min) unless reinforced; strong actions always shown
- Signed operator tolerance for low-level patterns only; damage/serious alerts never tolerable;
  tolerance never hides escalation; max 168 h
- Triage affects what the human sees only - never blocks a defensive action
- NOISY DAY (synthetic, seed 7): see test output for raw alerts -> pages, real attack paged
  (real-data evaluation still to do)
- FIX: show threshold 2.0 -> 1.5 (edge-of-threshold bug caught by tests). Noisy day: 303 raw -> 5 pages (98% less), attack paged

### Step 3c - Inflammation + fever (done 2026-10-02)
- Inflammation: host with active suspicious evidence uses lower thresholds (local, cools in 5 min)
- Fever: 3+ hosts in trouble -> network-wide lower thresholds for 15 min, then cools down
- Bounded: fixed floors, fever capped at 1 h + 30 min cooldown (attacker can't keep it hot forever)
- Two-sensor rule for isolate NEVER weakened (tested during fever)
- Same 3 failed logins: normal host -> 0 alerts, inflamed host -> 1
- Lesson: 2 test mistakes (inflaming via ring added a 2nd sensor) - brain correctly chose isolate; tests fixed
