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

## PHASE 3 COMPLETE (2026-10-02)
- Open: process/file sensors are adapters only (real auditd/inotify monitors still to build)
- Open: noisy-day result is synthetic; real-data evaluation still to do

## Phase 4 - Disguise
### Step 4a - Camouflage (done 2026-10-02)
- Real banners normalized to generic (no version/OS): "nginx/1.18.0 (Ubuntu)" -> "Server: web"
- Real host shows only the services it runs; everything else looks closed
- Bait hosts get a consistent personality per host, with that personality's own banners
- Fixes: SSH-2.0 is the required protocol id (test corrected); decoys now use their personality banners
- Policy engine only (passive); live socket wiring deferred to the demo

### Step 4b - Mimic: attacker-tailored decoys (done 2026-10-02)
- Decoy chosen by what each attacker hunts (credentials, remote access, admin, files, AI tools)
- Unique secret token per decoy; touch = near-certain evidence (new 'decoy' sensor)
- Internal toucher -> limit_access / isolate with 2nd sensor; outside toucher -> collect_evidence
- Caps: 3 per attacker, 50 total; allowlisted scanners ignored; decoys passive, no real secrets
- MIMIC STORY: lateral movement -> decoy server planted -> touched -> isolate (network + decoy)
- Note: per-attacker cap (3) can't be exceeded by today's fact types; mechanism tested with cap=2

### Step 4c - Captured arm as bait (done 2026-10-02)
- Capture detected when an arm reports 'clean' twice while 2 independent sensors see trouble
  (arm's own host logs never count as independent); or by signed operator quarantine
- Captured arm revoked (never trusted, even with valid cert) but left running as bait
- Attacker playbook recorded as type/size/time/digest only - no attacker text stored
- Clean replacement arm gets fresh identity (arm-02 -> arm-02-r1 -> arm-02-r2)

## PHASE 4 COMPLETE (2026-10-02)
- Open: camouflage/decoys are policy engines; live listeners deferred to the demo
- Open: revocation list is in-memory; must be shared across arms (ring) before multi-machine

## Phase 5 - Survival
### Step 5a - Short life: rotation + CA key protection (done 2026-10-02)
- Components renew when < 25% of cert life remains; replaced cert is RETIRED
- Retired key still time-valid but used -> refused + "retired-key-in-use" alarm (copied key)
- Expired key used -> "expired-key-in-use" alarm
- CA key encrypted with passphrase (12+ chars); wrong/missing passphrase refused (T12 partly closed)
- Real dev CA now encrypted; issuing asks for the passphrase

### Step 5b - Regeneration from signed image (done 2026-10-02)
- Release manifest (SHA-256 of every code file) signed by trusted operator
- Ring admission refuses modified / missing / unexpected code files
- Regeneration verifies the clean image first, restores files, moves unexpected
  files to .quarantine/ (evidence, never run), re-verifies before admission
- Planted symlinks replaced, never written through; path traversal rejected
- Limit: manifest signed with operator identity (max 7 days); production needs offline release key

### Step 5c - Tardigrade mode + last breath (done 2026-10-02)
- Survival mode on 2+ silent peers / 50+ rejected msgs per min / 90%+ load:
  keeps only detection, evidence, ring; exits only after 5 calm minutes (no flapping)
- Last breath: signed recent evidence sent to peers when stop is noticeable; sent once;
  peers validate every fact (smuggled facts rejected)
- REAL PROCESS TEST: SIGTERM -> last breath delivered and verified;
  SIGKILL -> nothing can be sent (honest limit) -> ring silence alarm covers it

## PHASE 5 COMPLETE (2026-10-02)
- Open: rotation/regeneration/survival are libraries; long-running arm service wiring still to build
- Open: release manifests use operator identity; offline release key for production

## Phase 6 - Learning (adaptive immunity)
### Step 6a - Safe learning from corrections (done 2026-10-03)
- Learns only from signed trusted-operator corrections; only during sleep (never fever/survival)
- One step per cycle, hard bounds (floors = inflammation floors); per-host settings
- Regression suite gate: any version that misses a known attack is refused
- Every version kept; rollback; correction flood (>20/cycle) capped + alarm
- STOLEN-KEY POISONING: 50 signed false-alarm corrections -> threshold 5 -> 6 only,
  1 adopted / 9 refused, 5/5 known attacks still detected

### Step 6b - Immune memory + vaccination (done 2026-10-03)
- Operator-confirmed incident addresses broadcast as signed memory; every arm recognizes them
- Only operator can create memories; expire (7 d default, 30 d max); bounded size
- Memory alone -> limit_access; memory + another sensor -> isolate
- Vaccination: confirmed attack -> permanent regression scenario
- RESULT: 3/3 arms recognize attacker after one broadcast; with a vaccine,
  learning stops at decoy threshold 75 instead of drifting to 85

### Step 6c - Earned autonomy (done 2026-10-03)
- Signed operator verdicts per executed action (each judged once)
- limit_access earns autonomy on protected hosts: 20+ correct, score 15+ (wrong = -5), clean last 10
- One wrong verdict revokes instantly; regained after 10 clean verdicts
- Hard limit: isolate on protected hosts never autonomous; breaker still applies to autonomous actions

## PHASE 6 COMPLETE (2026-10-03)
- Open: verdicts/corrections/memories are libraries; operator UI to send them comes in Phase 7

## Phase 7 - Face + proof
### Step 7a part 1 - Arm service (done 2026-10-03)
- One long-running process wiring ring, log tailer, barrier, memory, brain copy,
  gate, safety, executor (dry-run), audit trail, survival
- Log tailer follows auth.log from the end; handles rotation + truncation; caps endless lines
- Refuses to start with a missing or wrong identity; barrier salt created mode 600
- Tested: real log lines -> detection; signed proposal -> audited action; forged message
  rejected; operator memory -> known attacker in logs; silent peers -> survival mode
- LIVE: two services on real UDP sockets exchange signed heartbeats

### Step 7a part 2 - Hardened system service (done 2026-10-03)
- Runs as systemd service, own no-login user, CA key never copied, adm group for auth.log only
- Sandbox: read-only system, no capabilities, syscall filter, network limited to localhost + lab
- systemd-analyze security exposure: 1.2 OK (lower is safer; typical services score 9+)
- LIVE on real /var/log/auth.log: injection line -> collect_evidence; varied-port brute force ->
  watch -> limit_access
- REAL-SYSTEM FINDING: rsyslog collapses identical lines ("message repeated N times"),
  hiding failures; barrier now expands them (capped at 50). Verified live after fix.
- Open: certificate renewal not automated in the service yet (7-day identity, re-issue weekly)

### Step 7b part 1 - Real firewall backend (done 2026-10-03)
- nftables backend: isolate = drop all in/out; limit_access = drop new inbound;
  management + ring peers + loopback always allowed; acts only on own host; atomic ruleset
- Kernel-level dead-man switch: blocks live in TIMED kernel sets, auto-expire even if service dies
- LIVE TEST on dev VM: before ping OK -> isolate: 100% loss while SSH (management) stayed up,
  kernel set showed countdown -> after 120 s kernel lifted block itself, ping OK again
- Limits: IPv4 only; renewal does not yet extend kernel timer

### Step 7b part 2 - Real firewall in the running service (done 2026-10-03)
- Service uses real nftables when config enables it; one added permission (CAP_NET_ADMIN)
- Exposure score with firewall: 1.5 OK (1.2 without) - honest cost of the permission
- Renewals refresh the kernel timer; stopping the service never lifts a block (kernel timer does)
- LIVE FULL CHAIN on real system:
  brute force in real auth.log -> signed isolate proposal REFUSED (1 sensor, not corroborated)
  -> operator signed immune memory -> attacker's next attempt = 2nd sensor
  -> same proposal ACCEPTED -> real isolation (ping 100% loss, SSH stayed up)
  -> kernel lifted it after 180 s -> every decision in the hash-chained audit trail
- Lab tool tools/send.py signs one message as brain/operator (no special powers)

### Step 7c - Live Kali-style attack demo (done 2026-10-04)
- Setup: victim-01 (cloned Ubuntu, self-defending arm, REAL nftables) attacked by mcp-proxy
  over the lab network with real SSH brute force (sshpass loop; Kali VM files were missing)
- Victim detected brute force unaided: watch (brute-force) sensors=['host-log']
- Operator confirmed attacker (signed immune memory) -> known-attacker (memory sensor)
- Two independent sensors -> brain proposed isolate; one sensor alone -> only limit_access
- Signed brain proposal through the gate -> ACCEPTED -> real firewall block
- PROOF: attacker SSH went from instant "Permission denied" to timeout (exit code 124);
  operator SSH (192.168.109.1) stayed connected throughout; kernel auto-lifted the block
- Audit trail: action-started isolate + proposal-decision accepted, hash-chained

### Step 7c - Live network attack demo (done 2026-10-04)
- victim-01 (own hostname/IP/CA, self-defending arm, REAL nftables) attacked by mcp-proxy
  over the lab network with real SSH brute force (Kali VM files were missing; used sshpass loop)
- Victim detected brute force unaided: watch (brute-force) sensors=['host-log']
- Operator confirmed attacker (signed immune memory) -> known-attacker (memory sensor)
- Two sensors -> brain proposed isolate; one sensor alone -> only limit_access
- Signed proposal through gate -> ACCEPTED -> real firewall block
- PROOF: attacker SSH went instant "Permission denied" -> timeout (exit 124);
  operator SSH (192.168.109.1) stayed connected; kernel auto-lifted the block
- Audit: action-started isolate + proposal-decision accepted, hash-chained
