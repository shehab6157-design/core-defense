# Threat Model - Core Defense (v0.1)

## 1. Scope and assumptions
- Lab only: Linux hosts on an isolated virtual network I own.
- The attacker knows exactly how this system is built (Kerckhoffs's principle).
- The attacker can: reach the network, gain root on ONE host, write text into
  logs/traffic the system reads, and run known EDR-killer techniques.
- The system never acts on machines outside my own environment (no hack-back).

## 2. Assets to protect
| Asset | Why it matters |
|---|---|
| Detection capability | If blinded, attacks go unseen |
| Response authority (isolate, revoke) | If abused, the system becomes a weapon against me |
| Signing keys (root of trust) | Whoever holds them can impersonate any component |
| Evidence and audit trail | Needed to investigate and to prove decisions |
| Baselines and learned models | If poisoned, attacks start to look normal |

## 3. Components and trust boundaries
| Component | Role | Trust level |
|---|---|---|
| Brain (coordinator) | Correlates, plans, PROPOSES actions only | Medium - never trusted alone |
| Barrier (reader) | Turns untrusted text into structured facts | Low - no permissions at all |
| Arms (host agents) | Sense and act locally, least privilege each | Medium - verified continuously |
| Ring (agent mesh) | Direct agent-to-agent messages and heartbeats | Every message must be signed |
| Network sensor (APIS) | Watches hosts from the outside | Medium - independent of hosts |
| Audit store | Hash-chained record of every decision | High - append-only, copied off-host |
| Operator (me) | Approves high-impact actions, corrects mistakes | High - strong authentication |

Trust boundaries: every arrow between components crosses one. Nothing is
trusted because of WHERE it comes from, only because of a valid signature.

## 4. Threats, defenses, tests
| ID | Threat | Defense (rule #) | Phase | How we test it |
|---|---|---|---|---|
| T1 | Prompt injection: attacker plants instructions in logs/traffic the brain reads | Barrier passes only structured facts; fixed action allowlist; injection text raised as attacker evidence (R4) | 1 | Inject 50+ payloads into logs, measure harmful actions (goal: 0) |
| T2 | Brain killed or its host compromised | Arms keep defending alone; brain silence = alert; brain cannot act without quorum (R5, R7) | 1 | Kill brain mid-attack, confirm detection continues |
| T3 | Arm killed on its host (EDR killer, kill -9, root) | Ring heartbeats: silence = alarm; network sensor keeps watching the host (R7) | 1 | Kill arm 10 times, measure time-to-alert |
| T4 | Arm captured, sends fake "all clear" reports | Per-arm identity (mTLS); arm behavior baselined by peers; network evidence cross-checks host claims; quorum (R1, R5) | 1-2 | Tamper an arm's reports, confirm mismatch is flagged |
| T5 | Forged, replayed, or intercepted ring messages | mTLS, signatures, nonce + timestamp; unsigned message = alert (R1) | 1 | Send forged and replayed messages, confirm rejection + alert |
| T6 | Attacker kills an arm and fakes its heartbeat | Challenge-response needs the arm's key; short-lived keys; network sensor cross-check (R1, R3) | 1, 5 | Fake heartbeats without key, confirm detection |
| T7 | Attacker triggers false alarms so the system isolates critical machines | Staged response, two-source quorum, protected assets need human approval, action rate limits, everything reversible (R5) | 2 | Trigger fake single-source alarms, confirm no strong action |
| T8 | Alert flooding to hide the real attack | Flood detection treats the flood itself as a signal | 3 | Generate floods, confirm real attack still surfaces |
| T9 | Slow baseline poisoning ("boiling frog") | Drift monitor; learning only in scheduled cycles | 3, 6 | Gradual poisoning run, confirm drift alert |
| T10 | Poisoned learning (attacker "teaches" wrong lessons) | Updates versioned, must pass full test suite, rollback; only operator-signed corrections (R10) | 6 | Inject bad training data, confirm update is rejected |
| T11 | Audit trail tampering | Hash chain + off-host copy (R9) | 1-2 | Edit a record, confirm chain break is detected |
| T12 | Signing key theft | Keys stored separately, short-lived, auto-rotated; old key use = alert (R3) | 5 | Use an expired key, confirm rejection + alert |
| T13 | Malicious or vulnerable dependency (supply chain) | Minimal, pinned dependencies with hashes; automated vulnerability scan (R8) | 0+ | Scan on every commit |
| T14 | Attacker detects decoys | Layered decoys; decoy probing itself logged as evidence | 4 | Probe decoys from Kali, confirm logging |
| T15 | Operator access stolen (SSH, dashboard) | Key-based SSH, no passwords; dashboard local-only; all actions logged | 0, 7 | Password login attempt must fail |
| T16 | Resource exhaustion of an arm or host | Resource limits; survival mode keeps detection + evidence alive (R7) | 5 | Stress host, confirm arm survives in minimal mode |

## 5. Residual risks (honest limits)
- An attacker with kernel-level control of a host CAN blind that host's arm.
  We do not prevent this; we detect it (T3) and keep watching from the network.
- Encrypted traffic content is not visible; only metadata is analysed.
- Hypervisor compromise, physical access, and full-network takeover are out of scope.
- Prompt injection is not "solved"; the goal is that it cannot cause harmful actions.

## 6. Phase 1 security requirements (must be true before Phase 1 is "done")
- [ ] Every component has its own identity and certificate
- [ ] Every ring message is signed and checked; unsigned = rejected + alert
- [ ] Brain can only propose actions from a fixed allowlist
- [ ] Barrier has no network or action permissions
- [ ] Heartbeat silence raises an alert within a measured time
- [ ] Tests for T1, T2, T3, T5 exist and pass
