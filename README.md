# Core Defense

A security system that helps a small Linux network defend itself. I built it step by step in my own lab, on virtual machines I own, and tested every step with attacks on itself.

Each machine runs a small agent, called an arm in the code. The arms watch logs, network traffic and AI agent activity, warn each other, and can block an attacker with a real firewall rule. The main rule of the design is simple: no single signal is ever enough to cut a machine off. Two independent sensors have to agree first.

## What it does

- **Reads untrusted data safely.** Log lines are turned into strict facts before anything reads them, so text written by an attacker can never become an order.
- **Asks for two independent sensors.** Isolating a machine needs two different sensors to agree, for example the host logs and the network sensor. One sensor alone can only lead to a softer step.
- **Signs everything.** Every part has its own certificate, and every message is signed and checked. Forged, changed or replayed messages are refused and logged as evidence.
- **Keeps a record that cannot be quietly changed.** Every decision and action goes into a hash chained audit trail. Editing one entry breaks the chain at that entry.
- **Acts in small steps that can be undone.** Every action expires on its own unless it is renewed. A circuit breaker stops mass actions, and protected machines need a signed approval from the operator.
- **Keeps working under attack.** Arms send signed heartbeats to each other, so killing one arm raises an alarm on the others. Under heavy attack an arm drops to a survival mode that keeps only detection and evidence alive.
- **Learns, but only from safe sources.** It learns only from corrections signed by the operator, every new version must still catch every known attack, and old versions can be restored.
- **Plants decoys.** Fake targets that no real user ever touches. A touch on a decoy is near certain evidence of an attacker.

## Results from my lab

| Test | Result |
|---|---|
| 60 prompt injection attempts hidden in log lines | 0 got through as text, 0 harmful actions |
| Stolen brain key used to send 20 signed harmful orders | 0 carried out, 20 refusals recorded |
| An attack asking to isolate 20 machines at once | 3 carried out, 17 held, circuit breaker tripped |
| One arm killed with kill -9 | The two other arms raised the alarm about 4 seconds later, with no central server |
| A noisy simulated day with 303 raw alerts | 5 alerts shown to a person, and the real attack was one of them |
| Stolen key used to send 50 false corrections | The threshold moved by one step only, and 5 of 5 known attacks were still caught |
| Real nftables firewall test | Isolated machine lost all traffic except my management SSH, and the kernel lifted the block by itself when the timer ran out |
| Live SSH brute force from another virtual machine | Once two sensors agreed, the attacker was cut off with a real firewall rule while my own SSH connection stayed up |
| Hardened systemd service | Exposure score 1.2, or 1.5 with the firewall permission. Lower is safer, and typical services score above 9 |

The full story of every step, including the mistakes and fixes, is in [docs/PROGRESS.md](docs/PROGRESS.md). The threats it is built against are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## How it was built

| Phase | What was added |
|---|---|
| 0 | Threat model with 16 threats and 10 hardening rules |
| 1 | Identities and certificates, signed messages, heartbeats, the barrier that cleans log text, the brain that proposes actions, and sensors from [APIS](https://github.com/shehab6157-design/apis-lateral-movement-detector) and the [MCP Security Proxy](https://github.com/shehab6157-design/mcp-security-proxy) |
| 2 | Actions that expire and can be undone, a gate that checks every order, protected machines, the circuit breaker and the audit trail |
| 3 | Damage detection that works without signatures, alert triage, and sensitivity that rises during an attack and then cools down |
| 4 | Generic service banners, decoys chosen for each attacker, and a captured arm kept running as bait |
| 5 | Key rotation, an encrypted CA key, rebuilding an arm from a signed clean image, and survival mode |
| 6 | Safe learning from signed corrections, shared memory of confirmed attackers, and autonomy that has to be earned |
| 7 | A hardened systemd service on the real auth log, a real nftables firewall, and a live attack demo |

## Run the tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

456 tests, all passing.

## Run an arm on a lab machine

On an Ubuntu virtual machine you own, with certificates issued by your own lab CA in `secrets/`:

```bash
sudo bash install_arm.sh               # dry run, no firewall changes
sudo FIREWALL=1 bash install_arm.sh    # real nftables backend
```

The script installs the arm as a locked down systemd service with its own user. Read it first and set `MGMT` to your own management address, which is always allowed through the firewall.

## Folders

| Folder | What is inside |
|---|---|
| `ring/` | Identities, signed messages, heartbeats and key rotation |
| `barrier/` | Turns untrusted log text into strict facts |
| `brain/` | Reads facts, proposes actions, sorts alerts |
| `arms/` | Sensors, the gate, safety limits, the action executor, the nftables backend, decoy bait, and the APIS and MCP adapters |
| `audit/` | The hash chained audit trail |
| `disguise/` | Generic banners and decoys |
| `survival/` | Rebuild from a signed image, survival mode and last message on shutdown |
| `learning/` | Safe learning, attacker memory and earned autonomy |
| `service/` | The long running arm service |
| `tools/` | A lab tool that sends one signed message |
| `tests/` | The test suite |
| `docs/` | Threat model and progress log |

## Safety rules

- Lab only. It runs on machines I own and never acts on anything outside that network. There is no hack back.
- Decoys are passive and never hold real secrets.
- My management connection, the peer arms and loopback are always allowed through the firewall.
- Blocks live in timed kernel sets, so they end on their own even if the service dies.

## Limits

- This is a lab project, not a product. The live demo used two virtual machines.
- The firewall backend covers IPv4 only.
- Process and file sensors are adapters for now. Real auditd and inotify monitors are still to be built.
- The noisy day result is from simulated data. A test on real data is still to do.
- Messages between arms are signed but not yet encrypted, and the list of revoked arms is not yet shared between machines. Both are needed before running on more than one host.
- Certificate renewal is not automated in the service yet.
- A dashboard and a full write up are the next steps.

## Built by

Shehab Shibli, Network Engineering and Computer Security graduate.
[Portfolio](https://shehab6157-design.github.io), [GitHub](https://github.com/shehab6157-design) and [LinkedIn](https://www.linkedin.com/in/shehab-shibli)
