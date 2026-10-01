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
