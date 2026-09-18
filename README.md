# ATHP

ATHP is an agent harness protocol implementation with lifecycle, quarantine/recovery, idempotency, evidence-span logging, and RFC-0042 conformance tooling.

## Verification

```powershell
python athp/moon_base.py
python athp/conformance.py
```

The conformance suite writes certification reports under `athp/reports/`.
