# ATHP

ATHP is an agent harness protocol implementation with lifecycle, quarantine/recovery, idempotency, evidence-span logging, and RFC-0042 conformance tooling.

## Verification

```powershell
python athp/moon_base.py
python athp/conformance.py
```

The conformance suite writes certification reports under `athp/reports/`.

## Agent integration

Any coding agent can use the common client contract:

```python
from athp.client import ATHPClient, HttpTransport

client = ATHPClient("my-coding-agent", HttpTransport("http://127.0.0.1:8000/message"), secret)
client.register(["readonly_repo", "tests"])
client.heartbeat()
```

The CLI also supports `register`, `heartbeat`, and `shutdown` using
`ATHP_ENDPOINT`, `ATHP_AGENT_ID`, and `ATHP_SECRET` environment variables.

## Editable install

```powershell
python -m pip install -e .
athp --help
athp certify
```

For an in-process integration, use `athp.lib.Agent` with the certified
`athp.moon_base.Harness`.
