# ATHP RFC-0042 Certification Report

- Spec: RFC-0042 Agents Test Harness Protocol (draft v1.1)
- Harness: athp.moon_base (build digest `e8a6e819c51773b7cc0a051c77398fb6a345b4990feee102c92fa44d69a890bb`)
- Suite: `conformance.py`
- Conformance level claimed: **3** (wire + lifecycle + secure runtime)
- Generated: 2026-09-18T15:31:13.000Z
- Python: 3.12.10 (cpython)
- OS: win32
- Runner isolation: simulated (none)
- Aggregate manifest digest: `bd75f46db4349ad7ec54fe35786ffa6845a23eaff2d7fa4ee4876e3965736fe1`

## Summary

| Metric | Value |
| --- | --- |
| Total tests | 51 |
| Passed | 51 |
| Failed | 0 |
| MUST | 49/49 (100.0%) |
| SHOULD | 2/2 (100.0%) |

### Failures by severity

| Severity | Failures |
| --- | --- |
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |

### §7 Certification gates

| Gate | Status |
| --- | --- |
| zero_critical_high_failures | PASS |
| zero_security_policy_violations | PASS |
| must_100_percent | PASS |
| should_ge_95_percent | PASS |
| sla_declared | PASS |

## Conformance level coverage

### Level 1 - 15/15 passing

| Test ID | Req | Severity | Outcome | Detail |
| --- | --- | --- | --- | --- |
| ATHP-L1-001 | MUST | HIGH | PASS | REGISTER_OK version=1.1 |
| ATHP-L1-002 | MUST | MEDIUM | PASS | code=SCHEMA_INVALID |
| ATHP-L1-003 | MUST | MEDIUM | PASS | code=SCHEMA_INVALID |
| ATHP-L1-004 | MUST | LOW | PASS | accepted-with-extra=REGISTER_OK |
| ATHP-L1-005 | MUST | HIGH | PASS | REGISTER_OK sig=True heartbeat sig=True |
| ATHP-L1-006 | MUST | CRITICAL | PASS | code=AUTH_INVALID |
| ATHP-L1-007 | MUST | MEDIUM | PASS | stable=True arrays=True no-space=True raw-utf8=True |
| ATHP-L1-008 | MUST | MEDIUM | PASS | code=AUTH_INVALID |
| ATHP-L1-009 | MUST | MEDIUM | PASS | code=AUTH_REPLAY |
| ATHP-L1-010 | MUST | HIGH | PASS | selected=1.1 |
| ATHP-L1-011 | MUST | HIGH | PASS | code=VERSION_UNSUPPORTED state=REJECTED |
| ATHP-L1-012 | MUST | MEDIUM | PASS | selected=1.0 hb_ack=True |
| ATHP-L1-013 | MUST | MEDIUM | PASS | code=VERSION_UNSUPPORTED |
| ATHP-L1-014 | MUST | MEDIUM | PASS | shape=True no_secret=True session=True |
| ATHP-L1-015 | SHOULD | LOW | PASS | p50=0.0ms p95=16.0ms p99=16.0ms |
### Level 2 - 23/23 passing

| Test ID | Req | Severity | Outcome | Detail |
| --- | --- | --- | --- | --- |
| ATHP-L2-001 | MUST | HIGH | PASS | span_id=dec-fc3e45ad-62d4-4722-81fc-d3fbff04511c trigger=REGISTER_OK |
| ATHP-L2-002 | MUST | HIGH | PASS | rejected-span-present=True |
| ATHP-L2-003 | MUST | HIGH | PASS | status=SUCCEEDED states_seen=['EXECUTING', 'IDLE'] |
| ATHP-L2-004 | MUST | CRITICAL | PASS | state=QUARANTINED error=SANDBOX_VIOLATION |
| ATHP-L2-005 | MUST | HIGH | PASS | ok=True verified=True state=IDLE |
| ATHP-L2-006 | MUST | HIGH | PASS | error=SECRET_EXPOSURE escalated=ESCALATED |
| ATHP-L2-007 | MUST | HIGH | PASS | ok=True state=IDLE |
| ATHP-L2-008 | MUST | HIGH | PASS | ok=True state=SHUTDOWN |
| ATHP-L2-009 | MUST | HIGH | PASS | idle=True quarantined=True terminated=True |
| ATHP-L2-010 | MUST | HIGH | PASS | init=INIT quar=QUARANTINED codes=STATE_INVALID/STATE_INVALID |
| ATHP-L2-011 | MUST | HIGH | PASS | identical-cache=True type=REGISTER_OK |
| ATHP-L2-012 | MUST | HIGH | PASS | stored-replay=True status=SUCCEEDED |
| ATHP-L2-013 | MUST | HIGH | PASS | code=DUPLICATE_CONFLICT |
| ATHP-L2-014 | MUST | CRITICAL | PASS | code=STATE_INVALID state=QUARANTINED |
| ATHP-L2-015 | MUST | HIGH | PASS | same-session=True stored=1 |
| ATHP-L2-016 | MUST | HIGH | PASS | code=STATE_INVALID state=QUARANTINED |
| ATHP-L2-017 | MUST | HIGH | PASS | loaded-dedup=True replay-identical=True |
| ATHP-L2-018 | MUST | MEDIUM | PASS | fields=True stable=True spans=3 |
| ATHP-L2-019 | MUST | HIGH | PASS | state=QUARANTINED spans=1 trigger=HEARTBEAT_FAILURE |
| ATHP-L2-020 | MUST | MEDIUM | PASS | status=TIMED_OUT err=TASK_TIMEOUT state=IDLE |
| ATHP-L2-021 | MUST | MEDIUM | PASS | status=TIMED_OUT state=QUARANTINED reason=TASK_TIMEOUT |
| ATHP-L2-022 | MUST | HIGH | PASS | code=STATE_INVALID state=SHUTDOWN |
| ATHP-L2-023 | SHOULD | LOW | PASS | p95=0.0ms p99=16.0ms |
### Level 3 - 13/13 passing

| Test ID | Req | Severity | Outcome | Detail |
| --- | --- | --- | --- | --- |
| ATHP-L3-001 | MUST | CRITICAL | PASS | err=SANDBOX_VIOLATION state=QUARANTINED |
| ATHP-L3-002 | MUST | CRITICAL | PASS | err=EGRESS_DENIED state=QUARANTINED |
| ATHP-L3-003 | MUST | CRITICAL | PASS | err=SECRET_EXPOSURE state=QUARANTINED |
| ATHP-L3-004 | MUST | CRITICAL | PASS | err=SANDBOX_VIOLATION state=QUARANTINED |
| ATHP-L3-005 | MUST | HIGH | PASS | code=SANDBOX_VIOLATION state=IDLE (no execution) |
| ATHP-L3-006 | MUST | HIGH | PASS | code=SCHEMA_INVALID state=REJECTED |
| ATHP-L3-007 | MUST | HIGH | PASS | caps=['patch', 'tests', 'readonly_repo'] second=REGISTER_OK no-escalation=True |
| ATHP-L3-008 | MUST | CRITICAL | PASS | err=RESOURCE_LIMIT state=QUARANTINED |
| ATHP-L3-009 | MUST | MEDIUM | PASS | artifacts-verified=True |
| ATHP-L3-010 | MUST | HIGH | PASS | ok=False err=AUTH_INVALID state=QUARANTINED |
| ATHP-L3-011 | MUST | HIGH | PASS | health-gate=rejected-unhealthy-resume unhealthy-state=QUARANTINED resumed=IDLE |
| ATHP-L3-012 | MUST | HIGH | PASS | ok=True verified=True state=QUARANTINED span=None |
| ATHP-L3-013 | MUST | HIGH | PASS | state=IDLE exposure-evidence-kept=True |

## Declared SLA

Control-plane operations (register, heartbeat) are measured in-run.
SLA tests ATHP-L1-015 and ATHP-L2-023 assert p50/p95/p99 budgets;
results are recorded in the JSON report. SLA is declared satisfied
when both SLA tests pass and the p95 for each op is within budget.