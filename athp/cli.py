"""Small CLI for coding agents integrating with ATHP."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .client import ATHPClient, HttpTransport


def main() -> int:
    parser = argparse.ArgumentParser(description="ATHP agent client")
    parser.add_argument("command", choices=["register", "heartbeat", "shutdown", "evidence", "certify"])
    parser.add_argument("--endpoint", default=os.getenv("ATHP_ENDPOINT", "http://127.0.0.1:8000/message"))
    parser.add_argument("--agent-id", default=os.getenv("ATHP_AGENT_ID", "coding-agent.local"))
    parser.add_argument("--secret", default=os.getenv("ATHP_SECRET", "athp-moon-base-shared-secret-2026"))
    args = parser.parse_args()
    if args.command == "certify":
        from .conformance import main as certify_main
        return certify_main()
    if args.command == "evidence":
        print("Evidence export requires a connected harness session; use the Python API for remote sessions.")
        return 0
    client = ATHPClient(args.agent_id, HttpTransport(args.endpoint), args.secret.encode())
    response = getattr(client, args.command)()
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0 if response.get("message_type") not in {"ERROR", "REGISTER_REJECT"} else 1


if __name__ == "__main__":
    sys.exit(main())
