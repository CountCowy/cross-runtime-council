#!/usr/bin/env python3
"""One-request OpenCode bridge for the local Council broker.

The OpenCode plugin owns exact-session metadata and all raw capabilities in
memory. This child carries one authenticated request over the local Unix socket;
it never persists or prints a capability outside its JSON response channel.
"""

import json
import sys
sys.dont_write_bytecode = True
# ruff: noqa: E402 -- custom imports must follow bytecode-write suppression.
from typing import Any, Dict

import council

from council import (
    MAX_LINE_BYTES,
    CouncilClient,
    CouncilError,
    CouncilRequestRejected,
)

PACKAGE_ID = "fdf7ec2fbe4d9198c16b7b578d3b92f46265d421d2634e36820db07197cd2622"
RUNTIME_COHORT = "8181ae63906b42e4af670df1613dede4d194c48991594e3b8ea9b961877831b5"
if RUNTIME_COHORT != council.RUNTIME_COHORT:
    raise RuntimeError("Council bridge/helper cohort mismatch; refresh the complete runtime set")



def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
    if not raw or len(raw) > MAX_LINE_BYTES:
        print(json.dumps({
            "ok": False, "error": "bridge request is missing or too large",
            "error_kind": "error",
            "reason": "request_too_large" if raw else "invalid_request",
        }))
        return 2
    try:
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise CouncilError("bridge request must be an object")
        action = request.get("action")
        arguments = request.get("arguments") or {}
        if not isinstance(action, str) or not isinstance(arguments, dict):
            raise CouncilError("bridge action or arguments are invalid")
        origin = request.get("runtime_cohort")
        if origin != RUNTIME_COHORT:
            raise CouncilError("Council plugin/bridge cohort mismatch", reason="version_mismatch")
        result = CouncilClient(origin_cohort=origin).request(action, **arguments)
        response: Dict[str, Any] = {"ok": True, "result": result}
    except CouncilRequestRejected as error:
        response = {
            "ok": False, "error": str(error), "error_kind": "rejected",
            "reason": error.reason,
        }
        if error.commit_status == "precommit":
            response["commit_status"] = "precommit"
    except (CouncilError, ValueError, TypeError, json.JSONDecodeError) as error:
        response = {
            "ok": False, "error": str(error),
            "error_kind": error.error_kind if isinstance(error, CouncilError) else "error",
            "reason": error.reason if isinstance(error, CouncilError) else "invalid_request",
        }
    except Exception as error:
        response = {
            "ok": False,
            "error": "internal OpenCode bridge error: %s" % error,
            "error_kind": "internal",
            "reason": "internal",
        }
    print(json.dumps(response, separators=(",", ":"), ensure_ascii=False))
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
