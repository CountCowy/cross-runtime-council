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

PACKAGE_ID = "4873bbfab7e79c82e81c9c123bade7b7011ee22ba5b5ec3488eb26725e624d54"
RUNTIME_COHORT = "e5eed435bb8e236e619eb86e6834789f5bc3e055526219263d72c095c43139b0"
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
