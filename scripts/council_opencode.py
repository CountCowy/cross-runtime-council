#!/usr/bin/env python3
"""One-request OpenCode bridge for the local Council broker.

The OpenCode plugin owns exact-session metadata and all raw capabilities in
memory. This child carries one authenticated request over the local Unix socket;
it never persists or prints a capability outside its JSON response channel.
"""

import json
import sys
from typing import Any, Dict

from council import (
    MAX_LINE_BYTES,
    CouncilClient,
    CouncilError,
    CouncilRequestRejected,
)


def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
    if not raw or len(raw) > MAX_LINE_BYTES:
        print(json.dumps({"ok": False, "error": "bridge request is missing or too large"}))
        return 2
    try:
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise CouncilError("bridge request must be an object")
        action = request.get("action")
        arguments = request.get("arguments") or {}
        if not isinstance(action, str) or not isinstance(arguments, dict):
            raise CouncilError("bridge action or arguments are invalid")
        result = CouncilClient().request(action, **arguments)
        response: Dict[str, Any] = {"ok": True, "result": result}
    except CouncilRequestRejected as error:
        response = {"ok": False, "error": str(error), "error_kind": "rejected"}
    except (CouncilError, ValueError, TypeError, json.JSONDecodeError) as error:
        response = {"ok": False, "error": str(error), "error_kind": "error"}
    except Exception as error:
        response = {
            "ok": False,
            "error": "internal OpenCode bridge error: %s" % error,
            "error_kind": "internal",
        }
    print(json.dumps(response, separators=(",", ":"), ensure_ascii=False))
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
