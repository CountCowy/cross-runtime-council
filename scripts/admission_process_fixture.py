#!/usr/bin/env python3
"""Test-only real process/barrier fixture; fixed temporary roots, no host runtime.

The trust-origin seam is replaced only inside this disposable server process.
Production admission, lease, request handler and server drain are unmodified.
"""

from pathlib import Path
import sys
import threading

import council


def main():
    root = Path(sys.argv[1]).resolve()
    if not str(root).startswith(("/private/tmp/", "/tmp/")):
        raise ValueError("temporary fixture root required")
    action = sys.argv[2]
    broker = council.CouncilBroker(root)
    cap = "process-fixture-capability-" + "a" * 40
    for name in ("alpha", "beta"):
        broker.bind(
            "codex",
            name,
            name,
            "fixture",
            target_thread_id="thread-" + name,
            binding_capability=cap,
        )
    broker.start("alpha", "beta", "Drain fixture", "Bounded accepted handler", [])
    release = threading.Event()
    original = getattr(broker, action)

    def paused(**arguments):
        print("accepted", flush=True)
        if not release.wait(8):
            raise TimeoutError("fixture release missing")
        result = original(**arguments)
        # A supported nested durable writer makes the after-handler bound
        # independently observable even when status itself has no work to do.
        broker.configure_router("completed-" + action)
        return result

    setattr(broker, action, paused)
    council.trusted_mcp_runtime = lambda *_: "codex"
    server = council.ThreadingUnixServer(
        str(root / "broker.sock"), council.BrokerRequestHandler
    )
    server.broker = broker
    serving = threading.Thread(target=server.serve_forever)
    serving.start()
    print("ready", flush=True)
    if sys.stdin.readline().strip() != "shutdown":
        raise ValueError("expected shutdown")
    server.shutdown()
    serving.join()
    print("acceptance-stopped", flush=True)
    closer = threading.Thread(target=server.server_close)
    closer.start()
    if sys.stdin.readline().strip() != "release":
        raise ValueError("expected release")
    release.set()
    closer.join(10)
    if closer.is_alive():
        raise TimeoutError("accepted handlers did not drain")
    broker.close()
    print("closed", flush=True)


if __name__ == "__main__":
    main()
