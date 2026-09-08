#!/usr/bin/env python3
"""Disposable subprocess harness for unmodified frozen reader code, never live state.

Invocation is owned by test_predecessors.py. Only the passed copied fixture root
is mutable. The loaded reader's exact source/import identity is checked twice.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sys

sys.dont_write_bytecode = True


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(frozen, state, descriptor):
    expected = descriptor["reader"]["files"]
    for name, identity in expected.items():
        path = frozen / name
        if path.is_symlink() or digest(path) != identity["sha256"]:
            raise ValueError("frozen identity mismatch")
    sys.path.insert(0, str(frozen / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "council", frozen / "scripts/council.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["council"] = module
    spec.loader.exec_module(module)
    # The only injected production seams are a declared fixed clock and a
    # transport trap; validation, schemas and recovery stay authentic.
    module.epoch_now = lambda: descriptor["clock_epoch"]

    def no_transport(*_args, **_kwargs):
        raise AssertionError("frozen reader attempted transport")

    module.post_to_relay = no_transport
    socket.socket = no_transport
    result = {
        "constructor": "ok",
        "manifest_phases": {},
        "restore_error_count": 0,
        "corrupt_error_count": 0,
        "reader_errors": [],
        "relay_ready": False,
    }
    try:
        broker = module.CouncilBroker(state)
    except Exception as error:
        result.update(constructor="refused", error_type=type(error).__name__)
    else:
        if descriptor.get("mode") == "seed":
            for actor in ("alpha", "beta"):
                broker.bind(
                    "codex",
                    actor,
                    actor,
                    "historical-fixture",
                    target_thread_id="thread-" + actor,
                    binding_capability="historical-capability-" + actor * 12,
                )
            broker.start(
                "alpha",
                "beta",
                "Historical fixture",
                "Actual predecessor-produced state",
                [],
            )
        if (state / "router.json").exists():
            try:
                broker._router_config()
            except Exception as error:
                result["reader_errors"].append(type(error).__name__)
        if (state / "opencode-runtime.json").exists():
            result["pin_admitted"] = module._pinned_opencode_parent(
                "/fixture/opencode", state, None
            )
        if descriptor.get("case") == "extension-lost-ack":
            try:
                path = next((state / "dialogues").glob("dlg-*/manifest.json"))
                duplicate = broker.extend(
                    path.parent.name, "alpha", 1, extension_id="ext-frozen-lost-ack"
                )
                result["duplicate_extension"] = (
                    duplicate.get("duplicate") is True
                    and duplicate.get("authorized_rounds") == 2
                )
            except Exception:
                result["duplicate_extension"] = False
        if descriptor.get("case") == "stale-binding-generation":
            record = json.loads(
                next((state / "outbox/gamma").glob("*.json")).read_text()
            )
            try:
                broker.wake_ack(
                    "gamma",
                    record["envelope"]["message_id"],
                    record["wake_notification_id"],
                    "wake",
                    True,
                )
                result["stale_wake_rejected"] = False
            except module.CouncilError:
                result["stale_wake_rejected"] = True
        result["restore_error_count"] = len(broker.registration_restore_errors)
        result["corrupt_error_count"] = len(getattr(broker, "corrupt_file_errors", []))
        for route in broker.registrations.values():
            if route.get("runtime") in ("claude", "opencode") and (
                route.get("transport_ready") or route.get("_relay_capability")
            ):
                result["relay_ready"] = True
        for path in sorted((state / "dialogues").glob("dlg-*/manifest.json")):
            try:
                # Real public reader, plus actual submission read and final reader.
                manifest = broker.status(path.parent.name)
                result["manifest_phases"][path.parent.name] = manifest["phase"]
                for submission in (path.parent / "submissions").glob("*.json"):
                    broker._read_submission(
                        path.parent.name, "submissions/" + submission.name
                    )
                if manifest["phase"] == "complete":
                    module.completed_dialogue_report(state, path.parent.name)
            except Exception as error:
                result["reader_errors"].append(type(error).__name__)
    loaded = {}
    for name in ("council", "council_protocol"):
        helper = sys.modules.get(name)
        if helper is None:
            continue
        path = Path(helper.__file__).resolve()
        relative = str(path.relative_to(frozen))
        if relative not in expected or digest(path) != expected[relative]["sha256"]:
            raise ValueError("loaded helper identity mismatch")
        loaded[name] = expected[relative]["sha256"]
    result["loaded"] = loaded
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), json.load(sys.stdin))
