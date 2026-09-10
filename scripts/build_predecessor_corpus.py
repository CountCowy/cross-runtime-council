#!/usr/bin/env python3
"""Developer-only generator of disposable C1 state fixtures (never live state).

The committed corpus, exact historical readers and independent runner are the
CI inputs. Regeneration requires the source test fixtures, not any installation.
"""

import hashlib
import itertools
import json
from pathlib import Path
import tempfile
import uuid
from unittest import mock

import council
from test_council import (
    CAP_ALPHA,
    CAP_BETA,
    CAP_GAMMA,
    TEST_CLAIM_ID_SALT,
    proposal,
    multi_exchange,
    synthesis,
    representation_check,
    convergence_challenge,
)

ROOT = Path(__file__).resolve().parent / "fixtures/predecessors"
NOW = 2000000000


def main():
    objects = {}
    cases = {}
    counter = itertools.count(1)
    with (
        tempfile.TemporaryDirectory(prefix="c1-corpus-") as directory,
        mock.patch("council.epoch_now", return_value=NOW),
        mock.patch("council.utc_now", return_value="2033-05-18T03:33:20+00:00"),
        mock.patch(
            "council.uuid.uuid4", side_effect=lambda: uuid.UUID(int=next(counter))
        ),
        mock.patch("council.new_claim_id_salt", return_value=TEST_CLAIM_ID_SALT),
        mock.patch("council.secrets.token_hex", return_value="cd" * 16),
        mock.patch(
            "council.secrets.SystemRandom.shuffle",
            side_effect=lambda values: values.sort(),
        ),
    ):
        root = Path(directory) / "state"

        def capture(name, phase=None, disposition="preserve", tags=()):
            files = {}
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.name == "broker.lock":
                    continue
                data = path.read_text()
                digest = hashlib.sha256(data.encode()).hexdigest()
                objects[digest] = data
                files[str(path.relative_to(root))] = digest
            cases[name] = {
                "files": files,
                "expected_phase": phase,
                "disposition": disposition,
                "tags": list(tags),
            }

        def bind_all(broker, names):
            for name, cap in zip(names, (CAP_ALPHA, CAP_BETA, CAP_GAMMA)):
                broker.bind(
                    "codex",
                    name,
                    name.title(),
                    "test",
                    target_thread_id="thread-" + name,
                    binding_capability=cap,
                )

        with council.CouncilBroker(root) as broker:
            names = ("alpha", "beta", "gamma")
            bind_all(broker, names)
            broker.configure_router("fixture-router")
            capture(
                "router-configured-unbound", tags=("configuration", "registrations")
            )
            broker.router_bind("fixture-router", CAP_ALPHA)
            capture("router-bound", tags=("configuration",))
            dialogue = broker.start(
                "alpha",
                peer=None,
                peers=["beta", "gamma"],
                topic="Frozen reader fixture",
                brief="All seven submission kinds",
                premises=[],
                rounds=1,
                minimum_rounds=1,
                max_rounds=3,
            )["dialogue_id"]
            capture(
                "triad-proposals",
                "collecting_proposals",
                tags=("dialogue", "triad", "pending"),
            )
            beta_claim = broker.wait("beta")["message"]
            broker.pending_wakes()
            capture(
                "claimed-and-wake-leased",
                "collecting_proposals",
                tags=("claimed", "wake"),
            )
            for name in names[:-1]:
                broker.submit(dialogue, name, "proposal", 0, proposal(name))
                if name == "beta":
                    broker.ack("beta", beta_claim["message_id"])
            activation_error = RuntimeError("fixture activation suppressed")
            try:
                with mock.patch.object(
                    broker, "_activate_transition", side_effect=activation_error
                ):
                    broker.submit(
                        dialogue, names[-1], "proposal", 0, proposal(names[-1])
                    )
            except RuntimeError as error:
                if error is not activation_error:
                    raise
            else:
                raise AssertionError("commit-before-activation fixture did not stop")
            committed = broker._load_manifest(dialogue)["committed_transition_id"]
            staged = [
                council.read_json(path)
                for path in broker.outbox.glob("*/*.json")
                if council.read_json(path).get("status") == "staged"
            ]
            if not staged or any(
                record.get("transition_id") != committed for record in staged
            ):
                raise AssertionError(
                    "commit-before-activation fixture is not bound to the committed transition"
                )
            capture(
                "staged-after-commit",
                "collecting_exchange",
                disposition="recover",
                tags=("outbox", "staged_after"),
            )
            with broker.changed:
                broker._activate_transition(dialogue, committed)
            capture(
                "triad-exchange",
                "collecting_exchange",
                tags=("proposal", "acknowledged"),
            )
            for name in names:
                broker.submit(
                    dialogue, name, "exchange", 1, multi_exchange(name, names, True)
                )
            capture(
                "triad-challenge",
                "collecting_convergence_challenge",
                tags=("exchange",),
            )
            for name in names:
                broker.submit(
                    dialogue, name, "convergence_challenge", 1, convergence_challenge()
                )
            capture(
                "triad-synthesis",
                "collecting_synthesis",
                tags=("convergence_challenge",),
            )
            broker.submit(dialogue, "alpha", "synthesis", 1, synthesis())
            capture(
                "triad-representation",
                "collecting_representation_check",
                tags=("synthesis",),
            )
            broker.submit(
                dialogue,
                "beta",
                "representation_check",
                1,
                representation_check(False, ["Correct the material transport claim."]),
            )
            broker.submit(
                dialogue, "gamma", "representation_check", 1, representation_check()
            )
            capture(
                "triad-revision",
                "collecting_synthesis_revision",
                tags=("representation_check",),
            )
            broker.submit(dialogue, "alpha", "synthesis_revision", 1, synthesis())
            capture(
                "triad-revision-check",
                "collecting_revision_check",
                tags=("synthesis_revision",),
            )
            for name in names[1:]:
                broker.submit(
                    dialogue, name, "revision_check", 1, representation_check()
                )
            capture(
                "triad-complete",
                "complete",
                tags=("revision_check", "final", "terminal_envelope"),
            )
            # The exact selected inert namespace is ignored by old readers. It
            # intentionally makes no journal/recoverer compatibility claim.
            marker = root / ".council-lifecycle/admission.json"
            marker.parent.mkdir()
            marker.write_text(
                json.dumps(
                    {
                        "format": 1,
                        "namespace_version": 1,
                        "roots": {
                            "state": "/fixture/state",
                            "payload": "/fixture/payload",
                            "opencode": "/fixture/opencode",
                        },
                        "status": "uninstalled",
                        "transaction_id": None,
                        "committed": None,
                    }
                )
            )
            capture("inert-lifecycle-uninstalled", "complete", tags=("lifecycle",))
            marker.unlink()
            marker.parent.rmdir()
            # Completed-data deletion is captured both before and after cleanup.
            original = broker._complete_tombstoned_deletion
            with mock.patch.object(broker, "_complete_tombstoned_deletion"):
                broker.delete_terminal_dialogue(dialogue, "fixture deletion")
            capture(
                "interrupted-tombstone-deletion",
                disposition="delete",
                tags=("tombstones", "interrupted_deletion"),
            )
            original(dialogue)
            capture("deleted", disposition="delete", tags=("tombstones",))
        # Each following family starts from a real current dyad, copied from
        # independently named checkpoints rather than modified old source.
        import shutil

        shutil.rmtree(root)
        with council.CouncilBroker(root) as broker:
            names = ("alpha", "beta")
            bind_all(broker, names)
            dialogue = broker.start(
                "alpha",
                "beta",
                "Dormant fixture",
                "Retained state",
                [],
                rounds=1,
                minimum_rounds=1,
                max_rounds=3,
                stop_on_convergence=False,
            )["dialogue_id"]
            capture("dyad-proposals", "collecting_proposals", tags=("dyad", "dialogue"))
            for name in names:
                broker.submit(dialogue, name, "proposal", 0, proposal(name))
            capture(
                "dormant-awaiting-extension",
                "collecting_exchange",
                tags=("dormant", "awaiting_extension"),
            )
            broker.extend(dialogue, "alpha", 1, extension_id="ext-frozen-lost-ack")
            capture("extension-lost-ack", "collecting_exchange", tags=("extension",))
            broker.cancel(dialogue, "alpha", "fixture cancellation")
            capture(
                "cancellation-lost-ack", "cancelled", tags=("cancelled", "superseded")
            )

        # Declare perturbations independently. Old constructor outcomes are
        # checked by the runner and never used to manufacture expected values.
        def variation(base, name, transform, disposition, tags):
            item = dict(cases[base])
            files = {path: objects[digest] for path, digest in item["files"].items()}
            transform(files)
            item["files"] = {}
            for path, text in files.items():
                digest = hashlib.sha256(text.encode()).hexdigest()
                objects[digest] = text
                item["files"][path] = digest
            item.update(disposition=disposition, tags=list(tags))
            cases[name] = item

        def alter_json(files, path, **updates):
            value = json.loads(files[path])
            value.update(updates)
            files[path] = json.dumps(value)

        def first(files, suffix):
            return next(path for path in files if path.endswith(suffix))

        variation(
            "triad-complete",
            "audit-torn-tail",
            lambda files: files.update(
                {
                    first(files, "audit.jsonl"): files[first(files, "audit.jsonl")]
                    + '{"unfinished":'
                }
            ),
            "recover",
            ("audit", "torn_tail"),
        )
        variation(
            "triad-complete",
            "audit-missing-newline",
            lambda files: files.update(
                {
                    first(files, "audit.jsonl"): files[
                        first(files, "audit.jsonl")
                    ].rstrip()
                }
            ),
            "recover",
            ("audit", "missing_newline"),
        )
        variation(
            "dyad-proposals",
            "unknown-dialogue-schema",
            lambda files: alter_json(
                files, first(files, "manifest.json"), dialogue_schema_version=999
            ),
            "unsupported",
            ("unknown_schema",),
        )
        variation(
            "dyad-proposals",
            "corrupt-manifest",
            lambda files: files.update({first(files, "manifest.json"): '{"broken":'}),
            "unsupported",
            ("malformed",),
        )
        variation(
            "dyad-proposals",
            "legacy-generation-missing",
            lambda files: files.update(
                {
                    "registrations/alpha.json": json.dumps(
                        {
                            k: v
                            for k, v in json.loads(
                                files["registrations/alpha.json"]
                            ).items()
                            if k not in ("binding_generation", "runtime_cohort")
                        }
                    )
                }
            ),
            "legacy_registration",
            ("registrations", "legacy"),
        )
        variation(
            "dyad-proposals",
            "expired-registration",
            lambda files: alter_json(
                files, "registrations/alpha.json", lease_expires_epoch=NOW - 1
            ),
            "expired_registration",
            ("registrations", "expired"),
        )
        variation(
            "dyad-proposals",
            "duplicate-route",
            lambda files: alter_json(
                files, "registrations/beta.json", target_thread_id="thread-alpha"
            ),
            "route_error",
            ("registrations", "duplicate"),
        )
        variation(
            "dyad-proposals",
            "malformed-registration",
            lambda files: files.update({"registrations/alpha.json": "{"}),
            "route_error",
            ("registrations", "malformed"),
        )
        for runtime in ("claude", "opencode"):

            def relay(files, runtime=runtime):
                alter_json(
                    files,
                    "registrations/beta.json",
                    runtime=runtime,
                    transport="claude_mcp_child_relay"
                    if runtime == "claude"
                    else "opencode_plugin_relay",
                    relay_path="/private/tmp/c1-frozen-never-connect.sock",
                    relay_pid=2147483647,
                    relay_process_start_epoch=1,
                    relay_owner_hash="b" * 64,
                    target_session_id="fixture-session",
                )

            variation(
                "dyad-proposals",
                runtime + "-dead-relay",
                relay,
                "relay_tombstone",
                ("registrations", runtime, "dead", "unknown"),
            )
        for name, config, disposition in (
            ("retention-off", None, "preserve"),
            ("retention-on", {"days": 30}, "preserve"),
            ("retention-malformed", {"days": "invalid"}, "constructor_refuses"),
        ):
            if config is not None:
                variation(
                    "dyad-proposals",
                    name,
                    lambda files, config=config: files.update(
                        {"retention.json": json.dumps(config)}
                    ),
                    disposition,
                    ("configuration", "retention"),
                )
            else:
                cases[name] = dict(
                    cases["dyad-proposals"], tags=["configuration", "retention"]
                )
        for name, config in (
            (
                "opencode-pin",
                {
                    "runtime": "opencode",
                    "executable": "/fixture/opencode",
                    "sha256": "a" * 64,
                    "cdhash": "b" * 40,
                    "configured_at_epoch": NOW,
                },
            ),
            ("opencode-pin-malformed", {"executable": False}),
        ):
            variation(
                "dyad-proposals",
                name,
                lambda files, config=config: files.update(
                    {"opencode-runtime.json": json.dumps(config)}
                ),
                "preserve",
                ("configuration", "opencode_pin"),
            )
        # Independent outbox recovery families derived from an activated transition.
        # The commit-before-activation case above is captured at its real crash seam.
        for name, status in (
            ("delivered-lost-ack", "delivered"),
            ("attention", "needs_attention"),
        ):

            def outbox(files, status=status):
                path = next(
                    path
                    for path in files
                    if path.startswith("outbox/")
                    and json.loads(files[path])["envelope"]["kind"]
                    == "proposal_request"
                )
                alter_json(files, path, status=status)

            variation("triad-exchange", name, outbox, "recover", ("outbox", status))

        def staged_before(files):
            path = next(path for path in files if path.startswith("outbox/"))
            alter_json(files, path, status="staged", transition_id="tx-never-committed")

        variation(
            "dyad-proposals",
            "staged-before-commit",
            staged_before,
            "recover",
            ("outbox", "staged_before"),
        )

        def orphan(files):
            complete = cases["triad-complete"]["files"]
            final = next(path for path in complete if path.endswith("final.json"))
            manifest = first(files, "manifest.json")
            files[manifest.replace("manifest.json", "final.json")] = objects[
                complete[final]
            ]

        variation(
            "triad-revision-check",
            "orphan-final",
            orphan,
            "orphan_final",
            ("orphan_final",),
        )

        def audit_intent(files):
            path = first(files, "manifest.json")
            value = json.loads(files[path])
            value["pending_audit_events"] = {
                "fixture-pending": [
                    {
                        "event": "fixture_event",
                        "details": {"fixture": True, "audit_id": "fixture-pending"},
                    }
                ]
            }
            files[path] = json.dumps(value)

        variation(
            "dyad-proposals",
            "pending-audit-intent",
            audit_intent,
            "recover",
            ("pending_audit",),
        )

        def retention_expired(files):
            alter_json(
                files,
                first(files, "manifest.json"),
                completed_at="2033-01-01T00:00:00+00:00",
            )
            files["retention.json"] = json.dumps({"days": 30})

        variation(
            "triad-complete",
            "retention-expired-terminal",
            retention_expired,
            "delete",
            ("retention", "interrupted_retention"),
        )
        cases["retention-expired-terminal"]["expected_phase"] = None

        def lifecycle_variant(files, status="committed", version=1):
            marker = ".council-lifecycle/admission.json"
            value = json.loads(files[marker])
            receipt = '{"fixture_only":true}\n'
            value.update(
                namespace_version=version,
                status=status,
                transaction_id="fixture-pending"
                if status == "recovery_required"
                else None,
                committed={
                    "receipt_id": "fixture",
                    "receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
                    "package_id": "a" * 64,
                    "runtime_cohort": council.RUNTIME_COHORT,
                },
            )
            files[marker] = json.dumps(value)
            files[".council-lifecycle/v1/receipts/fixture.json"] = receipt

        variation(
            "inert-lifecycle-uninstalled",
            "inert-lifecycle-committed",
            lifecycle_variant,
            "preserve",
            ("lifecycle",),
        )
        variation(
            "inert-lifecycle-uninstalled",
            "inert-lifecycle-pending",
            lambda files: lifecycle_variant(files, "recovery_required"),
            "preserve",
            ("lifecycle",),
        )
        variation(
            "inert-lifecycle-uninstalled",
            "unknown-lifecycle-format",
            lambda files: lifecycle_variant(files, version=2),
            "unsupported",
            ("unknown_namespace",),
        )
        variation(
            "dyad-proposals",
            "router-malformed",
            lambda files: files.update(
                {"router.json": json.dumps({"target_thread_id": []})}
            ),
            "unsupported",
            ("configuration", "malformed"),
        )
        variation(
            "claimed-and-wake-leased",
            "stale-binding-generation",
            lambda files: alter_json(
                files, "registrations/gamma.json", binding_generation="gen-replaced"
            ),
            "recover",
            ("outbox", "stale_generation"),
        )
    output = {
        "format": 1,
        "producer_runtime_cohort": council.RUNTIME_COHORT,
        "clock_epoch": NOW,
        "objects": objects,
        "cases": cases,
    }
    encoded = (json.dumps(output, sort_keys=True, indent=2) + "\n").encode()
    (ROOT / "corpus.json").write_bytes(encoded)
    (ROOT / "corpus.sha256").write_text(hashlib.sha256(encoded).hexdigest() + "\n")
    print(
        "%d cases, %d distinct files, %d bytes"
        % (len(cases), len(objects), len(encoded))
    )


if __name__ == "__main__":
    main()
