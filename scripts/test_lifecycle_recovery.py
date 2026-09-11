#!/usr/bin/env python3
"""Disposable filesystem tests for the standalone lifecycle recovery core."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parent / "council_recover.py"
SPEC = importlib.util.spec_from_file_location("council_recover_source", SOURCE)
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


BOUNDARY_UNIT_IDS = (
    "payload",
    "opencode-plugin",
    "opencode-protocol",
    "opencode-registry",
    "opencode-tool",
)
BOUNDARY_OPERATION_KINDS = ("install", "upgrade", "rollback", "uninstall")


def required_recovery_boundaries(kind: str):
    if kind not in BOUNDARY_OPERATION_KINDS:
        raise ValueError(kind)
    required = {
        "before:replace-immutable:target-receipt",
        "after:replace-immutable:target-receipt",
        "before:replace:terminal-admission",
        "after:replace:terminal-admission",
    }
    for unit_id in BOUNDARY_UNIT_IDS:
        required.update({
            "before:replace:progress:" + unit_id,
            "after:replace:progress:" + unit_id,
        })
        if kind != "install":
            required.update({
                "before:rename:" + unit_id + ":preserve-initial",
                "after:rename:" + unit_id + ":preserve-initial",
            })
        if kind != "uninstall":
            required.update({
                "before:rename:" + unit_id + ":activate-target",
                "after:rename:" + unit_id + ":activate-target",
            })
    if kind != "uninstall":
        required.update({
            "before:replace-materialized-file:payload:target:SKILL.md",
            "after:replace-materialized-file:payload:target:SKILL.md",
            "before:replace-materialized-file:payload:target:scripts/runtime.py",
            "after:replace-materialized-file:payload:target:scripts/runtime.py",
        })
        for unit_id in BOUNDARY_UNIT_IDS[1:]:
            required.update({
                "before:replace-materialized-file:" + unit_id + ":target",
                "after:replace-materialized-file:" + unit_id + ":target",
            })
    return frozenset(required)


def assert_required_recovery_boundaries(kind: str, events) -> None:
    missing = required_recovery_boundaries(kind) - set(events)
    if missing:
        raise AssertionError("missing required recovery boundaries: %s" % sorted(missing))


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_bytes(source.json_bytes(value))
    path.chmod(0o600)


def make_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def write_payload(path: Path, label: str, *, cache: bool = False) -> None:
    make_directory(path)
    for relative, data in {
        "SKILL.md": (label + " skill\n").encode(),
        "scripts/runtime.py": ("VALUE = %r\n" % label).encode(),
    }.items():
        destination = path / relative
        make_directory(destination.parent)
        destination.write_bytes(data)
        destination.chmod(0o644)
    if cache:
        cache_path = path / "scripts/__pycache__/runtime.cpython-39.pyc"
        make_directory(cache_path.parent)
        cache_path.write_bytes(b"stale-cache-" + label.encode())
        cache_path.chmod(0o600)


def write_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    make_directory(path.parent)
    path.write_bytes(data)
    path.chmod(mode)


class Fixture:
    def __init__(self, parent: Path, *, initial: bool = False, cache: bool = False,
                 target_uninstalled: bool = False, preserve_unowned: bool = False):
        self.root = parent
        self.state = parent / "state"
        self.payload_parent = parent / "payload-parent"
        self.payload = self.payload_parent / "council"
        self.opencode = parent / "opencode"
        for path in (self.state, self.payload_parent, self.opencode, self.opencode / "tools"):
            make_directory(path)
        self.lock = self.state / "broker.lock"
        self.lock.write_bytes(b"stable-lock")
        self.lock.chmod(0o600)
        self.lock_inode = self.lock.stat().st_ino
        retained = self.state / "registrations/fixture.json"
        write_file(retained, b'{"fixture":true}\n', 0o600)
        self.lifecycle = self.state / ".council-lifecycle"
        self.v1 = self.lifecycle / "v1"
        for path in (
            self.lifecycle,
            self.v1,
            self.v1 / "receipts",
            self.v1 / "recovery",
            self.v1 / "transactions",
        ):
            make_directory(path)
        tool_data = SOURCE.read_bytes()
        self.tool_digest = hashlib.sha256(tool_data).hexdigest()
        self.tool = self.v1 / "recovery" / (self.tool_digest + ".py")
        self.tool.write_bytes(tool_data)
        self.tool.chmod(0o600)
        spec = importlib.util.spec_from_file_location(
            "council_recover_fixture_" + self.tool_digest[:12], self.tool
        )
        self.engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.engine)
        self.transaction_id = "txn-fixture"
        self.receipt_id = "receipt-fixture"
        self.transaction = self.v1 / "transactions" / self.transaction_id
        make_directory(self.transaction)
        self.roots = {
            "state": str(self.state.resolve()),
            "payload": str(self.payload.absolute()),
            "opencode": str(self.opencode.resolve()),
        }
        self.receipt_root_identities = {
            "state": source.physical_identity(self.state),
            "payload_parent": source.physical_identity(self.payload_parent),
            "opencode": source.physical_identity(self.opencode),
        }
        self.receipt_lock_identity = source.physical_identity(self.lock)
        if initial:
            make_directory(self.payload)
            write_payload(self.payload, "prior", cache=cache)
            for unit_id, relative in source.EXTERNAL_DESTINATIONS.items():
                write_file(self.opencode / relative, ("prior-%s\n" % unit_id).encode())
        elif preserve_unowned:
            write_file(self.opencode / "council-plugin.ts", b"preexisting-unowned\n")
        self.units = []
        for unit_id in source.UNIT_IDS:
            destination = source._unit_destination(self.roots, unit_id)
            kind = "directory" if unit_id == "payload" else "file"
            objects = source._unit_objects(destination, self.transaction_id, unit_id)
            initial_state = source.capture_state(destination, kind)
            prior_state = initial_state
            if initial and unit_id == "payload" and cache:
                clean_prior = Path(objects["prior"])
                write_payload(clean_prior, "prior")
                prior_state = source.capture_state(clean_prior, kind)
            elif initial:
                prior_object = Path(objects["prior"])
                if kind == "directory":
                    write_payload(prior_object, "prior")
                else:
                    write_file(prior_object, destination.read_bytes())
                prior_state = source.capture_state(prior_object, kind)
            elif initial_state["exists"]:
                prior_object = Path(objects["prior"])
                write_file(prior_object, destination.read_bytes())
                prior_state = source.capture_state(prior_object, kind)
            target_object = Path(objects["target"])
            preserve_this = preserve_unowned and unit_id == "opencode-plugin"
            if preserve_this:
                write_file(target_object, destination.read_bytes())
            elif not target_uninstalled:
                if kind == "directory":
                    write_payload(target_object, "target")
                else:
                    write_file(target_object, ("target-%s\n" % unit_id).encode())
            else:
                target_state = source.absent_state(kind)
            target_state = (
                source.capture_state(target_object, kind)
                if target_object.exists() else source.absent_state(kind)
            )
            self.units.append(
                {
                    "unit_id": unit_id,
                    "destination": str(destination),
                    "parent_identity": source.physical_identity(destination.parent),
                    "initial": initial_state,
                    "prior": prior_state,
                    "target": target_state,
                    "objects": objects,
                }
            )
        self.package_id = hashlib.sha256(b"fixture-package").hexdigest()
        self.runtime_cohort = hashlib.sha256(b"fixture-cohort").hexdigest()
        artifacts = {}
        selected = "initial" if target_uninstalled else "target"
        for unit in self.units:
            state_value = unit[selected]
            if unit["unit_id"] == "payload":
                for artifact in state_value["artifacts"]:
                    if artifact["kind"] == "file" and "__pycache__" not in Path(artifact["path"]).parts:
                        artifacts["payload/" + artifact["path"]] = artifact["sha256"]
            else:
                artifacts[source.EXTERNAL_MANIFEST_PATHS[unit["unit_id"]]] = state_value["sha256"]
        manifest = {
            "format": 1,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "runtime_sources": ["scripts/runtime.py"],
            "artifacts": dict(sorted(artifacts.items())),
            "opencode_sources": source.OPENCODE_SOURCES,
        }
        self.manifest_path = self.transaction / "source-manifest.json"
        write_json(self.manifest_path, manifest)
        support = {
            "source_sha256": hashlib.sha256(b"reader-source").hexdigest(),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "import_closure_sha256": hashlib.sha256(b"reader-closure").hexdigest(),
            "fixture_corpus_sha256": hashlib.sha256(b"reader-corpus").hexdigest(),
            "features": ["audit", "dialogues", "lifecycle-v1", "outbox", "registrations"],
            "state_reader": "pass",
            "managed_writer_admission": "pass",
            "external_recoverer": "pass",
            "formats": {"admission": 1, "plan": 1, "journal": 1, "receipt": 1, "recovery": 1},
        }
        self.support_path = self.transaction / "reader-support.json"
        write_json(self.support_path, support)
        if initial:
            prior_receipt_id = "receipt-prior"
            prior_receipt_path = self.v1 / "receipts" / (prior_receipt_id + ".json")
            prior_manifest_artifacts = {}
            for unit in self.units:
                if unit["unit_id"] == "payload":
                    for item in unit["prior"]["artifacts"]:
                        if item["kind"] == "file":
                            prior_manifest_artifacts["payload/" + item["path"]] = item["sha256"]
                else:
                    prior_manifest_artifacts[source.EXTERNAL_MANIFEST_PATHS[unit["unit_id"]]] = unit["prior"]["sha256"]
            prior_manifest = {
                "format": 1,
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
                "runtime_sources": ["scripts/runtime.py"],
                "artifacts": dict(sorted(prior_manifest_artifacts.items())),
                "opencode_sources": source.OPENCODE_SOURCES,
            }
            prior_manifest_path = self.v1 / "receipts" / (prior_receipt_id + ".manifest.json")
            write_json(prior_manifest_path, prior_manifest)
            prior_artifacts = []
            for unit in self.units:
                relatives = ["."]
                if unit["unit_id"] == "payload":
                    relatives.extend(item["path"] for item in unit["prior"]["artifacts"])
                for relative in sorted(relatives):
                    intended = source._leaf_state(unit["prior"], relative)
                    kind = "directory" if unit["unit_id"] == "payload" and relative == "." else None
                    prior_leaf = {"exists": False, "sha256": None, "mode": None, "kind": kind}
                    destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
                    unowned = preserve_unowned and unit["unit_id"] == "opencode-plugin"
                    prior_artifacts.append(
                        {
                            "unit_id": unit["unit_id"],
                            "path": relative,
                            "destination": str(destination),
                            "prior": intended if unowned else prior_leaf,
                            "intended": intended,
                            "ownership": "matching_preexisting_unowned" if unowned else "created",
                            "local_change": "none",
                        }
                    )
            prior_receipt = {
                "receipt_format": 1,
                "receipt_id": prior_receipt_id,
                "transaction_id": "txn-prior",
                "outcome": "committed",
                "roots": self.roots,
                "root_identities": self.receipt_root_identities,
                "lock_identity": self.receipt_lock_identity,
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
                "source_manifest_sha256": file_hash(prior_manifest_path),
                "prior_receipt": None,
                "recovery": {"format": 1, "tool_sha256": self.tool_digest},
                "reader_support_sha256": file_hash(self.support_path),
                "artifacts": prior_artifacts,
            }
            write_json(prior_receipt_path, prior_receipt)
            shutil.copyfile(
                self.support_path,
                self.v1 / "receipts" / (prior_receipt_id + ".reader-support.json"),
            )
            (self.v1 / "receipts" / (prior_receipt_id + ".reader-support.json")).chmod(0o600)
            prior_committed = {
                "receipt_id": prior_receipt_id,
                "receipt_sha256": file_hash(prior_receipt_path),
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
            }
            prior_status = "committed"
        else:
            prior_committed = None
            prior_status = "uninstalled"
        self.prior_admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": self.roots,
            "status": prior_status,
            "transaction_id": None,
            "committed": prior_committed,
        }
        write_json(self.lifecycle / "admission.json", self.prior_admission)
        receipt_artifacts = []
        for unit_id, relative in source._receipt_artifact_keys(self.units):
            unit = next(item for item in self.units if item["unit_id"] == unit_id)
            prior = source._leaf_state(unit["initial"], relative)
            intended = source._leaf_state(unit["target"], relative)
            destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
            if preserve_unowned and unit_id == "opencode-plugin":
                ownership = "matching_preexisting_unowned"
            else:
                ownership = "created" if not prior["exists"] else "already_owned"
            receipt_artifacts.append(
                {
                    "unit_id": unit_id,
                    "path": relative,
                    "destination": str(destination),
                    "prior": prior,
                    "intended": intended,
                    "ownership": ownership,
                    "local_change": "none",
                }
            )
        self.receipt = {
            "receipt_format": 1,
            "receipt_id": self.receipt_id,
            "transaction_id": self.transaction_id,
            "outcome": "uninstalled" if target_uninstalled else "committed",
            "roots": self.roots,
            "root_identities": self.receipt_root_identities,
            "lock_identity": self.receipt_lock_identity,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "source_manifest_sha256": file_hash(self.manifest_path),
            "prior_receipt": None if prior_committed is None else {
                "receipt_id": prior_committed["receipt_id"],
                "receipt_sha256": prior_committed["receipt_sha256"],
            },
            "recovery": {"format": 1, "tool_sha256": self.tool_digest},
            "reader_support_sha256": file_hash(self.support_path),
            "artifacts": receipt_artifacts,
        }
        self.receipt_path = self.transaction / "receipt.json"
        write_json(self.receipt_path, self.receipt)
        committed = {
            "receipt_id": self.receipt_id,
            "receipt_sha256": file_hash(self.receipt_path),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
        }
        target_admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": self.roots,
            "status": "uninstalled" if target_uninstalled else "committed",
            "transaction_id": None,
            "committed": committed,
        }
        if initial:
            prior_outcome = self.prior_admission
            proposed_prior = None
        else:
            prior_receipt_id = self.receipt_id + "-prior"
            prior_artifacts = []
            for unit_id, relative in source._receipt_artifact_keys(self.units, "prior"):
                unit = next(item for item in self.units if item["unit_id"] == unit_id)
                prior_leaf = source._leaf_state(unit["initial"], relative)
                intended = source._leaf_state(unit["prior"], relative)
                destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
                prior_artifacts.append(
                    {
                        "unit_id": unit_id,
                        "path": relative,
                        "destination": str(destination),
                        "prior": prior_leaf,
                        "intended": intended,
                        "ownership": (
                            "matching_preexisting_unowned" if prior_leaf["exists"] else "absent"
                        ),
                        "local_change": "none",
                    }
                )
            prior_receipt = {
                "receipt_format": 1,
                "receipt_id": prior_receipt_id,
                "transaction_id": self.transaction_id,
                "outcome": "uninstalled",
                "roots": self.roots,
                "root_identities": self.receipt_root_identities,
                "lock_identity": self.receipt_lock_identity,
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
                "source_manifest_sha256": file_hash(self.manifest_path),
                "prior_receipt": None,
                "recovery": {"format": 1, "tool_sha256": self.tool_digest},
                "reader_support_sha256": file_hash(self.support_path),
                "artifacts": prior_artifacts,
            }
            prior_candidate_path = self.transaction / "prior-receipt.json"
            write_json(prior_candidate_path, prior_receipt)
            prior_summary = {
                "receipt_id": prior_receipt_id,
                "receipt_sha256": file_hash(prior_candidate_path),
                "package_id": self.package_id,
                "runtime_cohort": self.runtime_cohort,
            }
            prior_outcome = copy.deepcopy(self.prior_admission)
            prior_outcome["committed"] = prior_summary
            proposed_prior = {
                "path": "prior-receipt.json",
                "sha256": file_hash(prior_candidate_path),
            }
        self.plan = {
            "plan_format": 1,
            "transaction_id": self.transaction_id,
            "kind": "uninstall" if target_uninstalled else "upgrade" if initial else "install",
            "roots": self.roots,
            "root_identities": {
                "state": source.physical_identity(self.state),
                "payload_parent": source.physical_identity(self.payload_parent),
                "opencode": source.physical_identity(self.opencode),
                "lifecycle": source.physical_identity(self.lifecycle),
                "v1": source.physical_identity(self.v1),
                "receipts": source.physical_identity(self.v1 / "receipts"),
                "recovery": source.physical_identity(self.v1 / "recovery"),
                "transactions": source.physical_identity(self.v1 / "transactions"),
                "transaction": source.physical_identity(self.transaction),
            },
            "lock_identity": source.physical_identity(self.lock),
            "prior_admission": self.prior_admission,
            "outcomes": {"target": target_admission, "prior": prior_outcome},
            "target_receipt_id": self.receipt_id,
            "source_manifest": {"path": "source-manifest.json", "sha256": file_hash(self.manifest_path)},
            "proposed_receipt": {"path": "receipt.json", "sha256": file_hash(self.receipt_path)},
            "proposed_prior_receipt": proposed_prior,
            "recovery": {
                "format": 1,
                "tool_path": str(self.tool),
                "tool_sha256": self.tool_digest,
                "python_path": str(Path(sys.executable).resolve()),
                "python_version": list(sys.version_info[:3]),
            },
            "required_operations": list(source.REQUIRED_OPERATIONS),
            "allowed_goals": ["target", "prior"],
            "units": self.units,
            "retained_state": source.retained_state_fingerprint(self.state),
            "reader_support": {"path": "reader-support.json", "sha256": file_hash(self.support_path)},
        }
        self.plan_path = self.transaction / "plan.json"
        write_json(self.plan_path, self.plan)
        self.progress = {
            "journal_format": 1,
            "transaction_id": self.transaction_id,
            "plan_sha256": file_hash(self.plan_path),
            "sequence": 0,
            "goal": "target",
            "units": [{"unit_id": unit_id, "phase": "pending"} for unit_id in source.UNIT_IDS],
        }
        self.progress_path = self.transaction / "progress.json"
        write_json(self.progress_path, self.progress)

    def publish_intent(self) -> None:
        pending = copy.deepcopy(self.prior_admission)
        pending["status"] = "recovery_required"
        pending["transaction_id"] = self.transaction_id
        write_json(self.lifecycle / "admission.json", pending)

    def prepare_managed_transaction(self, kind: str) -> None:
        if kind not in ("upgrade", "uninstall"):
            raise ValueError(kind)
        prior_admission = json.loads((self.lifecycle / "admission.json").read_text())
        if prior_admission["status"] != "committed":
            raise ValueError("managed transaction requires a committed installation")
        prior_summary = prior_admission["committed"]
        prior_receipt_path = self.v1 / "receipts" / (prior_summary["receipt_id"] + ".json")
        prior_receipt = json.loads(prior_receipt_path.read_text())
        prior_ownership = {
            (item["unit_id"], item["path"]): item["ownership"]
            for item in prior_receipt["artifacts"]
        }
        generation = getattr(self, "generation", 0) + 1
        self.generation = generation
        self.transaction_id = "txn-%s-%d" % (kind, generation)
        self.receipt_id = "receipt-%s-%d" % (kind, generation)
        self.transaction = self.v1 / "transactions" / self.transaction_id
        make_directory(self.transaction)
        self.units = []
        for unit_id in source.UNIT_IDS:
            destination = source._unit_destination(self.roots, unit_id)
            unit_kind = "directory" if unit_id == "payload" else "file"
            objects = source._unit_objects(destination, self.transaction_id, unit_id)
            initial_state = source.capture_state(destination, unit_kind)
            prior_object = Path(objects["prior"])
            if unit_kind == "directory":
                shutil.copytree(destination, prior_object)
                for path in prior_object.rglob("*"):
                    path.chmod(0o700 if path.is_dir() else 0o644)
                prior_object.chmod(0o700)
            else:
                write_file(prior_object, destination.read_bytes())
            prior_state = source.capture_state(prior_object, unit_kind)
            root_ownership = prior_ownership[(unit_id, ".")]
            preserve_unowned = root_ownership == "matching_preexisting_unowned"
            target_object = Path(objects["target"])
            if preserve_unowned:
                write_file(target_object, destination.read_bytes())
                target_state = source.capture_state(target_object, unit_kind)
            elif kind == "uninstall":
                target_state = source.absent_state(unit_kind)
            elif unit_kind == "directory":
                write_payload(target_object, "managed-update-%d" % generation)
                target_state = source.capture_state(target_object, unit_kind)
            else:
                write_file(
                    target_object,
                    ("managed-update-%d-%s\n" % (generation, unit_id)).encode(),
                )
                target_state = source.capture_state(target_object, unit_kind)
            self.units.append(
                {
                    "unit_id": unit_id,
                    "destination": str(destination),
                    "parent_identity": source.physical_identity(destination.parent),
                    "initial": initial_state,
                    "prior": prior_state,
                    "target": target_state,
                    "objects": objects,
                }
            )
        if kind == "upgrade":
            self.package_id = hashlib.sha256(
                ("fixture-package-%d" % generation).encode()
            ).hexdigest()
            self.runtime_cohort = hashlib.sha256(
                ("fixture-cohort-%d" % generation).encode()
            ).hexdigest()
        else:
            self.package_id = prior_summary["package_id"]
            self.runtime_cohort = prior_summary["runtime_cohort"]
        artifacts = {}
        selected = "initial" if kind == "uninstall" else "target"
        for unit in self.units:
            state_value = unit[selected]
            if unit["unit_id"] == "payload":
                for artifact in state_value["artifacts"]:
                    if artifact["kind"] == "file":
                        artifacts["payload/" + artifact["path"]] = artifact["sha256"]
            else:
                artifacts[source.EXTERNAL_MANIFEST_PATHS[unit["unit_id"]]] = state_value["sha256"]
        manifest = {
            "format": 1,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "runtime_sources": ["scripts/runtime.py"],
            "artifacts": dict(sorted(artifacts.items())),
            "opencode_sources": source.OPENCODE_SOURCES,
        }
        self.manifest_path = self.transaction / "source-manifest.json"
        write_json(self.manifest_path, manifest)
        support = {
            "source_sha256": hashlib.sha256(("reader-source-%d" % generation).encode()).hexdigest(),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "import_closure_sha256": hashlib.sha256(("reader-closure-%d" % generation).encode()).hexdigest(),
            "fixture_corpus_sha256": hashlib.sha256(b"reader-corpus").hexdigest(),
            "features": ["audit", "dialogues", "lifecycle-v1", "outbox", "registrations"],
            "state_reader": "pass",
            "managed_writer_admission": "pass",
            "external_recoverer": "pass",
            "formats": {"admission": 1, "plan": 1, "journal": 1, "receipt": 1, "recovery": 1},
        }
        self.support_path = self.transaction / "reader-support.json"
        write_json(self.support_path, support)
        receipt_artifacts = []
        old_records = {
            (item["unit_id"], item["path"]): item
            for item in prior_receipt["artifacts"]
        }
        for unit_id, relative in source._receipt_artifact_keys(self.units):
            unit = next(item for item in self.units if item["unit_id"] == unit_id)
            prior_leaf = source._leaf_state(unit["initial"], relative)
            intended = source._leaf_state(unit["target"], relative)
            old = old_records.get((unit_id, relative))
            if old is not None and old["ownership"] == "matching_preexisting_unowned":
                ownership = old["ownership"]
            elif prior_leaf["exists"]:
                ownership = "already_owned"
            elif intended["exists"]:
                ownership = "created"
            else:
                ownership = "absent"
            destination = Path(unit["destination"]) if relative == "." else Path(unit["destination"]) / relative
            receipt_artifacts.append(
                {
                    "unit_id": unit_id,
                    "path": relative,
                    "destination": str(destination),
                    "prior": prior_leaf,
                    "intended": intended,
                    "ownership": ownership,
                    "local_change": "none",
                }
            )
        self.receipt = {
            "receipt_format": 1,
            "receipt_id": self.receipt_id,
            "transaction_id": self.transaction_id,
            "outcome": "uninstalled" if kind == "uninstall" else "committed",
            "roots": self.roots,
            "root_identities": self.receipt_root_identities,
            "lock_identity": self.receipt_lock_identity,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "source_manifest_sha256": file_hash(self.manifest_path),
            "prior_receipt": {
                "receipt_id": prior_summary["receipt_id"],
                "receipt_sha256": prior_summary["receipt_sha256"],
            },
            "recovery": {"format": 1, "tool_sha256": self.tool_digest},
            "reader_support_sha256": file_hash(self.support_path),
            "artifacts": receipt_artifacts,
        }
        self.receipt_path = self.transaction / "receipt.json"
        write_json(self.receipt_path, self.receipt)
        committed = {
            "receipt_id": self.receipt_id,
            "receipt_sha256": file_hash(self.receipt_path),
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
        }
        target_admission = {
            "format": 1,
            "namespace_version": 1,
            "roots": self.roots,
            "status": "uninstalled" if kind == "uninstall" else "committed",
            "transaction_id": None,
            "committed": committed,
        }
        self.prior_admission = prior_admission
        self.plan = {
            "plan_format": 1,
            "transaction_id": self.transaction_id,
            "kind": kind,
            "roots": self.roots,
            "root_identities": {
                "state": source.physical_identity(self.state),
                "payload_parent": source.physical_identity(self.payload_parent),
                "opencode": source.physical_identity(self.opencode),
                "lifecycle": source.physical_identity(self.lifecycle),
                "v1": source.physical_identity(self.v1),
                "receipts": source.physical_identity(self.v1 / "receipts"),
                "recovery": source.physical_identity(self.v1 / "recovery"),
                "transactions": source.physical_identity(self.v1 / "transactions"),
                "transaction": source.physical_identity(self.transaction),
            },
            "lock_identity": source.physical_identity(self.lock),
            "prior_admission": prior_admission,
            "outcomes": {"target": target_admission, "prior": prior_admission},
            "target_receipt_id": self.receipt_id,
            "source_manifest": {"path": "source-manifest.json", "sha256": file_hash(self.manifest_path)},
            "proposed_receipt": {"path": "receipt.json", "sha256": file_hash(self.receipt_path)},
            "proposed_prior_receipt": None,
            "recovery": {
                "format": 1,
                "tool_path": str(self.tool),
                "tool_sha256": self.tool_digest,
                "python_path": str(Path(sys.executable).resolve()),
                "python_version": list(sys.version_info[:3]),
            },
            "required_operations": list(source.REQUIRED_OPERATIONS),
            "allowed_goals": ["target", "prior"],
            "units": self.units,
            "retained_state": source.retained_state_fingerprint(self.state),
            "reader_support": {"path": "reader-support.json", "sha256": file_hash(self.support_path)},
        }
        self.plan_path = self.transaction / "plan.json"
        write_json(self.plan_path, self.plan)
        self.progress = {
            "journal_format": 1,
            "transaction_id": self.transaction_id,
            "plan_sha256": file_hash(self.plan_path),
            "sequence": 0,
            "goal": "target",
            "units": [{"unit_id": unit_id, "phase": "pending"} for unit_id in source.UNIT_IDS],
        }
        self.progress_path = self.transaction / "progress.json"
        write_json(self.progress_path, self.progress)

    def rewrite_plan(self, mutate) -> None:
        plan = json.loads(self.plan_path.read_text())
        mutate(plan)
        write_json(self.plan_path, plan)
        progress = json.loads(self.progress_path.read_text())
        progress["plan_sha256"] = file_hash(self.plan_path)
        write_json(self.progress_path, progress)

    def snapshot(self):
        result = []
        for path in sorted(self.root.rglob("*")):
            details = path.lstat()
            relative = str(path.relative_to(self.root))
            if path.is_symlink():
                result.append((relative, "link", os.readlink(path), stat.S_IMODE(details.st_mode)))
            elif path.is_file():
                result.append((relative, "file", file_hash(path), stat.S_IMODE(details.st_mode)))
            else:
                result.append((relative, "directory", None, stat.S_IMODE(details.st_mode)))
        return result

    def assert_goal(self, testcase: unittest.TestCase, goal: str) -> None:
        for unit in self.units:
            testcase.assertTrue(
                self.engine.state_matches(Path(unit["destination"]), unit[goal]),
                unit["unit_id"],
            )
        testcase.assertEqual(self.lock.stat().st_ino, self.lock_inode)


class LifecycleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="council-lifecycle-core-")
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, **kwargs) -> Fixture:
        path = self.root / ("fixture-%d" % len(list(self.root.glob("fixture-*"))))
        make_directory(path)
        return Fixture(path, **kwargs)

    def operation_fixture(self, kind: str) -> Fixture:
        fixture = self.fixture()
        if kind != "install":
            fixture.publish_intent()
            fixture.engine.recover(fixture.state)
            fixture.prepare_managed_transaction(
                "uninstall" if kind == "uninstall" else "upgrade"
            )
            if kind == "rollback":
                fixture.rewrite_plan(lambda plan: plan.__setitem__("kind", "rollback"))
        fixture.publish_intent()
        return fixture

    def test_describe_matches_literal_format_fixture(self):
        expected = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/describe-v1.json").read_text()
        )
        self.assertEqual(source.describe(), expected)
        described = subprocess.run(
            [sys.executable, "-I", "-B", str(SOURCE), "describe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(described.returncode, 0, described.stderr)
        self.assertEqual(json.loads(described.stdout), expected)
        cases = json.loads(
            (Path(__file__).parent / "fixtures/lifecycle/format-cases-v1.json").read_text()
        )
        self.assertEqual(cases["format"], 1)
        self.assertIn("borrowed-validated-lease", cases["supported"])
        self.assertIn("native-or-configuration-operation", cases["refused"])

    def test_check_plan_is_exact_and_read_only(self):
        fixture = self.fixture()
        before = fixture.snapshot()
        result = fixture.engine.check_plan(fixture.plan_path)
        self.assertEqual(result["status"], "plan-valid")
        self.assertEqual(result["units"], list(source.UNIT_IDS))
        self.assertEqual(fixture.snapshot(), before)
        empty = self.root / "empty"
        make_directory(empty)
        environment = dict(os.environ, PYTHONPATH=str(self.root / "poison"))
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "check-plan", str(fixture.plan_path)],
            cwd=empty,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "plan-valid")
        self.assertEqual(fixture.snapshot(), before)
        nonisolated = subprocess.run(
            [sys.executable, str(fixture.tool), "check-plan", str(fixture.plan_path)],
            cwd=empty,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(nonisolated.returncode, 1)
        self.assertIn("requires Python -I -B", nonisolated.stderr)
        self.assertEqual(fixture.snapshot(), before)

    def test_immutable_control_writer_refuses_oversized_bytes_before_creation(self):
        fixture = self.fixture()
        path = fixture.transaction / "oversized.json"
        before = fixture.snapshot()
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "1 MiB"):
            fixture.engine._write_immutable(
                path, b"x" * (fixture.engine.MAX_METADATA_BYTES + 1), None,
                "oversized-control",
            )
        self.assertFalse(path.exists())
        self.assertFalse(path.with_name(path.name + ".partial").exists())
        self.assertEqual(fixture.snapshot(), before)

    def test_forward_recovery_commits_all_five_units_and_receipt_last(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        events = []
        result = fixture.engine.recover(fixture.state, failpoint=events.append)
        self.assertEqual(result["status"], "committed")
        fixture.assert_goal(self, "target")
        admission = json.loads((fixture.lifecycle / "admission.json").read_text())
        self.assertEqual(admission, fixture.plan["outcomes"]["target"])
        final_receipt = fixture.v1 / "receipts" / (fixture.receipt_id + ".json")
        self.assertEqual(final_receipt.read_bytes(), fixture.receipt_path.read_bytes())
        self.assertLess(
            events.index("after:replace-immutable:target-receipt"),
            events.index("before:replace:terminal-admission"),
        )
        self.assertEqual(fixture.engine.recover(fixture.state), result)

    def test_abort_is_sticky_and_restores_validated_prior_after_partial_target(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_payload(event):
            if event == "after:rename:payload:activate-target":
                raise RuntimeError("stop after payload activation")

        with self.assertRaisesRegex(RuntimeError, "payload activation"):
            fixture.engine.recover(fixture.state, failpoint=stop_after_payload)
        self.assertTrue(
            fixture.engine.state_matches(Path(fixture.units[0]["destination"]), fixture.units[0]["target"])
        )
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "uninstalled")
        fixture.assert_goal(self, "prior")
        progress = json.loads(fixture.progress_path.read_text())
        self.assertEqual(progress["goal"], "prior")
        shutil.rmtree(fixture.transaction)
        write_file(fixture.state / "registrations/later.json", b"{}\n", 0o600)
        self.assertEqual(fixture.engine.recover(fixture.state), result)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "terminal"):
            fixture.engine.recover(fixture.state, abort=True)

    def test_managed_abort_reactivates_the_clean_prior_set(self):
        fixture = self.fixture(initial=True)
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_two_units(event):
            if event == "after:rename:opencode-plugin:activate-target":
                raise RuntimeError("partial managed update")

        with self.assertRaises(RuntimeError):
            fixture.engine.recover(fixture.state, failpoint=stop_after_two_units)
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["receipt_id"], "receipt-prior")
        fixture.assert_goal(self, "prior")
        self.assertEqual(json.loads(fixture.progress_path.read_text())["goal"], "prior")

    def test_actual_install_then_managed_update_abort_repeats_without_transaction_history(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        installed = fixture.engine.recover(fixture.state)
        first_receipt = installed["receipt_id"]
        fixture.prepare_managed_transaction("upgrade")
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_two_units(event):
            if event == "after:rename:opencode-plugin:activate-target":
                raise RuntimeError("partial managed update")

        with self.assertRaises(RuntimeError):
            fixture.engine.recover(fixture.state, failpoint=stop_after_two_units)
        aborted = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(aborted["status"], "committed")
        self.assertEqual(aborted["receipt_id"], first_receipt)
        for transaction in list((fixture.v1 / "transactions").iterdir()):
            shutil.rmtree(transaction)
        write_file(fixture.state / "registrations/post-commit.json", b"{}\n", 0o600)
        repeated = fixture.engine.recover(fixture.state)
        self.assertEqual(repeated, aborted)
        fixture.assert_goal(self, "prior")

    def test_abort_discards_only_a_known_partial_forward_stage(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_in_stage(event):
            if event == "after:replace-materialized-file:payload:target:SKILL.md":
                raise RuntimeError("partial target stage")

        with self.assertRaises(RuntimeError):
            fixture.engine.recover(fixture.state, failpoint=stop_in_stage)
        stage = Path(fixture.units[0]["objects"]["stage"])
        self.assertTrue((stage / "SKILL.md").is_file())
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "uninstalled")
        self.assertFalse(stage.exists())
        fixture.assert_goal(self, "prior")

    def test_recovery_mutations_refuse_swapped_stage_progress_and_source(self):
        fixture = self.fixture()
        fixture.publish_intent()

        def stop_partial(event):
            if event == "after:replace-materialized-file:payload:target:SKILL.md":
                raise RuntimeError("partial stage")

        with self.assertRaisesRegex(RuntimeError, "partial stage"):
            fixture.engine.recover(fixture.state, failpoint=stop_partial)
        stage = Path(fixture.units[0]["objects"]["stage"])
        saved = stage.with_name(stage.name + "-saved")
        outside = fixture.root / "outside-stage"
        write_payload(outside, "outside")
        outside_before = fixture.engine.capture_state(outside, "directory")
        swapped = {"done": False}

        def swap_stage(event):
            if (event.startswith("before:unlink-stage:payload:discard-target-stage:")
                    and not swapped["done"]):
                stage.rename(saved)
                stage.symlink_to(outside, target_is_directory=True)
                swapped["done"] = True

        with self.assertRaisesRegex(fixture.engine.RecoveryError, "stage changed"):
            fixture.engine.recover(fixture.state, abort=True, failpoint=swap_stage)
        self.assertTrue(stage.is_symlink())
        self.assertTrue(fixture.engine.state_matches(outside, outside_before))

        fixture = self.fixture()
        fixture.publish_intent()
        progress = fixture.progress_path
        original = progress.with_name("progress-before-swap.json")

        def swap_progress(event):
            if event == "before:replace:progress:payload":
                progress.rename(original)
                write_file(progress, b"outside-owner\n", 0o600)

        with self.assertRaisesRegex(
            fixture.engine.RecoveryError, "changed before metadata replacement"
        ):
            fixture.engine.recover(fixture.state, failpoint=swap_progress)
        self.assertEqual(progress.read_bytes(), b"outside-owner\n")
        self.assertTrue(original.is_file())

        fixture = self.fixture()
        fixture.publish_intent()
        stage = Path(fixture.units[0]["objects"]["stage"])
        saved = stage.with_name(stage.name + "-saved")

        def swap_activation(event):
            if event == "before:rename:payload:activate-target":
                stage.rename(saved)
                write_payload(stage, "foreign")

        with self.assertRaisesRegex(
            fixture.engine.RecoveryError, "rename source or destination changed"
        ):
            fixture.engine.recover(fixture.state, failpoint=swap_activation)
        self.assertFalse(fixture.payload.exists())
        self.assertTrue((stage / "SKILL.md").is_file())

    def test_unrelated_partial_name_is_never_engine_scratch(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        stage = Path(fixture.units[1]["objects"]["stage"])
        unrelated = stage.with_name(stage.name + ".partial")
        write_file(unrelated, b"unrelated-user-file", 0o600)
        fixture.engine.recover(fixture.state)
        self.assertEqual(unrelated.read_bytes(), b"unrelated-user-file")
        fixture.assert_goal(self, "target")

    def test_plan_owned_partial_resumes_but_preintent_collision_is_preserved(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        def stop_after_copy(event):
            if event == "after:copy-file:opencode-plugin:target":
                raise RuntimeError("synthetic external partial")

        with self.assertRaisesRegex(RuntimeError, "external partial"):
            fixture.engine.recover(fixture.state, failpoint=stop_after_copy)
        partial = Path(fixture.units[1]["objects"]["partial"])
        self.assertTrue(partial.is_file())
        self.assertFalse(Path(fixture.units[1]["objects"]["stage"]).exists())
        fixture.engine.recover(fixture.state)
        self.assertFalse(partial.exists())
        fixture.assert_goal(self, "target")

        collision = self.fixture()
        partial = Path(collision.units[1]["objects"]["partial"])
        write_file(partial, b"pre-existing", 0o600)
        with self.assertRaisesRegex(collision.engine.RecoveryError, "pre-intent partial"):
            collision.engine.check_plan(collision.plan_path)
        self.assertEqual(partial.read_bytes(), b"pre-existing")

    def test_unknown_destination_and_recovery_objects_fail_closed(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        write_payload(fixture.payload, "unknown")
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unknown content"):
            fixture.engine.recover(fixture.state)
        admission = json.loads((fixture.lifecycle / "admission.json").read_text())
        self.assertEqual(admission["status"], "recovery_required")
        self.assertFalse((fixture.opencode / "council-plugin.ts").exists())

        fixture2 = self.fixture()
        stage = Path(fixture2.units[0]["objects"]["stage"])
        stage.symlink_to(fixture2.units[0]["objects"]["target"])
        fixture2.publish_intent()
        with self.assertRaises(fixture2.engine.RecoveryError):
            fixture2.engine.recover(fixture2.state)

    def test_strict_formats_reject_unknown_operations_types_and_bounds(self):
        fixture = self.fixture()
        fixture.rewrite_plan(lambda plan: plan["required_operations"].append("native-config-edit"))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unsupported or incomplete operations"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.rewrite_plan(lambda plan: plan["root_identities"]["state"].__setitem__("device", True))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "integer"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        data = fixture.plan_path.read_text()
        fixture.plan_path.write_text(data.replace('"plan_format": 1', '"plan_format": 1, "plan_format": 1', 1))
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "duplicate JSON key"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.plan_path.write_bytes(b'{"padding":"' + b"x" * source.MAX_METADATA_BYTES + b'"}')
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "1 MiB"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        receipt = json.loads(fixture.receipt_path.read_text())
        receipt["artifacts"][0]["destination"] = "/tmp/elsewhere"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "destination"):
            fixture.engine.check_plan(fixture.plan_path)

    def test_direct_and_borrowed_leases_share_the_same_inode(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()

        class Borrowed:
            def __init__(self, lease):
                self.lease = lease
                self.calls = 0

            def validate_for_recovery(self, state_root):
                self.calls += 1
                return self.lease.validate_for_recovery(state_root)

        alias = self.root / "state-alias"
        alias.symlink_to(fixture.state)
        with fixture.engine.acquire_recovery_lease(alias) as lease:
            adapter = Borrowed(lease)
            result = fixture.engine._execute_with_lease(fixture.state, adapter)
            self.assertEqual(result["status"], "committed")
            self.assertGreater(adapter.calls, 5)
            with self.assertRaisesRegex(fixture.engine.RecoveryError, "already held"):
                fixture.engine.acquire_recovery_lease(fixture.state)
            child = subprocess.run(
                [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root", str(alias)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(child.returncode, 1)
            self.assertIn("already held", child.stderr)
            self.assertFalse(lease.closed)
        self.assertTrue(lease.closed)

    def test_forked_child_cannot_validate_or_release_parent_lease(self):
        fixture = self.fixture()
        with fixture.engine.acquire_recovery_lease(fixture.state) as lease:
            child = os.fork()
            if child == 0:
                try:
                    lease.validate()
                except fixture.engine.RecoveryError:
                    lease.close()
                    os._exit(0)
                os._exit(3)
            _pid, status_value = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status_value), 0)
            with self.assertRaisesRegex(fixture.engine.RecoveryError, "already held"):
                fixture.engine.acquire_recovery_lease(fixture.state)
            lease.validate()

    def test_displaced_lock_and_retained_state_changes_refuse(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        old_lock = fixture.state / "broker.lock.old"
        fixture.lock.rename(old_lock)
        fixture.lock.write_bytes(b"replacement")
        fixture.lock.chmod(0o600)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "lock"):
            fixture.engine.recover(fixture.state)
        self.assertFalse(fixture.payload.exists())

        fixture2 = self.fixture()
        fixture2.publish_intent()
        write_file(fixture2.state / "registrations/new.json", b"{}\n", 0o600)
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "retained state"):
            fixture2.engine.recover(fixture2.state)

    def test_external_cli_recovers_without_payload_or_import_environment(self):
        fixture = self.fixture()
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        poison = self.root / "poison"
        make_directory(poison)
        for name in ("council.py", "council_admission.py", "json.py"):
            (poison / name).write_text("raise RuntimeError('poison imported')\n")
        empty = self.root / "empty-cwd"
        make_directory(empty)
        environment = dict(os.environ, PYTHONPATH=str(poison), PYTHONDONTWRITEBYTECODE="1")
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root", str(fixture.state)],
            cwd=empty,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")
        fixture.assert_goal(self, "target")
        self.assertFalse((empty / "__pycache__").exists())
        self.assertFalse((poison / "__pycache__").exists())

    def test_uninstall_preserves_matching_unowned_external_and_raw_cache_backup(self):
        fixture = self.fixture(
            initial=True,
            cache=True,
            target_uninstalled=True,
            preserve_unowned=True,
        )
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        result = fixture.engine.recover(fixture.state)
        self.assertEqual(result["status"], "uninstalled")
        fixture.assert_goal(self, "target")
        self.assertFalse(fixture.payload.exists())
        unowned = fixture.opencode / "council-plugin.ts"
        self.assertEqual(unowned.read_bytes(), b"prior-opencode-plugin\n")
        payload_backup = Path(fixture.units[0]["objects"]["backup"])
        self.assertTrue((payload_backup / "scripts/__pycache__/runtime.cpython-39.pyc").is_file())
        self.assertEqual(fixture.lock.stat().st_ino, fixture.lock_inode)
        self.assertEqual(file_hash(fixture.tool), fixture.tool_digest)
        self.assertTrue(fixture.plan_path.is_file())
        before = fixture.snapshot()
        refused = subprocess.run(
            [sys.executable, "-I", "-B", str(fixture.tool), "recover", "--state-root",
             str(fixture.state), "--purge-state"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(fixture.snapshot(), before)

    def test_actual_install_then_uninstall_repeats_from_receipt_without_history(self):
        fixture = self.fixture(preserve_unowned=True)
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        fixture.prepare_managed_transaction("uninstall")
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        uninstalled = fixture.engine.recover(fixture.state)
        self.assertEqual(uninstalled["status"], "uninstalled")
        self.assertIn("receipt_id", uninstalled)
        for transaction in list((fixture.v1 / "transactions").iterdir()):
            shutil.rmtree(transaction)
        write_file(fixture.state / "registrations/post-uninstall.json", b"{}\n", 0o600)
        self.assertEqual(fixture.engine.recover(fixture.state), uninstalled)
        self.assertFalse(fixture.payload.exists())
        self.assertEqual(
            (fixture.opencode / "council-plugin.ts").read_bytes(),
            b"preexisting-unowned\n",
        )

    def test_legacy_uninstalled_marker_without_receipt_is_uncertified(self):
        fixture = self.fixture()
        write_json(fixture.lifecycle / "admission.json", fixture.prior_admission)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "no certifying"):
            fixture.engine.recover(fixture.state)

    def test_rollback_uses_the_same_fixed_forward_target_machine(self):
        fixture = self.fixture(initial=True)
        fixture.rewrite_plan(lambda plan: plan.__setitem__("kind", "rollback"))
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        self.assertEqual(fixture.engine.recover(fixture.state)["status"], "committed")
        fixture.assert_goal(self, "target")

    def test_cache_is_retained_in_backup_but_forward_activates_clean_target(self):
        fixture = self.fixture(initial=True, cache=True)
        fixture.engine.check_plan(fixture.plan_path)
        fixture.publish_intent()
        result = fixture.engine.recover(fixture.state)
        self.assertEqual(result["status"], "committed")
        fixture.assert_goal(self, "target")
        self.assertFalse((fixture.payload / "scripts/__pycache__").exists())
        self.assertTrue(
            (Path(fixture.units[0]["objects"]["backup"])
             / "scripts/__pycache__/runtime.cpython-39.pyc").is_file()
        )
        cache = fixture.payload / "scripts/__pycache__/runtime.cpython-39.pyc"
        make_directory(cache.parent)
        cache.write_bytes(b"later-runtime-cache")
        cache.chmod(0o600)
        self.assertEqual(fixture.engine.recover(fixture.state), result)
        inspected = fixture.engine.inspect_terminal_ownership(
            fixture.state, fixture.payload, fixture.opencode
        )
        self.assertTrue(inspected["certified"])
        self.assertEqual([item["path"] for item in inspected["payload_cache"]], [
            "scripts/__pycache__",
            "scripts/__pycache__/runtime.cpython-39.pyc",
        ])

    def test_every_forward_durability_boundary_recovers_after_process_exit(self):
        for kind in BOUNDARY_OPERATION_KINDS:
            probe = self.operation_fixture(kind)
            events = []
            probe.engine.recover(probe.state, failpoint=events.append)
            assert_required_recovery_boundaries(kind, events)
            self.assertGreater(len(events), 40)
            removed = next(iter(required_recovery_boundaries(kind)))
            with self.assertRaisesRegex(AssertionError, "missing required"):
                assert_required_recovery_boundaries(
                    kind, [event for event in events if event != removed]
                )
            for boundary in range(len(events)):
                with self.subTest(kind=kind, boundary=boundary, event=events[boundary]):
                    fixture = self.operation_fixture(kind)
                    child = os.fork()
                    if child == 0:
                        observed = {"index": -1}

                        def crash(_event):
                            observed["index"] += 1
                            if observed["index"] == boundary:
                                os._exit(97)

                        fixture.engine.recover(fixture.state, failpoint=crash)
                        os._exit(0)
                    _pid, status_value = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status_value), 97)
                    fixture.engine.recover(fixture.state)
                    fixture.assert_goal(self, "target")
                    admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                    self.assertEqual(
                        admission["status"],
                        "uninstalled" if kind == "uninstall" else "committed",
                    )

    def test_every_abort_durability_boundary_keeps_prior_goal_sticky(self):
        def partial_forward(fixture):
            def stop(event):
                if event == "after:replace:progress:payload":
                    raise RuntimeError("partial")

            with self.assertRaises(RuntimeError):
                fixture.engine.recover(fixture.state, failpoint=stop)

        for kind in BOUNDARY_OPERATION_KINDS:
            probe = self.operation_fixture(kind)
            partial_forward(probe)
            events = []
            probe.engine.recover(probe.state, abort=True, failpoint=events.append)
            self.assertGreater(len(events), 20)
            for boundary in range(len(events)):
                with self.subTest(kind=kind, boundary=boundary, event=events[boundary]):
                    fixture = self.operation_fixture(kind)
                    partial_forward(fixture)
                    child = os.fork()
                    if child == 0:
                        observed = {"index": -1}

                        def crash(_event):
                            observed["index"] += 1
                            if observed["index"] == boundary:
                                os._exit(98)

                        fixture.engine.recover(fixture.state, abort=True, failpoint=crash)
                        os._exit(0)
                    _pid, status_value = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status_value), 98)
                    admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                    if admission["status"] == "recovery_required":
                        fixture.engine.recover(fixture.state, abort=True)
                    else:
                        fixture.engine.recover(fixture.state)
                    fixture.assert_goal(self, "prior")
                    self.assertEqual(
                        json.loads(fixture.progress_path.read_text())["goal"], "prior"
                    )

    def test_every_partial_stage_discard_boundary_recovers_after_process_exit(self):
        def partial_stage(fixture):
            fixture.publish_intent()

            def stop(event):
                if event == "after:replace-materialized-file:payload:target:SKILL.md":
                    raise RuntimeError("partial stage")

            with self.assertRaises(RuntimeError):
                fixture.engine.recover(fixture.state, failpoint=stop)

        probe = self.fixture()
        partial_stage(probe)
        events = []
        probe.engine.recover(probe.state, abort=True, failpoint=events.append)
        self.assertTrue(any("unlink-stage" in event for event in events))
        for boundary in range(len(events)):
            with self.subTest(boundary=boundary, event=events[boundary]):
                fixture = self.fixture()
                partial_stage(fixture)
                child = os.fork()
                if child == 0:
                    observed = {"index": -1}

                    def crash(_event):
                        observed["index"] += 1
                        if observed["index"] == boundary:
                            os._exit(99)

                    fixture.engine.recover(fixture.state, abort=True, failpoint=crash)
                    os._exit(0)
                _pid, status_value = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status_value), 99)
                admission = json.loads((fixture.lifecycle / "admission.json").read_text())
                if admission["status"] == "recovery_required":
                    fixture.engine.recover(fixture.state, abort=True)
                else:
                    fixture.engine.recover(fixture.state)
                fixture.assert_goal(self, "prior")

    def test_nested_staged_payload_abort_completes_in_one_call(self):
        fixture = self.fixture()
        fixture.publish_intent()

        def stop_after_nested_file(event):
            if event == (
                "after:replace-materialized-file:"
                "payload:target:scripts/runtime.py"
            ):
                raise RuntimeError("complete nested stage")

        with self.assertRaisesRegex(RuntimeError, "complete nested stage"):
            fixture.engine.recover(
                fixture.state, failpoint=stop_after_nested_file
            )
        stage = Path(fixture.units[0]["objects"]["stage"])
        self.assertTrue((stage / "scripts/runtime.py").is_file())
        result = fixture.engine.recover(fixture.state, abort=True)
        self.assertEqual(result["status"], "uninstalled")
        fixture.assert_goal(self, "prior")
        self.assertFalse(stage.exists())

    def test_nested_stage_directory_replacement_or_type_change_refuses(self):
        for mutation in ("replacement", "type-change"):
            with self.subTest(mutation=mutation):
                fixture = self.fixture()
                fixture.publish_intent()

                def stop_after_nested_file(event):
                    if event == (
                        "after:replace-materialized-file:"
                        "payload:target:scripts/runtime.py"
                    ):
                        raise RuntimeError("complete nested stage")

                with self.assertRaisesRegex(RuntimeError, "complete nested stage"):
                    fixture.engine.recover(
                        fixture.state, failpoint=stop_after_nested_file
                    )
                stage = Path(fixture.units[0]["objects"]["stage"])
                nested = stage / "scripts"
                saved = stage / "scripts.saved"
                changed = {"done": False}

                def change_nested_directory(event):
                    if not event.endswith(
                        "payload:discard-target-stage:scripts"
                    ) or not event.startswith("before:rmdir-stage:"):
                        return
                    if mutation == "replacement":
                        nested.rename(saved)
                        make_directory(nested)
                    else:
                        nested.rmdir()
                        write_file(nested, b"replacement type\n")
                    changed["done"] = True

                with self.assertRaisesRegex(
                    fixture.engine.RecoveryError,
                    "stage changed during bounded removal",
                ):
                    fixture.engine.recover(
                        fixture.state,
                        abort=True,
                        failpoint=change_nested_directory,
                    )
                self.assertTrue(changed["done"])
                if mutation == "replacement":
                    self.assertTrue(saved.is_dir())
                    self.assertTrue(nested.is_dir())
                else:
                    self.assertTrue(nested.is_file())

    def test_staged_payload_file_and_inventory_changes_remain_fail_closed(self):
        for mutation in ("content", "symlink", "hardlink", "unexpected"):
            with self.subTest(mutation=mutation):
                fixture = self.fixture()
                fixture.publish_intent()

                def stop_after_nested_file(event):
                    if event == (
                        "after:replace-materialized-file:"
                        "payload:target:scripts/runtime.py"
                    ):
                        raise RuntimeError("complete nested stage")

                with self.assertRaisesRegex(RuntimeError, "complete nested stage"):
                    fixture.engine.recover(
                        fixture.state, failpoint=stop_after_nested_file
                    )
                stage = Path(fixture.units[0]["objects"]["stage"])
                skill = stage / "SKILL.md"
                if mutation == "content":
                    skill.write_bytes(b"changed staged content\n")
                elif mutation == "symlink":
                    skill.unlink()
                    skill.symlink_to("scripts/runtime.py")
                elif mutation == "hardlink":
                    os.link(skill, fixture.root / "external-hardlink")
                else:
                    write_file(stage / "unexpected.txt", b"unexpected\n")
                with self.assertRaisesRegex(
                    fixture.engine.RecoveryError,
                    "stage contains unknown content|known disposable stage",
                ):
                    fixture.engine.recover(fixture.state, abort=True)

    def test_staged_payload_file_identity_change_during_removal_refuses(self):
        fixture = self.fixture()
        fixture.publish_intent()

        def stop_after_nested_file(event):
            if event == (
                "after:replace-materialized-file:"
                "payload:target:scripts/runtime.py"
            ):
                raise RuntimeError("complete nested stage")

        with self.assertRaisesRegex(RuntimeError, "complete nested stage"):
            fixture.engine.recover(fixture.state, failpoint=stop_after_nested_file)
        stage = Path(fixture.units[0]["objects"]["stage"])
        skill = stage / "SKILL.md"
        original = skill.read_bytes()
        displaced = stage / "SKILL.saved"
        changed = {"done": False}

        def replace_file(event):
            if event.endswith("payload:discard-target-stage:SKILL.md") and event.startswith(
                "before:unlink-stage:"
            ):
                skill.rename(displaced)
                write_file(skill, original)
                changed["done"] = True

        with self.assertRaisesRegex(
            fixture.engine.RecoveryError, "stage changed during bounded removal"
        ):
            fixture.engine.recover(
                fixture.state, abort=True, failpoint=replace_file
            )
        self.assertTrue(changed["done"])
        self.assertEqual(skill.read_bytes(), original)
        self.assertEqual(displaced.read_bytes(), original)

    def test_fsync_failure_and_premature_terminal_marker_do_not_claim_success(self):
        fixture = self.fixture()
        fixture.publish_intent()
        with mock.patch.object(fixture.engine.os, "fsync", side_effect=OSError("ENOSPC")):
            with self.assertRaisesRegex(OSError, "ENOSPC"):
                fixture.engine.recover(fixture.state)
        self.assertEqual(
            json.loads((fixture.lifecycle / "admission.json").read_text())["status"],
            "recovery_required",
        )

        fixture2 = self.fixture()
        fixture2.publish_intent()

        def stop_after_payload(event):
            if event == "after:rename:payload:activate-target":
                raise RuntimeError("payload only")

        with self.assertRaises(RuntimeError):
            fixture2.engine.recover(fixture2.state, failpoint=stop_after_payload)
        final_receipt = fixture2.v1 / "receipts" / (fixture2.receipt_id + ".json")
        final_receipt.write_bytes(fixture2.receipt_path.read_bytes())
        final_receipt.chmod(0o600)
        shutil.copyfile(
            fixture2.manifest_path,
            fixture2.v1 / "receipts" / (fixture2.receipt_id + ".manifest.json"),
        )
        shutil.copyfile(
            fixture2.support_path,
            fixture2.v1 / "receipts" / (fixture2.receipt_id + ".reader-support.json"),
        )
        write_json(fixture2.lifecycle / "admission.json", fixture2.plan["outcomes"]["target"])
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "coherent"):
            fixture2.engine.recover(fixture2.state)

    def test_preintent_changes_collisions_and_hardlinks_are_rejected_read_only(self):
        fixture = self.fixture()
        write_payload(fixture.payload, "late")
        before = fixture.snapshot()
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "changed before intent"):
            fixture.engine.check_plan(fixture.plan_path)
        self.assertEqual(fixture.snapshot(), before)

        fixture2 = self.fixture()
        plan = json.loads(fixture2.plan_path.read_text())
        payload = plan["units"][0]["target"]
        duplicate = copy.deepcopy(next(item for item in payload["artifacts"] if item["path"] == "SKILL.md"))
        duplicate["path"] = "skill.md"
        payload["artifacts"].append(duplicate)
        payload["artifacts"].sort(key=lambda item: item["path"])
        payload["sha256"] = source._inventory_digest(payload["artifacts"])
        write_json(fixture2.plan_path, plan)
        progress = json.loads(fixture2.progress_path.read_text())
        progress["plan_sha256"] = file_hash(fixture2.plan_path)
        write_json(fixture2.progress_path, progress)
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "collision"):
            fixture2.engine.check_plan(fixture2.plan_path)

        fixture3 = self.fixture()
        target = Path(fixture3.units[1]["objects"]["target"])
        linked = target.with_name(target.name + ".linked")
        os.link(target, linked)
        with self.assertRaisesRegex(fixture3.engine.RecoveryError, "recovery object"):
            fixture3.engine.check_plan(fixture3.plan_path)

        for git_kind in ("directory", "file", "symlink"):
            with self.subTest(git_kind=git_kind):
                fixture4 = self.fixture()
                payload_source = Path(fixture4.units[0]["objects"]["target"])
                git_path = payload_source / ".git"
                if git_kind == "directory":
                    make_directory(git_path)
                elif git_kind == "file":
                    write_file(git_path, b"gitdir: elsewhere\n")
                else:
                    git_path.symlink_to("elsewhere")
                with self.assertRaises(fixture4.engine.RecoveryError):
                    fixture4.engine.check_plan(fixture4.plan_path)

    def test_manifest_reader_receipt_progress_and_python_links_are_exact(self):
        fixture = self.fixture()
        manifest = json.loads(fixture.manifest_path.read_text())
        manifest["artifacts"]["opencode/native-registration.json"] = hashlib.sha256(b"x").hexdigest()
        write_json(fixture.manifest_path, manifest)
        fixture.rewrite_plan(
            lambda plan: plan["source_manifest"].__setitem__("sha256", file_hash(fixture.manifest_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "exactly four"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        support = json.loads(fixture.support_path.read_text())
        support["managed_writer_admission"] = "unknown"
        write_json(fixture.support_path, support)
        fixture.rewrite_plan(
            lambda plan: plan["reader_support"].__setitem__("sha256", file_hash(fixture.support_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "not an accepted result"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        receipt = json.loads(fixture.receipt_path.read_text())
        receipt["unexpected"] = "operation"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "unexpected receipt keys"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        progress = json.loads(fixture.progress_path.read_text())
        progress["sequence"] = True
        write_json(fixture.progress_path, progress)
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "integer"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture = self.fixture()
        fixture.rewrite_plan(
            lambda plan: plan["recovery"].__setitem__("python_version", [3, 8, 999])
        )
        with self.assertRaisesRegex(
            fixture.engine.RecoveryError, "recorded Python provenance"
        ):
            fixture.engine.check_plan(fixture.plan_path)

    def test_compatible_relocated_python_recovers_and_runtime_contract_refuses(self):
        fixture = self.fixture()
        alternate = fixture.root / "relocated-python3"
        alternate.symlink_to(Path(sys.executable).resolve())
        recorded = [sys.version_info[0], sys.version_info[1], sys.version_info[2] + 1]
        fixture.rewrite_plan(
            lambda plan: (
                plan["recovery"].__setitem__("python_path", str(alternate)),
                plan["recovery"].__setitem__("python_version", recorded),
            )
        )
        fixture.publish_intent()
        completed = subprocess.run(
            [str(alternate), "-I", "-B", str(fixture.tool), "recover",
             "--state-root", str(fixture.state)],
            cwd=fixture.root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["status"], "committed")

        cases = (
            ("implementation", "requires CPython"),
            ("version", "3.9 or newer"),
            ("features", "descriptor-relative"),
        )
        for case, message in cases:
            probe = self.fixture()
            if case == "implementation":
                patcher = mock.patch.object(
                    probe.engine.platform, "python_implementation", return_value="PyPy"
                )
            elif case == "version":
                patcher = mock.patch.object(probe.engine.sys, "version_info", (3, 8, 99))
            else:
                patcher = mock.patch.object(probe.engine.os, "supports_dir_fd", set())
            with self.subTest(case=case), patcher, self.assertRaisesRegex(
                probe.engine.RecoveryError, message
            ):
                probe.engine.check_plan(probe.plan_path)

    def test_prior_receipt_prevents_silent_adoption_or_dropped_ownership(self):
        fixture = self.fixture(initial=True, target_uninstalled=True, preserve_unowned=True)
        receipt = json.loads(fixture.receipt_path.read_text())
        plugin = next(
            item for item in receipt["artifacts"]
            if item["unit_id"] == "opencode-plugin"
        )
        plugin["ownership"] = "already_owned"
        write_json(fixture.receipt_path, receipt)
        fixture.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture.receipt_path))
        )
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "adopt"):
            fixture.engine.check_plan(fixture.plan_path)

        fixture2 = self.fixture(initial=True)
        prior_path = fixture2.v1 / "receipts/receipt-prior.json"
        prior = json.loads(prior_path.read_text())
        prior["artifacts"] = [
            item for item in prior["artifacts"]
            if not (item["unit_id"] == "opencode-protocol" and item["path"] == ".")
        ]
        write_json(prior_path, prior)
        committed = fixture2.prior_admission["committed"]
        committed["receipt_sha256"] = file_hash(prior_path)
        write_json(fixture2.lifecycle / "admission.json", fixture2.prior_admission)
        fixture2.rewrite_plan(
            lambda plan: plan["prior_admission"]["committed"].__setitem__(
                "receipt_sha256", file_hash(prior_path)
            )
        )
        receipt = json.loads(fixture2.receipt_path.read_text())
        receipt["prior_receipt"]["receipt_sha256"] = file_hash(prior_path)
        write_json(fixture2.receipt_path, receipt)
        fixture2.rewrite_plan(
            lambda plan: plan["proposed_receipt"].__setitem__("sha256", file_hash(fixture2.receipt_path))
        )
        with self.assertRaisesRegex(fixture2.engine.RecoveryError, "absent from the prior"):
            fixture2.engine.check_plan(fixture2.plan_path)

    def test_terminal_admission_status_must_match_receipt_outcome(self):
        committed = self.fixture()
        committed.publish_intent()
        committed.engine.recover(committed.state)
        admission_path = committed.lifecycle / "admission.json"
        admission = json.loads(admission_path.read_text())
        admission["status"] = "uninstalled"
        write_json(admission_path, admission)
        with self.assertRaisesRegex(
            committed.engine.RecoveryError, "outcome differs"
        ):
            committed.engine.inspect_terminal_ownership(
                committed.state, committed.payload, committed.opencode
            )

        uninstalled = self.fixture()
        uninstalled.publish_intent()
        uninstalled.engine.recover(uninstalled.state)
        uninstalled.prepare_managed_transaction("uninstall")
        uninstalled.publish_intent()
        uninstalled.engine.recover(uninstalled.state)
        admission_path = uninstalled.lifecycle / "admission.json"
        admission = json.loads(admission_path.read_text())
        admission["status"] = "committed"
        write_json(admission_path, admission)
        with self.assertRaisesRegex(
            uninstalled.engine.RecoveryError, "outcome differs"
        ):
            uninstalled.engine.inspect_terminal_ownership(
                uninstalled.state, uninstalled.payload, uninstalled.opencode
            )

    def test_pending_admission_must_match_all_plan_roots_before_unit_work(self):
        for root_name in ("payload", "opencode"):
            fixture = self.fixture()
            fixture.publish_intent()
            admission_path = fixture.lifecycle / "admission.json"
            admission = json.loads(admission_path.read_text())
            admission["roots"][root_name] = str(
                self.root / ("alternate-" + root_name)
            )
            write_json(admission_path, admission)
            before = fixture.snapshot()
            with self.subTest(root=root_name), self.assertRaisesRegex(
                fixture.engine.RecoveryError, "roots differ"
            ):
                fixture.engine.recover(fixture.state)
            self.assertEqual(fixture.snapshot(), before)

    def test_terminal_admission_must_match_all_receipt_roots(self):
        for root_name in ("payload", "opencode"):
            fixture = self.fixture()
            fixture.publish_intent()
            fixture.engine.recover(fixture.state)
            admission_path = fixture.lifecycle / "admission.json"
            admission = json.loads(admission_path.read_text())
            admission["roots"][root_name] = str(
                self.root / ("alternate-terminal-" + root_name)
            )
            write_json(admission_path, admission)
            before = fixture.snapshot()
            with self.subTest(root=root_name), self.assertRaisesRegex(
                fixture.engine.RecoveryError, "admission roots differ"
            ):
                fixture.engine.recover(fixture.state)
            self.assertEqual(fixture.snapshot(), before)

    def test_terminal_receipt_or_artifact_corruption_never_uses_progress_as_authority(self):
        fixture = self.fixture()
        fixture.publish_intent()
        fixture.engine.recover(fixture.state)
        fixture.progress_path.unlink()
        self.assertEqual(fixture.engine.recover(fixture.state)["status"], "committed")
        (fixture.payload / "SKILL.md").write_text("local edit\n")
        with self.assertRaisesRegex(fixture.engine.RecoveryError, "coherent"):
            fixture.engine.recover(fixture.state)

        fixture2 = self.fixture()
        fixture2.publish_intent()
        fixture2.engine.recover(fixture2.state)
        final_receipt = fixture2.v1 / "receipts" / (fixture2.receipt_id + ".json")
        final_receipt.write_text("{}\n")
        with self.assertRaises(fixture2.engine.RecoveryError):
            fixture2.engine.recover(fixture2.state)

        fixture3 = self.fixture()
        fixture3.publish_intent()
        fixture3.engine.recover(fixture3.state)
        old_lock = fixture3.lock.with_name("broker.lock.displaced")
        fixture3.lock.rename(old_lock)
        write_file(fixture3.lock, b"replacement", 0o600)
        with self.assertRaisesRegex(fixture3.engine.RecoveryError, "lock"):
            fixture3.engine.recover(fixture3.state)

        fixture4 = self.fixture()
        fixture4.publish_intent()
        fixture4.engine.recover(fixture4.state)
        receipt_path = fixture4.v1 / "receipts" / (fixture4.receipt_id + ".json")
        receipt = json.loads(receipt_path.read_text())
        receipt["roots"]["payload"] = str(self.root / "wrong-payload")
        write_json(receipt_path, receipt)
        admission_path = fixture4.lifecycle / "admission.json"
        admission = json.loads(admission_path.read_text())
        admission["committed"]["receipt_sha256"] = file_hash(receipt_path)
        write_json(admission_path, admission)
        with self.assertRaises(fixture4.engine.RecoveryError):
            fixture4.engine.recover(fixture4.state)

        fixture5 = self.fixture()
        fixture5.publish_intent()
        fixture5.engine.recover(fixture5.state)
        provenance = fixture5.v1 / "receipts" / (fixture5.receipt_id + ".manifest.json")
        provenance.write_text("{}\n")
        with self.assertRaises(fixture5.engine.RecoveryError):
            fixture5.engine.recover(fixture5.state)


if __name__ == "__main__":
    unittest.main()
