#!/usr/bin/env python3
"""Passive Council registration inspection and OpenCode candidate generation.

This module deliberately has no file or process API.  Callers supply bounded
configuration bytes and absolute source names, then receive observations or a
byte-for-byte candidate.  A candidate is data for the lifecycle executor; it
is not authorization, native-runtime qualification, or an apply operation.

The Python 3.9 baseline is retained.  Codex TOML inspection is available only
when this already-running interpreter provides the standard ``tomllib``
module (Python 3.11+).  The module never discovers or switches interpreters.
"""

import difflib
import hashlib
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass

try:  # Python 3.11+ only; absence is a supported, explicit result.
    import tomllib as _tomllib
except ImportError:  # pragma: no cover - exercised by a patched 3.9 oracle
    _tomllib = None


MAX_CONFIG_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100000
OPENCODE_COUNCIL_PLUGIN = "./council-plugin.ts"

CLAUDE_USER = "claude_user"
CLAUDE_PROJECT = "claude_project"
CLAUDE_LOCAL = "claude_local"
CODEX_USER = "codex_user"
OPENCODE_GLOBAL = "opencode_global"

CLAUDE_ENSURE = "claude_user_stdio_ensure"
CLAUDE_REMOVE = "claude_user_stdio_remove"
CODEX_ENSURE = "codex_user_stdio_ensure"
CODEX_REMOVE = "codex_user_stdio_remove"
OPENCODE_ENSURE = "opencode_global_plugin_ensure"
OPENCODE_REMOVE = "opencode_global_plugin_remove"

OPERATIONS = {
    CLAUDE_ENSURE,
    CLAUDE_REMOVE,
    CODEX_ENSURE,
    CODEX_REMOVE,
    OPENCODE_ENSURE,
    OPENCODE_REMOVE,
}

REGISTRATION_INTEGRATION_FORMAT = 1
REGISTRATION_EXECUTION_FORMAT = 1
NATIVE_REGISTRATION_PLAN_FORMAT = 3
NATIVE_REGISTRATION_EXECUTION_FORMAT = 3
C2_CONTRACT_FORMAT = 1
C2_SOURCE_COMMIT = "5a4160b0b99bbbe87f3c5e22705cf78d65e0e6b8"
C2_SOURCE_HASHES = {
    "scripts/council_admission.py": "4d8ba851861aade8d158093a8d483b59296a7e7325c41dbfd9354a1aab90c863",
    "scripts/council_inspect.py": "fbc6845244e9125cc72e4e7a36fdb96386e1586d7af01bb52ae68e0de44324d0",
    "scripts/council_lifecycle.py": "a51380a25223561a9efe5b28a15436cea08ed6fa82fc0cd2bcd939ec339829f9",
    "scripts/council_recover.py": "b10af86e1ff988dd55101ff44226b0eb1a2e339e1c84049d84d2484ab9cf46c3",
}
C2_INSPECTION_INTERFACES = (
    "inspect_artifacts(payload_root=<default>, opencode_root=<default>, *, release_root=<default>, state_root=<default>)",
)
C2_FORMAT_VERSIONS = {
    "admission": 1,
    "journal": 1,
    "namespace": 1,
    "plan": 1,
    "receipt": 1,
    "recovery": 1,
}
C2_UNIT_IDS = (
    "payload",
    "opencode-plugin",
    "opencode-protocol",
    "opencode-registry",
    "opencode-tool",
)
C2_REQUIRED_OPERATIONS = (
    "classify-filesystem-v1",
    "preserve-initial-v1",
    "materialize-selected-v1",
    "activate-five-units-v1",
    "verify-receipt-v1",
    "publish-admission-v1",
)
C2_PLANNER_INTERFACES = (
    "validate_release(release_root)",
    "inspect_ownership(state_root, payload_root, opencode_root)",
    "plan_ownership(kind, release_snapshot, ownership_snapshot, *, adopt_unowned=<default>)",
    "retained_release(state_root, receipt_id)",
    "prepare_transaction(preview, release_snapshot, lease, *, transaction_id=<default>, failpoint=<default>)",
    "run_handshake(bundle)",
    "publish_and_execute(bundle, lease, c1_inspect, registration_snapshot, *, now=<default>, probe=<default>)",
    "status(state_root, payload_root, opencode_root)",
    "execute_operation(kind, release_root, state_root, payload_root, opencode_root, *, maintenance_window_confirmed=<default>, adopt_unowned=<default>, receipt_id=<default>, transaction_id=<default>, now=<default>, probe=<default>, recovery_command_sink=<default>, _preparation_failpoint=<default>)",
)
C2_RECOVERY_INTERFACES = (
    "validate_plan(plan_path, *, pre_intent, require_progress=<default>, require_executing_tool=<default>)",
    "check_plan(plan_path)",
    "inspect_terminal_ownership(state_root, payload_root, opencode_root)",
    "recover(state_root, *, abort=<default>, failpoint=<default>)",
    "_execute_with_lease(state_root, lease_adapter, *, abort=<default>, failpoint=<default>)",
    "describe()",
)
C2_BUNDLE_KEYS = (
    "transaction_id",
    "kind",
    "bootstrap",
    "control_root",
    "canonical_root",
    "plan",
    "tool",
    "canonical_tool",
    "pending_admission",
    "loaded_recoverer",
    "preview_bytes",
    "release_snapshot",
    "recovery_command",
)
C2_EXTERNAL_COMMAND = (
    "<absolute-python>",
    "-I",
    "-B",
    "<state>/.council-lifecycle/v1/recovery/<sha256>.py",
    "describe|check-plan|recover",
)
OPERATION_INVERSES = {
    CLAUDE_ENSURE: CLAUDE_REMOVE,
    CLAUDE_REMOVE: CLAUDE_ENSURE,
    CODEX_ENSURE: CODEX_REMOVE,
    CODEX_REMOVE: CODEX_ENSURE,
    OPENCODE_ENSURE: OPENCODE_REMOVE,
    OPENCODE_REMOVE: OPENCODE_ENSURE,
}
OPERATION_SCOPES = {
    "claude": CLAUDE_USER,
    "codex": CODEX_USER,
    "opencode": OPENCODE_GLOBAL,
}
ENTRY_DISPOSITIONS = {
    "created",
    "already_owned",
    "matching_preexisting_unowned",
    "adopted_by_explicit_plan",
}
OBSERVATION_STATES = {
    "absent",
    "matching",
    "customized",
    "disabled",
    "unknown_fields",
    "ambiguous_identity",
    "malformed",
    "unsupported",
    "unsupported_schema",
    "parser_unavailable",
    "invalid_utf8",
    "strict_json_required",
    "duplicate_json_key",
    "json_depth_exceeded",
    "json_node_limit_exceeded",
}
CANDIDATE_OUTCOMES = {None, "candidate", "unchanged", "refused"}
NATIVE_ATTEMPT_STATES = {
    "prepared",
    "issued",
    "observed_target",
    "observed_prior",
    "unknown",
}
_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")


class RegistrationInputError(ValueError):
    """A caller supplied an unbounded or structurally invalid public input."""


class _JSONError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ConfigDocument:
    """An explicit configuration snapshot; construction performs no I/O."""

    path: str
    scope: str
    content: bytes

    def __post_init__(self):
        if not isinstance(self.path, str) or not os.path.isabs(self.path):
            raise RegistrationInputError("config path must be absolute")
        if "\x00" in self.path:
            raise RegistrationInputError("config path contains NUL")
        if os.path.normpath(self.path) != self.path:
            raise RegistrationInputError("config path must be normalized")
        if not isinstance(self.scope, str) or not self.scope:
            raise RegistrationInputError("config scope is required")
        if not isinstance(self.content, bytes):
            raise RegistrationInputError("config content must be bytes")


@dataclass(frozen=True)
class StdioSpec:
    """The only eligible Council MCP shape."""

    python_executable: str
    adapter_path: str

    def __post_init__(self):
        for name, value in (
            ("python executable", self.python_executable),
            ("adapter path", self.adapter_path),
        ):
            if not isinstance(value, str) or not os.path.isabs(value):
                raise RegistrationInputError(name + " must be absolute")
            if "\x00" in value:
                raise RegistrationInputError(name + " contains NUL")
            if os.path.normpath(value) != value:
                raise RegistrationInputError(name + " must be normalized")
        if (
            os.path.basename(self.adapter_path) != "council_mcp.py"
            or os.path.basename(os.path.dirname(self.adapter_path)) != "scripts"
        ):
            raise RegistrationInputError(
                "adapter path must select scripts/council_mcp.py"
            )


@dataclass(frozen=True)
class OwnershipEvidence:
    """Minimal later-receipt input; equality without this never grants ownership."""

    runtime: str
    source_path: str
    entry_sha256: str
    origin: str

    def __post_init__(self):
        if self.runtime not in {"claude", "codex", "opencode"}:
            raise RegistrationInputError("invalid ownership runtime")
        if not isinstance(self.source_path, str) or not os.path.isabs(self.source_path):
            raise RegistrationInputError("ownership source path must be absolute")
        if os.path.normpath(self.source_path) != self.source_path:
            raise RegistrationInputError("ownership source path must be normalized")
        if not _is_digest(self.entry_sha256):
            raise RegistrationInputError("ownership entry digest is invalid")
        if self.origin not in {"created", "adopted_by_explicit_plan"}:
            raise RegistrationInputError("ownership origin is invalid")


@dataclass(frozen=True)
class RegistrationObservation:
    """Redacted selected-entry result.  No raw unrelated value is retained."""

    runtime: str
    source_path: str
    source_scope: str
    source_sha256: str
    state: str
    reason: str
    entry_sha256: object
    entry_disposition: object
    candidate_eligible: bool
    unknown_fields: tuple
    selected_identity_count: int
    unrelated_entry_count: int
    complement_sha256: str
    competing_scopes: tuple
    effective_scope: str
    parser_capability: str

    @property
    def automatic_eligible(self):
        """Native mutation is outside this passive core and is never qualified."""
        return False

    def public_dict(self):
        return {
            "runtime": self.runtime,
            "source_path": self.source_path,
            "source_scope": self.source_scope,
            "source_sha256": self.source_sha256,
            "state": self.state,
            "reason": self.reason,
            "entry_sha256": self.entry_sha256,
            "entry_disposition": self.entry_disposition,
            "candidate_eligible": self.candidate_eligible,
            "automatic_mutation_eligible": False,
            "unknown_fields": list(self.unknown_fields),
            "selected_identity_count": self.selected_identity_count,
            "unrelated_entry_count": self.unrelated_entry_count,
            "complement_sha256": self.complement_sha256,
            "competing_scopes": list(self.competing_scopes),
            "effective_scope": self.effective_scope,
            "parser_capability": self.parser_capability,
        }


@dataclass(frozen=True)
class BytePatch:
    """One exact in-memory replacement against a digest-bound source."""

    start: int
    end: int
    replacement: bytes

    def candidate(self, source):
        if not isinstance(source, bytes):
            raise RegistrationInputError("patch source must be bytes")
        if not (0 <= self.start <= self.end <= len(source)):
            raise RegistrationInputError("patch bounds are invalid")
        return source[: self.start] + self.replacement + source[self.end :]


@dataclass(frozen=True)
class CandidateEdit:
    """Pure candidate result for later plan/admission/executor integration."""

    operation: str
    runtime: str
    source_path: str
    source_sha256: str
    candidate_sha256: object
    candidate_bytes: object
    patch: object
    outcome: str
    entry_disposition: object
    reason: str

    @property
    def changed(self):
        return self.candidate_bytes is not None

    def public_dict(self):
        marker = None
        if self.changed:
            marker = (
                "+ <council-plugin-entry>"
                if self.operation == OPENCODE_ENSURE
                else "- <council-plugin-entry>"
            )
        return {
            "operation": self.operation,
            "runtime": self.runtime,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "candidate_sha256": self.candidate_sha256,
            "outcome": self.outcome,
            "entry_disposition": self.entry_disposition,
            "reason": self.reason,
            "selected_key": "plugin",
            "redacted_hunk": marker,
            "candidate_only": True,
            "native_qualified": False,
            "applied": False,
        }

    def private_unified_diff(self, before):
        """Return an exact local-only diff; callers must not export it."""
        if not self.changed:
            return ""
        if _sha256(before) != self.source_sha256:
            raise RegistrationInputError("diff source digest mismatch")
        left = before.decode("utf-8").splitlines(True)
        right = self.candidate_bytes.decode("utf-8").splitlines(True)
        return "".join(
            difflib.unified_diff(
                left,
                right,
                fromfile=self.source_path + "@" + self.source_sha256,
                tofile=self.source_path + "@" + self.candidate_sha256,
                n=0,
            )
        )


@dataclass(frozen=True)
class CandidateComparison:
    """Digest-bound before/candidate comparison without applying either file."""

    source_path: str
    source_sha256: str
    candidate_sha256: str
    exact_diff: str

    def public_dict(self):
        return {
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "candidate_sha256": self.candidate_sha256,
            "diff_available_locally": True,
        }


@dataclass(frozen=True)
class ArtifactReceiptBinding:
    """The immutable C2 artifact receipt identity a D preview depends on."""

    receipt_id: str
    receipt_sha256: str
    package_id: str
    runtime_cohort: str

    def __post_init__(self):
        if not isinstance(self.receipt_id, str) or not _RECORD_ID.fullmatch(
            self.receipt_id
        ):
            raise RegistrationInputError("artifact receipt id is invalid")
        for label, value in (
            ("artifact receipt", self.receipt_sha256),
            ("artifact package", self.package_id),
            ("artifact runtime cohort", self.runtime_cohort),
        ):
            if not _is_digest(value):
                raise RegistrationInputError(label + " digest is invalid")

    @classmethod
    def from_summary(cls, summary):
        _exact_record_keys(
            summary,
            ("receipt_id", "receipt_sha256", "package_id", "runtime_cohort"),
            "artifact receipt summary",
        )
        return cls(
            summary["receipt_id"],
            summary["receipt_sha256"],
            summary["package_id"],
            summary["runtime_cohort"],
        )

    def public_dict(self):
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
        }


@dataclass(frozen=True)
class QualificationReference:
    """A bounded evidence reference; this D-only slice cannot qualify it."""

    record_sha256: str
    runtime_tuple_sha256: str
    qualification_eligible: bool = False

    def __post_init__(self):
        if not _is_digest(self.record_sha256) or not _is_digest(
            self.runtime_tuple_sha256
        ):
            raise RegistrationInputError("qualification reference digest is invalid")
        if self.qualification_eligible is not False:
            raise RegistrationInputError(
                "D-only integration cannot promote native qualification"
            )

    def public_dict(self):
        return {
            "record_sha256": self.record_sha256,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "qualification_eligible": False,
        }


@dataclass(frozen=True)
class QuiescentDecisionProjection:
    """A plan-bound user decision record with no execution behavior."""

    plan_sha256: str
    invocation_id: str
    goal: str
    hosts: tuple
    files: tuple
    closed_and_no_competing_writer: bool

    def __post_init__(self):
        if not _is_digest(self.plan_sha256):
            raise RegistrationInputError("quiescent decision plan digest is invalid")
        if not isinstance(self.invocation_id, str) or not _RECORD_ID.fullmatch(
            self.invocation_id
        ):
            raise RegistrationInputError("quiescent invocation id is invalid")
        if self.goal not in {"target", "prior"}:
            raise RegistrationInputError("quiescent recovery goal is invalid")
        for label, values in (("host", self.hosts), ("file", self.files)):
            if not isinstance(values, tuple) or not values or len(values) > 8:
                raise RegistrationInputError("quiescent %s set is invalid" % label)
            if len(values) != len(set(values)):
                raise RegistrationInputError("quiescent %s set is duplicated" % label)
            for value in values:
                if not isinstance(value, str) or not value or len(value) > 4096:
                    raise RegistrationInputError("quiescent %s is invalid" % label)
                if label == "file" and (
                    not os.path.isabs(value) or os.path.normpath(value) != value
                ):
                    raise RegistrationInputError("quiescent file path is invalid")
        if type(self.closed_and_no_competing_writer) is not bool:
            raise RegistrationInputError("quiescent assertion must be boolean")

    def public_dict(self):
        return {
            "plan_sha256": self.plan_sha256,
            "invocation_id": self.invocation_id,
            "goal": self.goal,
            "hosts": list(self.hosts),
            "files": list(self.files),
            "closed_and_no_competing_writer": self.closed_and_no_competing_writer,
            "projection_only": True,
        }


@dataclass(frozen=True)
class NativeAttemptProjection:
    """One journal projection; no exit code or progress bit establishes success."""

    operation_id: str
    sequence: int
    state: str
    pre_observation_sha256: str
    post_observation_sha256: object
    process_generation_sha256: object
    result_reason_sha256: object

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _RECORD_ID.fullmatch(
            self.operation_id
        ):
            raise RegistrationInputError("native attempt operation id is invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise RegistrationInputError("native attempt sequence is invalid")
        if self.state not in NATIVE_ATTEMPT_STATES:
            raise RegistrationInputError("native attempt state is invalid")
        if not _is_digest(self.pre_observation_sha256):
            raise RegistrationInputError("native pre-observation digest is invalid")
        for label, value in (
            ("post-observation", self.post_observation_sha256),
            ("process-generation", self.process_generation_sha256),
            ("result-reason", self.result_reason_sha256),
        ):
            if value is not None and not _is_digest(value):
                raise RegistrationInputError("native %s digest is invalid" % label)
        if self.state == "prepared" and any(
            value is not None
            for value in (
                self.post_observation_sha256,
                self.process_generation_sha256,
                self.result_reason_sha256,
            )
        ):
            raise RegistrationInputError("prepared native attempt has outcome evidence")
        if self.state in {"observed_target", "observed_prior", "unknown"} and self.post_observation_sha256 is None:
            raise RegistrationInputError("observed native attempt lacks post-observation")

    def public_dict(self):
        return {
            "operation_id": self.operation_id,
            "sequence": self.sequence,
            "state": self.state,
            "pre_observation_sha256": self.pre_observation_sha256,
            "post_observation_sha256": self.post_observation_sha256,
            "process_generation_sha256": self.process_generation_sha256,
            "result_reason_sha256": self.result_reason_sha256,
            "projection_only": True,
            "committed": False,
        }


@dataclass(frozen=True)
class RegistrationResultProjection:
    """Separate stored, effective-scope, restart, and readiness outcomes."""

    operation_id: str
    resulting_entry_sha256: object
    ownership_origin: str
    stored_config_result: str
    effective_scope: str
    host_restart: str
    authenticated_readiness: str

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _RECORD_ID.fullmatch(
            self.operation_id
        ):
            raise RegistrationInputError("registration result operation id is invalid")
        if self.resulting_entry_sha256 is not None and not _is_digest(
            self.resulting_entry_sha256
        ):
            raise RegistrationInputError("resulting registration digest is invalid")
        if self.ownership_origin not in ENTRY_DISPOSITIONS:
            raise RegistrationInputError("resulting registration ownership is invalid")
        if self.stored_config_result not in {
            "stored_config_verified",
            "stored_config_absent_verified",
            "unknown",
        }:
            raise RegistrationInputError("stored registration result is invalid")
        if self.effective_scope not in {"observed", "unknown"}:
            raise RegistrationInputError("effective registration scope is invalid")
        if self.host_restart not in {"required", "not_required", "unknown"}:
            raise RegistrationInputError("host restart result is invalid")
        if self.authenticated_readiness not in {"observed", "unobserved"}:
            raise RegistrationInputError("authenticated readiness result is invalid")

    def public_dict(self):
        return {
            "operation_id": self.operation_id,
            "resulting_entry_sha256": self.resulting_entry_sha256,
            "ownership_origin": self.ownership_origin,
            "stored_config_result": self.stored_config_result,
            "effective_scope": self.effective_scope,
            "host_restart": self.host_restart,
            "authenticated_readiness": self.authenticated_readiness,
            "projection_only": True,
        }


@dataclass(frozen=True)
class RegistrationOperationRecord:
    """One fixed registration operation prepared for later shared integration."""

    operation_id: str
    operation: str
    runtime: str
    source_path: str
    source_scope: str
    source_sha256: str
    complement_sha256: str
    prior_state: str
    intended_state: str
    entry_sha256: object
    entry_disposition: object
    candidate_sha256: object
    candidate_outcome: object
    qualification: object

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _RECORD_ID.fullmatch(
            self.operation_id
        ):
            raise RegistrationInputError("registration operation id is invalid")
        if self.operation not in OPERATIONS:
            raise RegistrationInputError("registration operation is not fixed")
        expected_runtime = self.operation.split("_", 1)[0]
        if self.runtime != expected_runtime or self.runtime not in OPERATION_SCOPES:
            raise RegistrationInputError("registration operation runtime differs")
        if self.source_scope != OPERATION_SCOPES[self.runtime]:
            raise RegistrationInputError("registration operation scope differs")
        if (
            not isinstance(self.source_path, str)
            or not os.path.isabs(self.source_path)
            or os.path.normpath(self.source_path) != self.source_path
        ):
            raise RegistrationInputError("registration source path is invalid")
        if not _is_digest(self.source_sha256) or not _is_digest(
            self.complement_sha256
        ):
            raise RegistrationInputError("registration source digest is invalid")
        expected_intended = (
            "matching" if self.operation.endswith("_ensure") else "absent"
        )
        if self.prior_state not in OBSERVATION_STATES:
            raise RegistrationInputError("registration prior state is invalid")
        if self.intended_state != expected_intended:
            raise RegistrationInputError("registration intended state differs")
        if self.entry_sha256 is not None and not _is_digest(self.entry_sha256):
            raise RegistrationInputError("registration entry digest is invalid")
        if (
            self.entry_disposition is not None
            and self.entry_disposition not in ENTRY_DISPOSITIONS
        ):
            raise RegistrationInputError("registration disposition is invalid")
        if self.candidate_sha256 is not None and not _is_digest(
            self.candidate_sha256
        ):
            raise RegistrationInputError("registration candidate digest is invalid")
        if self.candidate_outcome not in CANDIDATE_OUTCOMES:
            raise RegistrationInputError("registration candidate outcome is invalid")
        if self.runtime == "opencode" and self.candidate_outcome is None:
            raise RegistrationInputError("OpenCode operation requires a candidate outcome")
        if self.candidate_outcome == "candidate" and self.candidate_sha256 is None:
            raise RegistrationInputError("candidate outcome requires candidate digest")
        if self.candidate_outcome in {None, "unchanged", "refused"} and self.candidate_sha256 is not None:
            raise RegistrationInputError("non-candidate outcome cannot carry candidate digest")
        if self.runtime in {"claude", "codex"}:
            if not isinstance(self.qualification, QualificationReference):
                raise RegistrationInputError(
                    "native operation requires an ineligible qualification reference"
                )
            if self.candidate_sha256 is not None:
                raise RegistrationInputError("native operation cannot carry candidate bytes")
        elif self.qualification is not None:
            raise RegistrationInputError(
                "OpenCode semantic edit does not take native qualification"
            )

    @property
    def permitted_inverse(self):
        return OPERATION_INVERSES[self.operation]

    def public_dict(self):
        return {
            "operation_id": self.operation_id,
            "operation": self.operation,
            "runtime": self.runtime,
            "source_path": self.source_path,
            "source_scope": self.source_scope,
            "source_sha256": self.source_sha256,
            "complement_sha256": self.complement_sha256,
            "prior_state": self.prior_state,
            "intended_state": self.intended_state,
            "entry_sha256": self.entry_sha256,
            "entry_disposition": self.entry_disposition,
            "candidate_sha256": self.candidate_sha256,
            "candidate_outcome": self.candidate_outcome,
            "qualification": (
                self.qualification.public_dict()
                if self.qualification is not None
                else None
            ),
            "permitted_inverse": self.permitted_inverse,
            "automatic_apply_eligible": False,
        }


def operation_record(
    operation_id,
    operation,
    observation,
    *,
    candidate=None,
    qualification=None,
):
    """Project an existing passive observation into one strict D record."""
    if operation not in OPERATIONS:
        raise RegistrationInputError("unknown registration operation")
    runtime = operation.split("_", 1)[0]
    if observation.runtime != runtime:
        raise RegistrationInputError("operation and observation runtime differ")
    if candidate is not None and (
        candidate.operation != operation
        or candidate.runtime != runtime
        or candidate.source_path != observation.source_path
        or candidate.source_sha256 != observation.source_sha256
    ):
        raise RegistrationInputError("candidate and observation differ")
    return RegistrationOperationRecord(
        operation_id=operation_id,
        operation=operation,
        runtime=runtime,
        source_path=observation.source_path,
        source_scope=observation.source_scope,
        source_sha256=observation.source_sha256,
        complement_sha256=observation.complement_sha256,
        prior_state=observation.state,
        intended_state=("matching" if operation.endswith("_ensure") else "absent"),
        entry_sha256=observation.entry_sha256,
        entry_disposition=(
            candidate.entry_disposition
            if candidate is not None
            else observation.entry_disposition
        ),
        candidate_sha256=(candidate.candidate_sha256 if candidate is not None else None),
        candidate_outcome=(candidate.outcome if candidate is not None else None),
        qualification=qualification,
    )


def opencode_execution_record(
    operation_record_value, document, candidate, *, ownership_origin=None
):
    """Build the exact reversible byte-patch record used by shared recovery."""
    if (
        not isinstance(operation_record_value, RegistrationOperationRecord)
        or operation_record_value.runtime != "opencode"
        or candidate.operation != operation_record_value.operation
        or candidate.source_path != document.path
        or candidate.source_sha256 != _sha256(document.content)
    ):
        raise RegistrationInputError("OpenCode execution inputs differ")
    record = operation_record_value.public_dict()
    result = {
        "operation_id": record["operation_id"],
        "operation": record["operation"],
        "runtime": "opencode",
        "source_path": record["source_path"],
        "source_scope": record["source_scope"],
        "prior_sha256": record["source_sha256"],
        "target_sha256": candidate.candidate_sha256,
        "prior_entry_sha256": record["entry_sha256"],
        "target_entry_sha256": None,
        "entry_disposition": record["entry_disposition"],
        "ownership_origin": ownership_origin or record["entry_disposition"],
        "candidate_outcome": record["candidate_outcome"],
        "forward_patch": None,
        "inverse_patch": None,
        "automatic_apply_eligible": False,
    }
    if candidate.outcome == "candidate":
        target = ConfigDocument(document.path, document.scope, candidate.candidate_bytes)
        observed = observe_opencode_config(target, source_inputs_complete=True)
        expected = (
            "matching"
            if operation_record_value.operation == OPENCODE_ENSURE
            else "absent"
        )
        if observed.state != expected:
            raise RegistrationInputError("OpenCode target observation differs")
        result["target_entry_sha256"] = observed.entry_sha256
        patch = candidate.patch
        result["forward_patch"] = {
            "start": patch.start,
            "end": patch.end,
            "replacement_hex": patch.replacement.hex(),
        }
        result["inverse_patch"] = {
            "start": patch.start,
            "end": patch.start + len(patch.replacement),
            "replacement_hex": document.content[patch.start : patch.end].hex(),
        }
        result["automatic_apply_eligible"] = True
    elif candidate.outcome == "unchanged":
        result["target_sha256"] = record["source_sha256"]
        result["target_entry_sha256"] = record["entry_sha256"]
        result["automatic_apply_eligible"] = True
    return result


def build_registration_execution_preview(integration_preview, execution_records):
    """Bind reversible D records to a non-executable integration preview."""
    integration_bytes = canonical_integration_preview_bytes(integration_preview)
    if not isinstance(execution_records, (list, tuple)) or not execution_records:
        raise RegistrationInputError("registration execution records are required")
    expected_ids = {
        item["operation_id"] for item in integration_preview["operations"]
    }
    values = []
    seen = set()
    for value in execution_records:
        _validate_execution_record(value)
        operation_id = value["operation_id"]
        if operation_id in seen:
            raise RegistrationInputError("registration execution id is duplicated")
        seen.add(operation_id)
        values.append(value)
    if seen != expected_ids:
        raise RegistrationInputError("registration execution records are incomplete")
    result = {
        "registration_execution_format": REGISTRATION_EXECUTION_FORMAT,
        "executable": False,
        "integration_preview_sha256": _sha256(integration_bytes),
        "artifact_receipt": integration_preview["artifact_receipt"],
        "operations": values,
        "quiescent_edit": {
            "required": True,
            "decision": None,
        },
        "shared_recovery_extension": "required-before-apply",
    }
    canonical_registration_execution_bytes(result)
    return result


def _validate_patch(value, label):
    _exact_record_keys(value, ("start", "end", "replacement_hex"), label)
    if (
        type(value["start"]) is not int
        or type(value["end"]) is not int
        or not 0 <= value["start"] <= value["end"] <= MAX_CONFIG_BYTES
    ):
        raise RegistrationInputError(label + " bounds are invalid")
    replacement = value["replacement_hex"]
    if not isinstance(replacement, str) or len(replacement) > 2 * MAX_CONFIG_BYTES:
        raise RegistrationInputError(label + " replacement is invalid")
    try:
        bytes.fromhex(replacement)
    except ValueError as error:
        raise RegistrationInputError(label + " replacement is not hexadecimal") from error


def _validate_execution_record(value):
    _exact_record_keys(
        value,
        (
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "prior_sha256",
            "target_sha256",
            "prior_entry_sha256",
            "target_entry_sha256",
            "entry_disposition",
            "ownership_origin",
            "candidate_outcome",
            "forward_patch",
            "inverse_patch",
            "automatic_apply_eligible",
        ),
        "registration execution record",
    )
    if (
        not isinstance(value["operation_id"], str)
        or not _RECORD_ID.fullmatch(value["operation_id"])
        or value["operation"] not in {OPENCODE_ENSURE, OPENCODE_REMOVE}
        or value["runtime"] != "opencode"
        or value["source_scope"] != OPENCODE_GLOBAL
        or not isinstance(value["source_path"], str)
        or not os.path.isabs(value["source_path"])
        or os.path.normpath(value["source_path"]) != value["source_path"]
        or not _is_digest(value["prior_sha256"])
        or not _is_digest(value["target_sha256"])
        or type(value["automatic_apply_eligible"]) is not bool
        or value["ownership_origin"] not in ENTRY_DISPOSITIONS
    ):
        raise RegistrationInputError("registration execution record is invalid")
    for name in ("prior_entry_sha256", "target_entry_sha256"):
        if value[name] is not None and not _is_digest(value[name]):
            raise RegistrationInputError("registration execution entry digest is invalid")
    if value["candidate_outcome"] == "candidate":
        _validate_patch(value["forward_patch"], "forward patch")
        _validate_patch(value["inverse_patch"], "inverse patch")
    elif value["candidate_outcome"] == "unchanged":
        if (
            value["forward_patch"] is not None
            or value["inverse_patch"] is not None
            or value["prior_sha256"] != value["target_sha256"]
        ):
            raise RegistrationInputError("unchanged registration execution is invalid")
    else:
        raise RegistrationInputError("refused registration cannot enter execution")


def canonical_registration_execution_bytes(preview):
    _exact_record_keys(
        preview,
        (
            "registration_execution_format",
            "executable",
            "integration_preview_sha256",
            "artifact_receipt",
            "operations",
            "quiescent_edit",
            "shared_recovery_extension",
        ),
        "registration execution preview",
    )
    if (
        preview["registration_execution_format"]
        != REGISTRATION_EXECUTION_FORMAT
        or preview["executable"] is not False
        or not _is_digest(preview["integration_preview_sha256"])
        or preview["shared_recovery_extension"] != "required-before-apply"
    ):
        raise RegistrationInputError("registration execution preview is invalid")
    if preview["quiescent_edit"] != {"required": True, "decision": None}:
        raise RegistrationInputError("registration execution preview carries authority")
    for value in preview["operations"]:
        _validate_execution_record(value)
    return (
        json.dumps(preview, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _public_digest_record(value, label):
    if not hasattr(value, "public_dict") or not hasattr(value, "digest"):
        raise RegistrationInputError(label + " must be a validated record")
    public = value.public_dict()
    digest = value.digest()
    if not isinstance(public, dict) or not _is_digest(digest):
        raise RegistrationInputError(label + " public identity is invalid")
    if _sha256(
        json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ) != digest:
        raise RegistrationInputError(label + " digest differs from its public record")
    return public, digest


def build_native_plan_core(
    artifact_receipt,
    operation_id,
    operation,
    observation,
    stdio,
    implementation,
    policy,
    support,
    qualification_admission,
    runtime_tuple,
):
    """Build the authority-free native-v3 plan core confirmed before apply."""
    if operation not in {
        CLAUDE_ENSURE,
        CLAUDE_REMOVE,
        CODEX_ENSURE,
        CODEX_REMOVE,
    }:
        raise RegistrationInputError("native plan operation is not fixed")
    if not isinstance(operation_id, str) or not _RECORD_ID.fullmatch(operation_id):
        raise RegistrationInputError("native plan operation id is invalid")
    runtime = operation.split("_", 1)[0]
    if observation.runtime != runtime or observation.source_scope != OPERATION_SCOPES[runtime]:
        raise RegistrationInputError("native plan observation differs")
    if not isinstance(stdio, StdioSpec):
        raise RegistrationInputError("native plan stdio identity is invalid")
    if not isinstance(artifact_receipt, ArtifactReceiptBinding):
        raise RegistrationInputError("native plan requires an artifact receipt")
    records = {}
    for name, value in (
        ("implementation_identity", implementation),
        ("qualification_support", support),
        ("qualification_admission", qualification_admission),
        ("runtime_tuple", runtime_tuple),
    ):
        public, digest = _public_digest_record(value, name)
        records[name] = {"record": public, "sha256": digest}
    if not hasattr(policy, "public_dict") or not hasattr(policy, "digest"):
        raise RegistrationInputError("shape policy must be a validated record")
    policy_public = policy.public_dict()
    policy_source_sha256 = policy.digest()
    if (
        not isinstance(policy_public, dict)
        or not _is_digest(policy_source_sha256)
        or policy_public.get("policy_sha256") != policy_source_sha256
        or policy_public.get("qualification_eligible") is not False
    ):
        raise RegistrationInputError("shape policy source identity is invalid")
    records["shape_policy"] = {
        "record": policy_public,
        "sha256": _sha256(
            json.dumps(
                policy_public, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ),
        "source_sha256": policy_source_sha256,
    }
    core = {
        "native_registration_plan_format": NATIVE_REGISTRATION_PLAN_FORMAT,
        "executable": False,
        "operation_id": operation_id,
        "operation": operation,
        "runtime": runtime,
        "source_path": observation.source_path,
        "source_scope": observation.source_scope,
        "source_sha256": observation.source_sha256,
        "prior_state": observation.state,
        "prior_entry_sha256": observation.entry_sha256,
        "prior_complement_sha256": observation.complement_sha256,
        "stdio": {
            "python_executable": stdio.python_executable,
            "adapter_path": stdio.adapter_path,
        },
        "artifact_receipt": artifact_receipt.public_dict(),
        "records": records,
        "required_gates": [
            "owner-recorded-qualification-admission",
            "exact-current-attempt-binding",
            "fresh-sequence-quiescent-decision",
            "single-c1-writer-lease",
            "complete-process-network-write-observation",
        ],
        "native_success_activated": False,
    }
    canonical_native_plan_core_bytes(core)
    return core


def canonical_native_plan_core_bytes(core):
    _exact_record_keys(
        core,
        (
            "native_registration_plan_format",
            "executable",
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "source_sha256",
            "prior_state",
            "prior_entry_sha256",
            "prior_complement_sha256",
            "stdio",
            "artifact_receipt",
            "records",
            "required_gates",
            "native_success_activated",
        ),
        "native plan core",
    )
    if (
        core["native_registration_plan_format"] != NATIVE_REGISTRATION_PLAN_FORMAT
        or core["executable"] is not False
        or core["native_success_activated"] is not False
        or core["operation"]
        not in {CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE}
        or core["runtime"] != core["operation"].split("_", 1)[0]
        or core["source_scope"] != OPERATION_SCOPES[core["runtime"]]
        or not isinstance(core["operation_id"], str)
        or not _RECORD_ID.fullmatch(core["operation_id"])
        or not isinstance(core["source_path"], str)
        or not os.path.isabs(core["source_path"])
        or os.path.normpath(core["source_path"]) != core["source_path"]
        or not _is_digest(core["source_sha256"])
        or not _is_digest(core["prior_complement_sha256"])
    ):
        raise RegistrationInputError("native plan core is invalid")
    if core["prior_entry_sha256"] is not None and not _is_digest(
        core["prior_entry_sha256"]
    ):
        raise RegistrationInputError("native plan prior entry identity is invalid")
    _exact_record_keys(
        core["stdio"], ("python_executable", "adapter_path"), "native plan stdio"
    )
    StdioSpec(core["stdio"]["python_executable"], core["stdio"]["adapter_path"])
    ArtifactReceiptBinding.from_summary(core["artifact_receipt"])
    if set(core["records"]) != {
        "implementation_identity",
        "shape_policy",
        "qualification_support",
        "qualification_admission",
        "runtime_tuple",
    }:
        raise RegistrationInputError("native plan record set is invalid")
    for name, value in core["records"].items():
        expected_keys = (
            ("record", "sha256", "source_sha256")
            if name == "shape_policy"
            else ("record", "sha256")
        )
        _exact_record_keys(value, expected_keys, "native plan " + name)
        if not isinstance(value["record"], dict) or not _is_digest(value["sha256"]):
            raise RegistrationInputError("native plan record identity is invalid")
        if _sha256(
            json.dumps(value["record"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ) != value["sha256"]:
            raise RegistrationInputError("native plan record digest differs")
        if name == "shape_policy" and (
            not _is_digest(value["source_sha256"])
            or value["record"].get("policy_sha256") != value["source_sha256"]
            or value["record"].get("qualification_eligible") is not False
        ):
            raise RegistrationInputError("native shape policy source digest differs")
    if core["required_gates"] != [
        "owner-recorded-qualification-admission",
        "exact-current-attempt-binding",
        "fresh-sequence-quiescent-decision",
        "single-c1-writer-lease",
        "complete-process-network-write-observation",
    ]:
        raise RegistrationInputError("native plan gates differ")
    return (
        json.dumps(core, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def finalize_native_execution(
    core, attempt_family, attempt_binding, result_identity,
    execution_admission=None
):
    """Bind current-attempt and semantic receipt identities after confirmation."""
    core_bytes = canonical_native_plan_core_bytes(core)
    binding, binding_sha256 = _public_digest_record(
        attempt_binding, "native attempt binding"
    )
    family, family_sha256 = _public_digest_record(
        attempt_family, "native attempt family"
    )
    result, result_sha256 = _public_digest_record(
        result_identity, "native result identity"
    )
    execution_admission_record, execution_admission_sha256 = _public_digest_record(
        execution_admission, "native execution admission"
    )
    execution = {
        "native_registration_execution_format": NATIVE_REGISTRATION_EXECUTION_FORMAT,
        "executable": False,
        "plan_core_sha256": _sha256(core_bytes),
        "operation_id": core["operation_id"],
        "operation": core["operation"],
        "runtime": core["runtime"],
        "source_path": core["source_path"],
        "source_scope": core["source_scope"],
        "attempt_family": {"record": family, "sha256": family_sha256},
        "attempt_binding": {"record": binding, "sha256": binding_sha256},
        "execution_admission": {
            "record": execution_admission_record,
            "sha256": execution_admission_sha256,
        },
        "semantic_result_identity": {"record": result, "sha256": result_sha256},
        "copied_recovery_closure": "native-v3-three-module-closure",
        "native_success_activated": False,
    }
    canonical_native_execution_bytes(execution)
    return execution


def canonical_native_execution_bytes(execution):
    _exact_record_keys(
        execution,
        (
            "native_registration_execution_format",
            "executable",
            "plan_core_sha256",
            "operation_id",
            "operation",
            "runtime",
            "source_path",
            "source_scope",
            "attempt_family",
            "attempt_binding",
            "execution_admission",
            "semantic_result_identity",
            "copied_recovery_closure",
            "native_success_activated",
        ),
        "native registration execution",
    )
    if (
        execution["native_registration_execution_format"]
        != NATIVE_REGISTRATION_EXECUTION_FORMAT
        or execution["executable"] is not False
        or execution["native_success_activated"] is not False
        or not _is_digest(execution["plan_core_sha256"])
        or execution["operation"]
        not in {CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE}
        or execution["runtime"] != execution["operation"].split("_", 1)[0]
        or execution["source_scope"] != OPERATION_SCOPES[execution["runtime"]]
        or execution["copied_recovery_closure"]
        != "native-v3-three-module-closure"
    ):
        raise RegistrationInputError("native registration execution is invalid")
    for name in (
        "attempt_binding",
        "attempt_family",
        "execution_admission",
        "semantic_result_identity",
    ):
        value = execution[name]
        _exact_record_keys(value, ("record", "sha256"), "native " + name)
        if not isinstance(value["record"], dict) or not _is_digest(value["sha256"]):
            raise RegistrationInputError("native execution record is invalid")
        if _sha256(
            json.dumps(value["record"], sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ) != value["sha256"]:
            raise RegistrationInputError("native execution record digest differs")
    return (
        json.dumps(execution, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def render_plan_summary(operation, observation, candidate=None):
    """Return a fixed redacted plan projection for later C2 integration."""
    if operation not in OPERATIONS:
        raise RegistrationInputError("unknown registration operation")
    expected_runtime = operation.split("_", 1)[0]
    if expected_runtime != observation.runtime:
        raise RegistrationInputError("operation and observation runtime differ")
    if candidate is not None:
        if candidate.operation != operation or candidate.source_sha256 != observation.source_sha256:
            raise RegistrationInputError("candidate and observation differ")
        candidate_digest = candidate.candidate_sha256
        candidate_outcome = candidate.outcome
        candidate_reason = candidate.reason
    else:
        candidate_digest = None
        candidate_outcome = None
        candidate_reason = None
    keys = {
        "claude": "mcpServers.council",
        "codex": "mcp_servers.council",
        "opencode": "plugin",
    }
    intended = {
        "claude": "<fixed-council-stdio-entry>",
        "codex": "<fixed-council-stdio-entry>",
        "opencode": "<council-plugin-entry>",
    }
    inverses = {
        CLAUDE_ENSURE: CLAUDE_REMOVE,
        CLAUDE_REMOVE: CLAUDE_ENSURE,
        CODEX_ENSURE: CODEX_REMOVE,
        CODEX_REMOVE: CODEX_ENSURE,
        OPENCODE_ENSURE: OPENCODE_REMOVE,
        OPENCODE_REMOVE: OPENCODE_ENSURE,
    }
    return {
        "operation": operation,
        "runtime": observation.runtime,
        "source_path": observation.source_path,
        "source_sha256": observation.source_sha256,
        "selected_key": keys[observation.runtime],
        "intended_entry": intended[observation.runtime],
        "permitted_inverse": inverses[operation],
        "observation_state": observation.state,
        "observation_reason": observation.reason,
        "entry_disposition": observation.entry_disposition,
        "candidate_eligible": observation.candidate_eligible,
        "candidate_sha256": candidate_digest,
        "candidate_outcome": candidate_outcome,
        "candidate_reason": candidate_reason,
        "native_argv": None,
        "native_qualified": False,
        "apply_authorized": False,
        "quiescent_admission_integrated": False,
    }


def _exact_record_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise RegistrationInputError(label + " has an unexpected shape")


def _strict_object_bytes(data, label):
    if not isinstance(data, bytes) or len(data) > MAX_CONFIG_BYTES:
        raise RegistrationInputError(label + " must be bounded bytes")

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RegistrationInputError(label + " has a duplicate key")
            value[key] = item
        return value

    def reject_constant(value):
        raise RegistrationInputError(label + " has a non-finite number: " + value)

    try:
        parsed = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, RegistrationInputError):
            raise
        raise RegistrationInputError(label + " is not strict UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise RegistrationInputError(label + " must be an object")
    canonical = (
        json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if canonical != data:
        raise RegistrationInputError(label + " is not canonical C2 JSON")
    return parsed


def validate_c2_contract(contract):
    """Validate the closed artifact-only interface packet D was admitted against."""
    _exact_record_keys(
        contract,
        (
            "contract_format",
            "source_commit",
            "source_hashes",
            "inspection_interfaces",
            "format_versions",
            "unit_ids",
            "required_operations",
            "planner_interfaces",
            "recovery_interfaces",
            "bundle_keys",
            "external_command",
        ),
        "C2 contract",
    )
    if contract["contract_format"] != C2_CONTRACT_FORMAT:
        raise RegistrationInputError("unsupported C2 contract format")
    if contract["source_commit"] != C2_SOURCE_COMMIT:
        raise RegistrationInputError("C2 source commit changed")
    hashes = contract["source_hashes"]
    _exact_record_keys(
        hashes,
        tuple(C2_SOURCE_HASHES),
        "C2 source hashes",
    )
    if hashes != C2_SOURCE_HASHES:
        raise RegistrationInputError("C2 source hashes changed")
    if tuple(contract["inspection_interfaces"]) != C2_INSPECTION_INTERFACES:
        raise RegistrationInputError("C2 inspection interfaces changed")
    if contract["format_versions"] != C2_FORMAT_VERSIONS:
        raise RegistrationInputError("C2 format versions changed")
    if tuple(contract["unit_ids"]) != C2_UNIT_IDS:
        raise RegistrationInputError("C2 artifact units changed")
    if tuple(contract["required_operations"]) != C2_REQUIRED_OPERATIONS:
        raise RegistrationInputError("C2 required operations changed")
    if tuple(contract["planner_interfaces"]) != C2_PLANNER_INTERFACES:
        raise RegistrationInputError("C2 planner interfaces changed")
    if tuple(contract["recovery_interfaces"]) != C2_RECOVERY_INTERFACES:
        raise RegistrationInputError("C2 recovery interfaces changed")
    if tuple(contract["bundle_keys"]) != C2_BUNDLE_KEYS:
        raise RegistrationInputError("C2 transaction bundle changed")
    if tuple(contract["external_command"]) != C2_EXTERNAL_COMMAND:
        raise RegistrationInputError("C2 external command changed")
    return contract


def _validate_c2_preview(data):
    preview = _strict_object_bytes(data, "C2 planning preview")
    _exact_record_keys(
        preview,
        (
            "planning_preview_format",
            "executable",
            "non_executable_reason",
            "kind",
            "roots",
            "release",
            "current",
            "eligible_for_integration",
            "blockers",
            "required_gates",
            "payload_cache_backup",
            "units",
            "artifacts",
        ),
        "C2 planning preview",
    )
    if preview["planning_preview_format"] != 1 or preview["executable"] is not False:
        raise RegistrationInputError("C2 preview must remain non-executable v1")
    if preview["kind"] not in {
        "install", "upgrade", "rollback", "uninstall", "registration"
    }:
        raise RegistrationInputError("C2 preview kind is unsupported")
    if not isinstance(preview["blockers"], list) or not isinstance(
        preview["required_gates"], list
    ):
        raise RegistrationInputError("C2 preview blockers/gates are invalid")
    current = preview["current"]
    _exact_record_keys(
        current,
        ("status", "certified", "reason", "summary"),
        "C2 current artifact state",
    )
    if type(current["certified"]) is not bool:
        raise RegistrationInputError("C2 artifact certification is invalid")
    return preview


def build_integration_preview(
    c2_preview_bytes,
    c2_contract,
    operations,
    *,
    artifact_receipt=None,
):
    """Bind strict D records to a real canonical C2 artifact preview.

    The result is deliberately incapable of execution.  Shared lifecycle/recovery
    integration must consume it later under a separate path admission.
    """
    validate_c2_contract(c2_contract)
    c2_preview = _validate_c2_preview(c2_preview_bytes)
    if not isinstance(operations, (list, tuple)) or not operations:
        raise RegistrationInputError("registration operations are required")
    operation_values = []
    operation_ids = set()
    for operation in operations:
        if not isinstance(operation, RegistrationOperationRecord):
            raise RegistrationInputError("registration operation record is invalid")
        if operation.operation_id in operation_ids:
            raise RegistrationInputError("registration operation id is duplicated")
        operation_ids.add(operation.operation_id)
        operation_values.append(operation.public_dict())
    summary = c2_preview["current"]["summary"]
    if summary is None:
        if artifact_receipt is not None:
            raise RegistrationInputError(
                "unmanaged artifact preview cannot bind a prior receipt"
            )
        receipt_value = None
    else:
        if not isinstance(artifact_receipt, ArtifactReceiptBinding):
            raise RegistrationInputError(
                "managed artifact preview requires its immutable receipt binding"
            )
        receipt_value = artifact_receipt.public_dict()
        if receipt_value != ArtifactReceiptBinding.from_summary(summary).public_dict():
            raise RegistrationInputError("artifact receipt binding differs from C2")
    reasons = [
        "c2-registration-format-extension-not-admitted",
        "quiescent-edit-admission-not-integrated",
    ]
    if not c2_preview["eligible_for_integration"] or c2_preview["blockers"]:
        reasons.append("c2-artifact-preview-blocked")
    if any(value["runtime"] in {"claude", "codex"} for value in operation_values):
        reasons.append("native-behavior-unqualified")
    if any(value["candidate_outcome"] == "refused" for value in operation_values):
        reasons.append("registration-operation-refused")
    result = {
        "registration_integration_format": REGISTRATION_INTEGRATION_FORMAT,
        "executable": False,
        "non_executable_reasons": sorted(set(reasons)),
        "c2_contract": {
            "source_commit": c2_contract["source_commit"],
            "source_hashes": c2_contract["source_hashes"],
            "format_versions": c2_contract["format_versions"],
        },
        "c2_preview_sha256": _sha256(c2_preview_bytes),
        "c2_kind": c2_preview["kind"],
        "artifact_receipt": receipt_value,
        "operations": operation_values,
        "records_ready_for_shared_integration": (
            c2_preview["eligible_for_integration"]
            and not c2_preview["blockers"]
            and not any(
                value["candidate_outcome"] == "refused"
                for value in operation_values
            )
        ),
        "execution_requirements": {
            "single_c1_lease": True,
            "shared_format_extension": "pending-separate-admission",
            "quiescent_edit": "required-not-provided",
            "native_qualification": "required-not-qualified",
            "c2_v1_registration_behavior": "refuse",
        },
    }
    canonical_integration_preview_bytes(result)
    return result


def canonical_integration_preview_bytes(preview):
    """Validate and encode a D-only preview without executable plan fields."""
    _exact_record_keys(
        preview,
        (
            "registration_integration_format",
            "executable",
            "non_executable_reasons",
            "c2_contract",
            "c2_preview_sha256",
            "c2_kind",
            "artifact_receipt",
            "operations",
            "records_ready_for_shared_integration",
            "execution_requirements",
        ),
        "registration integration preview",
    )
    if (
        preview["registration_integration_format"]
        != REGISTRATION_INTEGRATION_FORMAT
        or preview["executable"] is not False
    ):
        raise RegistrationInputError("registration preview must remain non-executable")
    forbidden = {
        "plan_format",
        "intent",
        "recovery_required",
        "native_argv",
        "apply_authorized",
        "quiescent_admission_integrated",
    }

    def visit(value):
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise RegistrationInputError(
                    "registration preview contains executable transaction fields"
                )
            if value.get("automatic_apply_eligible") not in (None, False):
                raise RegistrationInputError("registration preview claims automatic apply")
            if value.get("qualification_eligible") not in (None, False):
                raise RegistrationInputError("registration preview claims qualification")
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(preview)
    return (
        json.dumps(preview, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True)
class _JSONMember:
    key: str
    key_start: int
    key_end: int
    value: object


@dataclass(frozen=True)
class _JSONNode:
    kind: str
    start: int
    end: int
    value: object


_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


class _JSONParser:
    def __init__(self, raw):
        self.raw = raw
        self.position = 0
        self.nodes = 0

    def parse(self):
        try:
            self.raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _JSONError("invalid_utf8")
        node = self._value(0)
        self._space()
        if self.position != len(self.raw):
            raise _JSONError("strict_json_required")
        return node

    def _space(self):
        while self.position < len(self.raw) and self.raw[self.position] in b" \t\r\n":
            self.position += 1

    def _value(self, depth):
        if depth > MAX_JSON_DEPTH:
            raise _JSONError("json_depth_exceeded")
        self.nodes += 1
        if self.nodes > MAX_JSON_NODES:
            raise _JSONError("json_node_limit_exceeded")
        self._space()
        if self.position >= len(self.raw):
            raise _JSONError("strict_json_required")
        token = self.raw[self.position]
        if token == 0x7B:
            return self._object(depth)
        if token == 0x5B:
            return self._array(depth)
        if token == 0x22:
            return self._string()
        for literal, kind, value in (
            (b"true", "bool", True),
            (b"false", "bool", False),
            (b"null", "null", None),
        ):
            if self.raw.startswith(literal, self.position):
                start = self.position
                self.position += len(literal)
                return _JSONNode(kind, start, self.position, value)
        match = _NUMBER.match(self.raw, self.position)
        if match is not None:
            start = self.position
            self.position = match.end()
            return _JSONNode("number", start, self.position, None)
        raise _JSONError("strict_json_required")

    def _string(self):
        start = self.position
        self.position += 1
        escaped = False
        while self.position < len(self.raw):
            value = self.raw[self.position]
            if value < 0x20:
                raise _JSONError("strict_json_required")
            if escaped:
                if value == 0x75:
                    digits = self.raw[self.position + 1 : self.position + 5]
                    if len(digits) != 4 or any(
                        char not in b"0123456789abcdefABCDEF" for char in digits
                    ):
                        raise _JSONError("strict_json_required")
                    self.position += 5
                elif value in b'"\\/bfnrt':
                    self.position += 1
                else:
                    raise _JSONError("strict_json_required")
                escaped = False
                continue
            if value == 0x5C:
                escaped = True
                self.position += 1
                continue
            if value == 0x22:
                self.position += 1
                token = self.raw[start : self.position]
                try:
                    decoded = json.loads(token.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    raise _JSONError("strict_json_required")
                return _JSONNode("string", start, self.position, decoded)
            self.position += 1
        raise _JSONError("strict_json_required")

    def _object(self, depth):
        start = self.position
        self.position += 1
        members = []
        seen = set()
        self._space()
        if self.position < len(self.raw) and self.raw[self.position] == 0x7D:
            self.position += 1
            return _JSONNode("object", start, self.position, tuple(members))
        while True:
            self._space()
            if self.position >= len(self.raw) or self.raw[self.position] != 0x22:
                raise _JSONError("strict_json_required")
            key_node = self._string()
            if key_node.value in seen:
                raise _JSONError("duplicate_json_key")
            seen.add(key_node.value)
            self._space()
            if self.position >= len(self.raw) or self.raw[self.position] != 0x3A:
                raise _JSONError("strict_json_required")
            self.position += 1
            value = self._value(depth + 1)
            members.append(
                _JSONMember(
                    key_node.value,
                    key_node.start,
                    key_node.end,
                    value,
                )
            )
            self._space()
            if self.position >= len(self.raw):
                raise _JSONError("strict_json_required")
            if self.raw[self.position] == 0x7D:
                self.position += 1
                return _JSONNode("object", start, self.position, tuple(members))
            if self.raw[self.position] != 0x2C:
                raise _JSONError("strict_json_required")
            self.position += 1

    def _array(self, depth):
        start = self.position
        self.position += 1
        items = []
        self._space()
        if self.position < len(self.raw) and self.raw[self.position] == 0x5D:
            self.position += 1
            return _JSONNode("array", start, self.position, tuple(items))
        while True:
            items.append(self._value(depth + 1))
            self._space()
            if self.position >= len(self.raw):
                raise _JSONError("strict_json_required")
            if self.raw[self.position] == 0x5D:
                self.position += 1
                return _JSONNode("array", start, self.position, tuple(items))
            if self.raw[self.position] != 0x2C:
                raise _JSONError("strict_json_required")
            self.position += 1


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _is_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _bounded(document, expected_scope):
    if document.scope != expected_scope:
        raise RegistrationInputError(
            "expected %s document, got %s" % (expected_scope, document.scope)
        )
    if len(document.content) > MAX_CONFIG_BYTES:
        raise RegistrationInputError("config exceeds byte limit")


def _json(document):
    if len(document.content) > MAX_CONFIG_BYTES:
        raise RegistrationInputError("config exceeds byte limit")
    return _JSONParser(document.content).parse()


def _member(node, key):
    if node.kind != "object":
        return None
    for member in node.value:
        if member.key == key:
            return member
    return None


def _object_keys(node):
    if node.kind != "object":
        return set()
    return {member.key for member in node.value}


def _node_digest(raw, node):
    return _sha256(raw[node.start : node.end])


def _masked_digest(raw, nodes):
    """Hash exact bytes after replacing selected spans with a fixed marker."""
    pieces = []
    position = 0
    for node in sorted(nodes, key=lambda item: item.start):
        if node.start < position:
            raise AssertionError("overlapping digest spans")
        pieces.append(raw[position : node.start])
        pieces.append(b"<selected-council-entry>")
        position = node.end
    pieces.append(raw[position:])
    return _sha256(b"".join(pieces))


def _member_removed_digest(raw, object_node, selected):
    """Hash exact bytes after removing one complete JSON object member."""
    members = list(object_node.value)
    index = members.index(selected)
    if len(members) == 1:
        start, end = selected.key_start, selected.value.end
    elif index < len(members) - 1:
        start, end = selected.key_start, members[index + 1].key_start
    else:
        start, end = members[index - 1].value.end, selected.value.end
    return _sha256(raw[:start] + raw[end:])


def _ownership_disposition(ownership, runtime, path, entry_sha256):
    if ownership is None:
        return "matching_preexisting_unowned", False
    if ownership.runtime != runtime or ownership.source_path != path:
        return "matching_preexisting_unowned", False
    if ownership.entry_sha256 != entry_sha256:
        return None, False
    if ownership.origin == "adopted_by_explicit_plan":
        return "adopted_by_explicit_plan", True
    return "already_owned", True


def _strict_stdio_entry(node, raw, spec):
    if node.kind != "object":
        return "unsupported", (), _node_digest(raw, node)
    fields = _object_keys(node)
    unknown = tuple(sorted(fields - {"type", "command", "args"}))
    type_node = _member(node, "type")
    command = _member(node, "command")
    args = _member(node, "args")
    matches = (
        type_node is not None
        and type_node.value.kind == "string"
        and type_node.value.value == "stdio"
        and command is not None
        and command.value.kind == "string"
        and command.value.value == spec.python_executable
        and args is not None
        and args.value.kind == "array"
        and len(args.value.value) == 1
        and args.value.value[0].kind == "string"
        and args.value.value[0].value == spec.adapter_path
    )
    if unknown:
        if "disabled" in unknown or "enabled" in unknown:
            return "disabled", _public_field_labels(unknown), _node_digest(raw, node)
        return "unknown_fields", _public_field_labels(unknown), _node_digest(raw, node)
    if fields != {"type", "command", "args"}:
        return "unsupported", (), _node_digest(raw, node)
    return ("matching" if matches else "customized"), (), _node_digest(raw, node)


def _parse_claude_selected(document, spec):
    try:
        root = _json(document)
    except _JSONError as error:
        return error.code, None, (), 0, 0, _sha256(document.content)
    if root.kind != "object":
        return "unsupported_schema", None, (), 0, 0, _sha256(document.content)
    servers = _member(root, "mcpServers")
    if servers is None:
        return "absent", None, (), 0, 0, _sha256(document.content)
    if servers.value.kind != "object":
        return "unsupported_schema", None, (), 0, 0, _sha256(document.content)
    selected = _member(servers.value, "council")
    aliases = 0
    for server in servers.value.value:
        if server.key == "council":
            continue
        state, _, _ = _strict_stdio_entry(server.value, document.content, spec)
        if state == "matching":
            aliases += 1
    if selected is None:
        return (
            "ambiguous_identity" if aliases else "absent",
            None,
            (),
            aliases,
            len(servers.value.value),
            _sha256(document.content),
        )
    state, unknown, digest = _strict_stdio_entry(
        selected.value, document.content, spec
    )
    if aliases:
        state = "ambiguous_identity"
    return (
        state,
        digest,
        unknown,
        aliases,
        len(servers.value.value) - 1,
        _member_removed_digest(document.content, servers.value, selected),
    )


def _parse_claude_local(document, project_key, spec):
    """Inspect exactly one caller-selected local project key; never scan projects."""
    try:
        root = _json(document)
    except _JSONError as error:
        return error.code
    projects = _member(root, "projects") if root.kind == "object" else None
    if projects is None:
        return "absent"
    if projects.value.kind != "object":
        return "unsupported_schema"
    project = _member(projects.value, project_key)
    if project is None:
        return "absent"
    if project.value.kind != "object":
        return "unsupported_schema"
    servers = _member(project.value, "mcpServers")
    if servers is None:
        return "absent"
    if servers.value.kind != "object":
        return "unsupported_schema"
    selected = _member(servers.value, "council")
    if selected is None:
        return "absent"
    state, _, _ = _strict_stdio_entry(selected.value, document.content, spec)
    return state


def observe_claude_config(
    document,
    spec,
    ownership=None,
    *,
    project_documents=(),
    current_project_key=None,
    scope_inputs_complete=False,
):
    """Observe only Claude's explicit user entry and supplied scope overrides.

    ``project_documents`` must contain explicit ``claude_project`` or
    ``claude_local`` snapshots.  ``current_project_key`` selects at most one
    local-project entry inside the user document.  No other project is read.
    """
    _bounded(document, CLAUDE_USER)
    state, entry_digest, unknown, alias, unrelated_count, complement = (
        _parse_claude_selected(document, spec)
    )
    competing = []
    if current_project_key is not None:
        if not isinstance(current_project_key, str) or not current_project_key:
            raise RegistrationInputError("current project key must be nonempty")
        local_state = _parse_claude_local(document, current_project_key, spec)
        if local_state != "absent":
            competing.append("claude_local:" + local_state)
    seen = set()
    for candidate in project_documents:
        if candidate.scope not in {CLAUDE_PROJECT, CLAUDE_LOCAL}:
            raise RegistrationInputError("invalid Claude override scope")
        _bounded(candidate, candidate.scope)
        identity = (candidate.scope, candidate.path)
        if identity in seen:
            competing.append(candidate.scope + ":duplicate_source")
            continue
        seen.add(identity)
        override_state, _, _, _, _, _ = _parse_claude_selected(candidate, spec)
        if override_state != "absent":
            competing.append(candidate.scope + ":" + override_state)
    if not scope_inputs_complete:
        competing.append("scope_inputs_incomplete")
    disposition = None
    owned = False
    if state == "matching":
        disposition, owned = _ownership_disposition(
            ownership, "claude", document.path, entry_digest
        )
    reason = state
    eligible = state in {"absent", "matching"} and not competing and not alias
    if state == "matching" and ownership is not None and not owned:
        reason = "ownership_mismatch"
        eligible = False
    if competing:
        reason = "scope_ambiguous"
        eligible = False
    return RegistrationObservation(
        "claude",
        document.path,
        document.scope,
        _sha256(document.content),
        state,
        reason,
        entry_digest,
        disposition,
        eligible,
        unknown,
        (1 if entry_digest is not None else 0) + alias,
        unrelated_count,
        complement,
        tuple(competing),
        "unobserved",
        "stdlib_json",
    )


def _semantic_digest(value):
    def encode(item):
        if isinstance(item, dict):
            return ["dict", [[key, encode(item[key])] for key in sorted(item)]]
        if isinstance(item, list):
            return ["list", [encode(child) for child in item]]
        if isinstance(item, tuple):
            return ["tuple", [encode(child) for child in item]]
        if isinstance(item, bool):
            return ["bool", item]
        if isinstance(item, str):
            return ["str", item]
        if isinstance(item, int):
            return ["int", str(item)]
        if isinstance(item, float):
            return ["float", repr(item)]
        if item is None:
            return ["null", None]
        if hasattr(item, "isoformat"):
            return [type(item).__name__, item.isoformat()]
        return [type(item).__name__, repr(item)]

    return _sha256(json.dumps(encode(value), separators=(",", ":")).encode())


def _public_field_labels(fields):
    safe = {
        "allowedTools",
        "args",
        "command",
        "disabled",
        "enabled",
        "env",
        "timeout",
        "type",
    }
    labels = []
    for field in fields:
        if field in safe:
            labels.append(field)
        else:
            encoded = field.encode("utf-8", errors="backslashreplace")
            labels.append("other:" + _sha256(encoded)[:12])
    return tuple(sorted(labels))


def _toml_stdio_state(entry, spec):
    if not isinstance(entry, dict):
        return "unsupported", (), _semantic_digest(entry)
    unknown = tuple(sorted(set(entry) - {"command", "args"}))
    matches = (
        entry.get("command") == spec.python_executable
        and entry.get("args") == [spec.adapter_path]
    )
    if unknown:
        if "enabled" in unknown or "disabled" in unknown:
            return "disabled", _public_field_labels(unknown), _semantic_digest(entry)
        return "unknown_fields", _public_field_labels(unknown), _semantic_digest(entry)
    if set(entry) != {"command", "args"}:
        return "unsupported", (), _semantic_digest(entry)
    return ("matching" if matches else "customized"), (), _semantic_digest(entry)


def observe_codex_config(
    document,
    spec,
    ownership=None,
    *,
    layer_inputs_complete=False,
):
    """Observe Codex TOML with this interpreter's stdlib parser, when present."""
    _bounded(document, CODEX_USER)
    source_digest = _sha256(document.content)
    capability = (
        "stdlib_tomllib:%d.%d:%s"
        % (sys.version_info[0], sys.version_info[1], sys.executable)
        if _tomllib is not None
        else "parser_unavailable:stdlib_tomllib"
    )
    if _tomllib is None:
        return RegistrationObservation(
            "codex",
            document.path,
            document.scope,
            source_digest,
            "parser_unavailable",
            "parser_unavailable",
            None,
            None,
            False,
            (),
            0,
            0,
            source_digest,
            ("layer_inputs_incomplete",) if not layer_inputs_complete else (),
            "unobserved",
            capability,
        )
    try:
        decoded = document.content.decode("utf-8")
        parsed = _tomllib.loads(decoded)
    except (UnicodeDecodeError, ValueError):
        return RegistrationObservation(
            "codex",
            document.path,
            document.scope,
            source_digest,
            "malformed",
            "invalid_toml",
            None,
            None,
            False,
            (),
            0,
            0,
            source_digest,
            (),
            "unobserved",
            capability,
        )
    servers = parsed.get("mcp_servers")
    state = "absent"
    entry_digest = None
    unknown = ()
    alias_count = 0
    unrelated_count = 0
    complement = source_digest
    if servers is not None and not isinstance(servers, dict):
        state = "unsupported_schema"
    elif servers is None:
        complement_root = dict(parsed)
        complement_root["mcp_servers"] = {}
        complement = _semantic_digest(complement_root)
    elif isinstance(servers, dict):
        selected = servers.get("council")
        if selected is not None:
            state, unknown, entry_digest = _toml_stdio_state(selected, spec)
        for name, entry in servers.items():
            if name == "council":
                continue
            sibling_state, _, _ = _toml_stdio_state(entry, spec)
            if sibling_state == "matching":
                alias_count += 1
        unrelated_count = len(servers) - (1 if "council" in servers else 0)
        complement_root = dict(parsed)
        complement_servers = dict(servers)
        complement_servers.pop("council", None)
        complement_root["mcp_servers"] = complement_servers
        complement = _semantic_digest(complement_root)
        if alias_count:
            state = "ambiguous_identity"
    disposition = None
    owned = False
    if state == "matching":
        disposition, owned = _ownership_disposition(
            ownership, "codex", document.path, entry_digest
        )
    competing = () if layer_inputs_complete else ("layer_inputs_incomplete",)
    reason = state
    if ownership is not None and state == "matching" and not owned:
        reason = "ownership_mismatch"
    elif competing:
        reason = "scope_ambiguous"
    # Parsing does not qualify Codex's whole-map native writer, so this passive
    # core never marks an automatic native operation eligible.
    return RegistrationObservation(
        "codex",
        document.path,
        document.scope,
        source_digest,
        state,
        reason,
        entry_digest,
        disposition,
        False,
        unknown,
        (1 if entry_digest is not None else 0) + alias_count,
        unrelated_count,
        complement,
        competing,
        "unobserved",
        capability,
    )


def _plugin_identity(value):
    if value == OPENCODE_COUNCIL_PLUGIN:
        return "exact"
    if not isinstance(value, str) or "\x00" in value:
        return None
    normalized = posixpath.normpath(value)
    if posixpath.basename(normalized) == "council-plugin.ts":
        return "alias"
    return None


def _opencode_shape(document):
    root = _json(document)
    if root.kind != "object":
        raise _JSONError("unsupported_schema")
    if _member(root, "plugins") is not None:
        raise _JSONError("unsupported_plural_plugin")
    plugin = _member(root, "plugin")
    if plugin is None:
        return root, None, (), (), 0
    if plugin.value.kind != "array":
        raise _JSONError("unsupported_plugin_schema")
    exact = []
    alias = []
    unrelated = []
    for index, item in enumerate(plugin.value.value):
        identity = None
        if item.kind == "string":
            identity = _plugin_identity(item.value)
        elif (
            item.kind == "array"
            and len(item.value) == 2
            and item.value[0].kind == "string"
            and item.value[1].kind == "object"
        ):
            identity = _plugin_identity(item.value[0].value)
            if identity is not None:
                identity = "tuple"
        else:
            raise _JSONError("unsupported_plugin_member")
        if identity == "exact":
            exact.append((index, item))
        elif identity is not None:
            alias.append((index, item))
        else:
            unrelated.append(item)
    return root, plugin, tuple(exact), tuple(alias), len(unrelated)


def observe_opencode_config(
    document,
    ownership=None,
    *,
    competing_documents=(),
    source_inputs_complete=False,
):
    """Observe one selected OpenCode global strict-JSON document."""
    _bounded(document, OPENCODE_GLOBAL)
    competing = []
    seen = {(document.scope, document.path)}
    for candidate in competing_documents:
        _bounded(candidate, OPENCODE_GLOBAL)
        identity = (candidate.scope, candidate.path)
        competing.append(
            "duplicate_source" if identity in seen else "multiple_global_sources"
        )
        seen.add(identity)
    if not source_inputs_complete:
        competing.append("source_inputs_incomplete")
    error_code = None
    try:
        _, _, exact, aliases, unrelated_count = _opencode_shape(document)
        count = len(exact) + len(aliases)
        if aliases or len(exact) > 1:
            state = "ambiguous_identity"
            entry_digest = None
        elif exact:
            state = "matching"
            entry_digest = _node_digest(document.content, exact[0][1])
        else:
            state = "absent"
            entry_digest = None
        unknown = ()
        complement = (
            _masked_digest(document.content, (exact[0][1],))
            if len(exact) == 1 and not aliases
            else _sha256(document.content)
        )
    except _JSONError as error:
        state = "malformed" if error.code in {
            "invalid_utf8",
            "strict_json_required",
            "duplicate_json_key",
            "json_depth_exceeded",
            "json_node_limit_exceeded",
        } else "unsupported"
        entry_digest = None
        count = 0
        unrelated_count = 0
        complement = _sha256(document.content)
        unknown = ()
        error_code = error.code
    disposition = None
    owned = False
    if state == "matching":
        disposition, owned = _ownership_disposition(
            ownership, "opencode", document.path, entry_digest
        )
    reason = error_code if state in {"malformed", "unsupported"} else state
    eligible = state in {"absent", "matching"} and not competing
    if state == "matching" and ownership is not None and not owned:
        reason = "ownership_mismatch"
        eligible = False
    if competing:
        reason = "scope_ambiguous"
        eligible = False
    return RegistrationObservation(
        "opencode",
        document.path,
        document.scope,
        _sha256(document.content),
        state,
        reason,
        entry_digest,
        disposition,
        eligible,
        unknown,
        count,
        unrelated_count,
        complement,
        tuple(competing),
        "unobserved",
        "strict_json_span_parser",
    )


def _opencode_ensure_patch(raw, root, plugin):
    encoded = json.dumps(OPENCODE_COUNCIL_PLUGIN, ensure_ascii=False).encode("utf-8")
    if plugin is None:
        member = b'"plugin":[' + encoded + b"]"
        if not root.value:
            return BytePatch(root.start + 1, root.start + 1, member)
        return BytePatch(root.value[-1].value.end, root.value[-1].value.end, b"," + member)
    items = plugin.value.value
    if not items:
        position = plugin.value.start + 1
        return BytePatch(position, position, encoded)
    position = items[-1].end
    return BytePatch(position, position, b"," + encoded)


def _opencode_remove_patch(plugin, index):
    items = plugin.value.value
    selected = items[index]
    if len(items) == 1:
        return BytePatch(selected.start, selected.end, b"")
    if index < len(items) - 1:
        return BytePatch(selected.start, items[index + 1].start, b"")
    return BytePatch(items[index - 1].end, selected.end, b"")


def _opencode_fingerprints(raw, root, plugin):
    top = []
    for member in root.value:
        if member.key == "plugin":
            continue
        top.append(
            (
                member.key,
                raw[member.key_start : member.key_end],
                raw[member.value.start : member.value.end],
            )
        )
    items = ()
    if plugin is not None:
        items = tuple(raw[item.start : item.end] for item in plugin.value.value)
    return tuple(top), items


def _candidate_result(operation, document, patch, disposition):
    raw = document.content
    root, plugin, _, _, _ = _opencode_shape(document)
    before_top, before_items = _opencode_fingerprints(raw, root, plugin)
    candidate = patch.candidate(raw)
    candidate_document = ConfigDocument(document.path, document.scope, candidate)
    after_root, after_plugin, after_exact, after_alias, _ = _opencode_shape(
        candidate_document
    )
    after_top, after_items = _opencode_fingerprints(
        candidate, after_root, after_plugin
    )
    if before_top != after_top or after_alias:
        raise AssertionError("candidate changed unrelated top-level content")
    marker = json.dumps(OPENCODE_COUNCIL_PLUGIN).encode("utf-8")
    if operation == OPENCODE_ENSURE:
        if len(after_exact) != 1:
            raise AssertionError("ensure candidate lacks one Council entry")
        if tuple(item for item in after_items if item != marker) != before_items:
            raise AssertionError("ensure candidate changed unrelated plugin members")
    else:
        if after_exact:
            raise AssertionError("remove candidate retained Council entry")
        selected_raw = raw[_opencode_shape(document)[2][0][1].start : _opencode_shape(document)[2][0][1].end]
        removed = False
        retained = []
        for item in before_items:
            if not removed and item == selected_raw:
                removed = True
                continue
            retained.append(item)
        if tuple(retained) != after_items:
            raise AssertionError("remove candidate changed unrelated plugin members")
    return CandidateEdit(
        operation,
        "opencode",
        document.path,
        _sha256(raw),
        _sha256(candidate),
        candidate,
        patch,
        "candidate",
        disposition,
        "candidate_only_not_applied_or_native_qualified",
    )


def plan_opencode_candidate(
    operation,
    document,
    ownership=None,
    *,
    competing_documents=(),
    source_inputs_complete=False,
):
    """Create a pure exact OpenCode candidate or a fixed refusal/no-op result."""
    if operation not in {OPENCODE_ENSURE, OPENCODE_REMOVE}:
        raise RegistrationInputError("operation is not an OpenCode operation")
    observation = observe_opencode_config(
        document,
        ownership,
        competing_documents=competing_documents,
        source_inputs_complete=source_inputs_complete,
    )
    base = dict(
        operation=operation,
        runtime="opencode",
        source_path=document.path,
        source_sha256=observation.source_sha256,
        candidate_sha256=None,
        candidate_bytes=None,
        patch=None,
        entry_disposition=observation.entry_disposition,
    )
    if observation.reason == "scope_ambiguous":
        return CandidateEdit(outcome="refused", reason="scope_ambiguous", **base)
    if observation.reason == "ownership_mismatch":
        return CandidateEdit(outcome="refused", reason="ownership_mismatch", **base)
    if observation.state not in {"absent", "matching"}:
        return CandidateEdit(outcome="refused", reason=observation.reason, **base)
    root, plugin, exact, _, _ = _opencode_shape(document)
    if operation == OPENCODE_ENSURE:
        if observation.state == "matching":
            return CandidateEdit(
                outcome="unchanged",
                reason=(
                    "already_owned"
                    if observation.entry_disposition in {
                        "already_owned",
                        "adopted_by_explicit_plan",
                    }
                    else "matching_preexisting_unowned"
                ),
                **base
            )
        patch = _opencode_ensure_patch(document.content, root, plugin)
        return _candidate_result(operation, document, patch, "created")
    if observation.state == "absent":
        reason = "missing_owned_entry" if ownership is not None else "already_absent"
        return CandidateEdit(outcome="refused" if ownership else "unchanged", reason=reason, **base)
    if observation.entry_disposition == "matching_preexisting_unowned":
        return CandidateEdit(
            outcome="unchanged",
            reason="matching_preexisting_unowned_preserved",
            **base
        )
    if observation.entry_disposition not in {
        "already_owned",
        "adopted_by_explicit_plan",
    }:
        return CandidateEdit(outcome="refused", reason="ownership_mismatch", **base)
    patch = _opencode_remove_patch(plugin, exact[0][0])
    return _candidate_result(
        operation, document, patch, observation.entry_disposition
    )


def compare_candidate(document, candidate_bytes):
    """Render an exact local diff for explicit bounded before/candidate bytes."""
    if len(document.content) > MAX_CONFIG_BYTES or len(candidate_bytes) > MAX_CONFIG_BYTES:
        raise RegistrationInputError("candidate comparison exceeds byte limit")
    try:
        before = document.content.decode("utf-8")
        after = candidate_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise RegistrationInputError("candidate comparison requires UTF-8")
    source_digest = _sha256(document.content)
    candidate_digest = _sha256(candidate_bytes)
    exact = "".join(
        difflib.unified_diff(
            before.splitlines(True),
            after.splitlines(True),
            fromfile=document.path + "@" + source_digest,
            tofile=document.path + "@" + candidate_digest,
            n=0,
        )
    )
    return CandidateComparison(
        document.path, source_digest, candidate_digest, exact
    )


__all__ = [
    "MAX_CONFIG_BYTES",
    "OPENCODE_COUNCIL_PLUGIN",
    "OPERATIONS",
    "CLAUDE_USER",
    "CLAUDE_PROJECT",
    "CLAUDE_LOCAL",
    "CODEX_USER",
    "OPENCODE_GLOBAL",
    "CLAUDE_ENSURE",
    "CLAUDE_REMOVE",
    "CODEX_ENSURE",
    "CODEX_REMOVE",
    "OPENCODE_ENSURE",
    "OPENCODE_REMOVE",
    "NATIVE_REGISTRATION_PLAN_FORMAT",
    "NATIVE_REGISTRATION_EXECUTION_FORMAT",
    "ConfigDocument",
    "StdioSpec",
    "OwnershipEvidence",
    "RegistrationObservation",
    "BytePatch",
    "CandidateEdit",
    "CandidateComparison",
    "ArtifactReceiptBinding",
    "QualificationReference",
    "QuiescentDecisionProjection",
    "NativeAttemptProjection",
    "RegistrationResultProjection",
    "RegistrationOperationRecord",
    "RegistrationInputError",
    "observe_claude_config",
    "observe_codex_config",
    "observe_opencode_config",
    "plan_opencode_candidate",
    "compare_candidate",
    "render_plan_summary",
    "operation_record",
    "opencode_execution_record",
    "build_registration_execution_preview",
    "canonical_registration_execution_bytes",
    "build_native_plan_core",
    "canonical_native_plan_core_bytes",
    "finalize_native_execution",
    "canonical_native_execution_bytes",
    "validate_c2_contract",
    "build_integration_preview",
    "canonical_integration_preview_bytes",
]
