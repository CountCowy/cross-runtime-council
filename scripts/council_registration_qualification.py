#!/usr/bin/env python3
"""Validate native-registration evidence and run injected one-attempt logic.

The collector has no file, process, home-discovery, environment, or network
API.  A future disposable-runner controller supplies an explicit fixture
admission plus exactly one launch receipt and one post-observation receipt.
Synthetic tests inject those receipts directly. Collector packets never
self-promote; native-v3 attempts require a separate owner admission bound to
independently reviewed evidence and still return no support claim.
"""

import hashlib
import json
from pathlib import PurePosixPath
import re
from dataclasses import dataclass

from council_registration import (
    CLAUDE_ENSURE,
    CLAUDE_REMOVE,
    CLAUDE_USER,
    CODEX_ENSURE,
    CODEX_REMOVE,
    CODEX_USER,
    ConfigDocument,
    StdioSpec,
    observe_claude_config,
    observe_codex_config,
)


FORMAT = "council-registration-qualification-collection-v1"
ATTEMPT_FORMAT = "council-registration-qualified-attempt-v1"
ATTEMPT_JOURNAL_FORMAT = "council-registration-attempt-journal-v1"
NATIVE_POLICY_FORMAT = "council-native-v3-shape-policy-v1"
NATIVE_ATTEMPT_FORMAT = "council-registration-admitted-attempt-v3"
NATIVE_JOURNAL_FORMAT = "council-registration-attempt-journal-v3"
MAX_OUTPUT_BYTES = 64 * 1024
MAX_CHANGED_PATHS = 256
FIXTURE_ACCOUNT_KIND = "disposable_fixture_account"
FIXTURE_AUTHORITY = "external_fixture_controller"
CLEAN_FIXTURE_STATE = "admitted_clean_synthetic"
CREDENTIAL_STATE = "observed_absent"
EVIDENCE_KINDS = {"synthetic_fault_model", "genuine_runner_observation"}
PROCESS_STATES = {"not_started", "terminated", "surviving", "unidentified"}
NETWORK_STATES = {
    "not_applicable",
    "no_activity_observed",
    "activity_observed",
    "unobserved",
}
RESULT_KINDS = {
    "pre_spawn_failure",
    "exit",
    "signal",
    "timeout",
    "output_lost",
}
INITIAL_STATES = {
    "absent",
    "matching",
    "customized",
    "unknown_fields",
    "disabled",
    "malformed",
    "parser_unavailable",
    "strict_json_required",
    "duplicate_json_key",
    "invalid_toml",
    "unsupported",
    "unsupported_schema",
}
NATIVE_OPERATIONS = {
    CLAUDE_ENSURE,
    CLAUDE_REMOVE,
    CODEX_ENSURE,
    CODEX_REMOVE,
}
ATTEMPT_MODES = {"forward", "inverse", "recovery"}
NATIVE_FORMAT_VERSION = 3
NATIVE_OWNERSHIP = {"created", "already_owned", "adopted_by_explicit_plan"}
FIXED_CASES = {
    "claude-add-absent": ("claude", CLAUDE_ENSURE, "absent", "ordinary"),
    "claude-add-identical": ("claude", CLAUDE_ENSURE, "matching", "ordinary"),
    "claude-add-customized": ("claude", CLAUDE_ENSURE, "customized", "ordinary"),
    "claude-add-malformed": (
        "claude",
        CLAUDE_ENSURE,
        "strict_json_required",
        "malformed_config",
    ),
    "claude-add-unwritable": (
        "claude",
        CLAUDE_ENSURE,
        "absent",
        "unwritable_config",
    ),
    "claude-remove-present": ("claude", CLAUDE_REMOVE, "matching", "ordinary"),
    "claude-remove-absent": ("claude", CLAUDE_REMOVE, "absent", "ordinary"),
    "codex-add-absent": ("codex", CODEX_ENSURE, "absent", "ordinary"),
    "codex-add-identical": ("codex", CODEX_ENSURE, "matching", "ordinary"),
    "codex-add-customized": ("codex", CODEX_ENSURE, "customized", "ordinary"),
    "codex-add-malformed": (
        "codex",
        CODEX_ENSURE,
        "malformed",
        "malformed_config",
    ),
    "codex-add-unwritable": (
        "codex",
        CODEX_ENSURE,
        "absent",
        "unwritable_config",
    ),
    "codex-remove-present": ("codex", CODEX_REMOVE, "matching", "ordinary"),
    "codex-remove-absent": ("codex", CODEX_REMOVE, "absent", "ordinary"),
}
SELECTED_VERSIONS = {"claude": "2.1.241", "codex": "0.153.4"}
_CASE_ID = re.compile(r"^[a-z][a-z0-9-]{2,79}$")


def _required_cases(operation):
    return tuple(
        sorted(case_id for case_id, value in FIXED_CASES.items() if value[1] == operation)
    )


def _validate_operation_runtime(operation, runtime):
    if operation not in NATIVE_OPERATIONS:
        raise QualificationInputError("native operation is invalid")
    if runtime not in {"claude", "codex"} or not operation.startswith(runtime + "_"):
        raise QualificationInputError("native operation runtime is invalid")


def _validate_case_evidence(evidence, operation):
    if not isinstance(evidence, tuple):
        raise QualificationInputError("native case evidence must be a tuple")
    ids = []
    case_digests = []
    packet_digests = []
    for item in evidence:
        if (not isinstance(item, tuple) or len(item) != 4 or
                not isinstance(item[0], str) or not _is_digest(item[1]) or
                not _is_digest(item[2]) or item[3] != "genuine_runner_observation"):
            raise QualificationInputError("native case evidence is invalid")
        ids.append(item[0])
        case_digests.append(item[1])
        packet_digests.append(item[2])
    if tuple(ids) != _required_cases(operation):
        raise QualificationInputError("native case evidence inventory is incomplete")
    if (len(case_digests) != len(set(case_digests)) or
            len(packet_digests) != len(set(packet_digests))):
        raise QualificationInputError("native case evidence is duplicated")


def _case_evidence_dicts(evidence):
    return [
        {"case_id": case_id, "case_sha256": case_sha256,
         "packet_sha256": packet_sha256, "evidence_kind": evidence_kind}
        for case_id, case_sha256, packet_sha256, evidence_kind in evidence
    ]


def _native_inverse(operation):
    return {
        CLAUDE_ENSURE: CLAUDE_REMOVE,
        CLAUDE_REMOVE: CLAUDE_ENSURE,
        CODEX_ENSURE: CODEX_REMOVE,
        CODEX_REMOVE: CODEX_ENSURE,
    }[operation]


class QualificationInputError(ValueError):
    """The supplied bounded case or receipt is invalid."""


@dataclass(frozen=True)
class QualificationDecision:
    """Independent promotion record; collector packets never promote themselves."""

    decision_id: str
    mode: str
    operation: str
    runtime: str
    runtime_tuple_sha256: str
    case_evidence: tuple
    independent_review_sha256: str
    support_matrix_sha256: str
    reviewer_authority: str
    qualification_eligible: bool

    def __post_init__(self):
        if not isinstance(self.decision_id, str) or not _CASE_ID.fullmatch(
            self.decision_id
        ):
            raise QualificationInputError("qualification decision id is invalid")
        if self.operation not in NATIVE_OPERATIONS:
            raise QualificationInputError("qualification decision operation is invalid")
        if self.runtime not in {"claude", "codex"} or not self.operation.startswith(
            self.runtime + "_"
        ):
            raise QualificationInputError("qualification decision runtime is invalid")
        if self.mode not in ATTEMPT_MODES:
            raise QualificationInputError("qualification decision mode is invalid")
        if (self.mode == "forward" and not self.operation.endswith("_ensure")) or (
            self.mode == "inverse" and not self.operation.endswith("_remove")
        ):
            raise QualificationInputError("qualification decision mode differs from operation")
        for value in (
            self.runtime_tuple_sha256,
            self.independent_review_sha256,
            self.support_matrix_sha256,
        ):
            if not _is_digest(value):
                raise QualificationInputError("qualification decision digest is invalid")
        if self.reviewer_authority != "independent_genuine_runner_reviewer":
            raise QualificationInputError("qualification reviewer authority is invalid")
        if self.qualification_eligible is not True:
            raise QualificationInputError("qualification decision is not eligible")
        if not isinstance(self.case_evidence, tuple):
            raise QualificationInputError("qualification case evidence must be a tuple")
        ids = []
        case_digests = []
        packet_digests = []
        for item in self.case_evidence:
            if (
                not isinstance(item, tuple)
                or len(item) != 4
                or not isinstance(item[0], str)
                or not _is_digest(item[1])
                or not _is_digest(item[2])
                or item[3] != "genuine_runner_observation"
            ):
                raise QualificationInputError("qualification case evidence is invalid")
            ids.append(item[0])
            case_digests.append(item[1])
            packet_digests.append(item[2])
        if tuple(ids) != _required_cases(self.operation):
            raise QualificationInputError(
                "qualification decision does not cover the fixed case inventory"
            )
        if (len(case_digests) != len(set(case_digests)) or
                len(packet_digests) != len(set(packet_digests))):
            raise QualificationInputError("qualification case evidence is duplicated")

    def digest(self):
        return _digest_json(self.public_dict())

    def public_dict(self):
        return {
            "decision_id": self.decision_id,
            "mode": self.mode,
            "operation": self.operation,
            "runtime": self.runtime,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "case_evidence": [
                {
                    "case_id": case_id,
                    "case_sha256": case_digest,
                    "packet_sha256": packet_digest,
                    "evidence_kind": evidence_kind,
                }
                for case_id, case_digest, packet_digest, evidence_kind
                in self.case_evidence
            ],
            "independent_review_sha256": self.independent_review_sha256,
            "support_matrix_sha256": self.support_matrix_sha256,
            "reviewer_authority": self.reviewer_authority,
            "qualification_eligible": True,
        }


@dataclass(frozen=True)
class NativeImplementationIdentity:
    """Exact native-v3 code and format identity bound by external evidence."""

    package_id: str
    runtime_cohort: str
    plan_format: int
    receipt_format: int
    journal_format: int
    recovery_format: int
    recoverer_sha256: str
    registration_sha256: str
    qualification_sha256: str
    supervisor_sha256: str
    observer_sha256: str
    observer_policy_sha256: str

    def __post_init__(self):
        for value in (self.package_id, self.runtime_cohort, self.recoverer_sha256,
                      self.registration_sha256, self.qualification_sha256,
                      self.supervisor_sha256, self.observer_sha256,
                      self.observer_policy_sha256):
            if not _is_digest(value):
                raise QualificationInputError("native implementation digest is invalid")
        for value in (self.plan_format, self.receipt_format, self.journal_format,
                      self.recovery_format):
            if type(value) is not int or value != NATIVE_FORMAT_VERSION:
                raise QualificationInputError("native implementation format is invalid")

    def public_dict(self):
        return {
            "package_id": self.package_id,
            "runtime_cohort": self.runtime_cohort,
            "formats": {
                "plan": self.plan_format,
                "receipt": self.receipt_format,
                "journal": self.journal_format,
                "recovery": self.recovery_format,
            },
            "source_sha256": {
                "council_recover.py": self.recoverer_sha256,
                "council_registration.py": self.registration_sha256,
                "council_registration_qualification.py": self.qualification_sha256,
                "native_supervisor": self.supervisor_sha256,
                "native_observer": self.observer_sha256,
                "native_observer_policy": self.observer_policy_sha256,
            },
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class NativeShapePolicy:
    """Validated closed policy wrapper bound to the exact canonical source bytes."""

    format: str
    policy_sha256: str
    policies: tuple
    qualification_eligible: bool = False

    def __post_init__(self):
        if self.format != NATIVE_POLICY_FORMAT or not _is_digest(self.policy_sha256):
            raise QualificationInputError("native shape policy identity is invalid")
        if self.qualification_eligible is not False or not isinstance(self.policies, tuple):
            raise QualificationInputError("native shape policy cannot claim qualification")
        order = (CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE)
        if tuple(item.get("operation") for item in self.policies) != order:
            raise QualificationInputError("native shape policy inventory differs")
        for item in self.policies:
            if item != _expected_policy_record(item.get("operation")):
                raise QualificationInputError("native shape policy record differs")

    def public_dict(self):
        return {
            "format": self.format,
            "policy_sha256": self.policy_sha256,
            "policies": [dict(item) for item in self.policies],
            "qualification_eligible": False,
        }

    def digest(self):
        return self.policy_sha256


@dataclass(frozen=True)
class QualificationSupportDecision:
    """Consistency result for genuine packets; it carries no execution authority."""

    support_id: str
    operation: str
    runtime: str
    runtime_tuple_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    implementation_sha256: str
    intended_entry_sha256: object
    case_evidence: tuple
    independent_review_sha256: str
    support_matrix_sha256: str
    reviewer_authority: str
    consistency_supported: bool
    qualification_authority: bool

    def __post_init__(self):
        if not isinstance(self.support_id, str) or not _CASE_ID.fullmatch(self.support_id):
            raise QualificationInputError("qualification support id is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        if not isinstance(self.policy_id, str) or not _CASE_ID.fullmatch(self.policy_id):
            raise QualificationInputError("qualification support policy id is invalid")
        if type(self.policy_version) is not int or self.policy_version != 1:
            raise QualificationInputError("qualification support policy version is invalid")
        for value in (self.runtime_tuple_sha256, self.policy_sha256,
                      self.implementation_sha256, self.independent_review_sha256,
                      self.support_matrix_sha256):
            if not _is_digest(value):
                raise QualificationInputError("qualification support digest is invalid")
        if ((self.operation.endswith("_ensure")) !=
                (self.intended_entry_sha256 is not None)) or (
            self.intended_entry_sha256 is not None and
            not _is_digest(self.intended_entry_sha256)
        ):
            raise QualificationInputError("qualification support intended entry is invalid")
        _validate_case_evidence(self.case_evidence, self.operation)
        if self.reviewer_authority != "independent_genuine_runner_reviewer":
            raise QualificationInputError("qualification support reviewer is invalid")
        if self.consistency_supported is not True or self.qualification_authority is not False:
            raise QualificationInputError("qualification support is not consistency-only")

    def public_dict(self):
        return {
            "support_id": self.support_id,
            "operation": self.operation,
            "runtime": self.runtime,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "implementation_sha256": self.implementation_sha256,
            "intended_entry_sha256": self.intended_entry_sha256,
            "case_evidence": _case_evidence_dicts(self.case_evidence),
            "independent_review_sha256": self.independent_review_sha256,
            "support_matrix_sha256": self.support_matrix_sha256,
            "reviewer_authority": self.reviewer_authority,
            "consistency_supported": True,
            "qualification_authority": False,
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class QualificationAdmission:
    """Owner trust-root record required in addition to a consistency decision."""

    admission_id: str
    operation: str
    runtime: str
    runtime_tuple_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    implementation_sha256: str
    support_decision_sha256: str
    intended_entry_sha256: object
    case_evidence: tuple
    independent_review_sha256: str
    support_matrix_sha256: str
    owner_authority: str
    admitted: bool

    def __post_init__(self):
        if not isinstance(self.admission_id, str) or not _CASE_ID.fullmatch(self.admission_id):
            raise QualificationInputError("qualification admission id is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        if not isinstance(self.policy_id, str) or not _CASE_ID.fullmatch(self.policy_id):
            raise QualificationInputError("qualification admission policy id is invalid")
        if type(self.policy_version) is not int or self.policy_version != 1:
            raise QualificationInputError("qualification admission policy version is invalid")
        for value in (self.runtime_tuple_sha256, self.policy_sha256,
                      self.implementation_sha256, self.support_decision_sha256,
                      self.independent_review_sha256, self.support_matrix_sha256):
            if not _is_digest(value):
                raise QualificationInputError("qualification admission digest is invalid")
        if ((self.operation.endswith("_ensure")) !=
                (self.intended_entry_sha256 is not None)) or (
            self.intended_entry_sha256 is not None and
            not _is_digest(self.intended_entry_sha256)
        ):
            raise QualificationInputError("qualification admission intended entry is invalid")
        _validate_case_evidence(self.case_evidence, self.operation)
        if self.owner_authority != "council_lifecycle_qualification_owner":
            raise QualificationInputError("qualification admission owner is invalid")
        if self.admitted is not True:
            raise QualificationInputError("qualification admission is not admitted")

    @property
    def fixed_relative_path(self):
        return ".council-lifecycle/v1/native-qualification-admissions/%s.json" % self.operation

    def public_dict(self):
        return {
            "admission_id": self.admission_id,
            "operation": self.operation,
            "runtime": self.runtime,
            "runtime_tuple_sha256": self.runtime_tuple_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "implementation_sha256": self.implementation_sha256,
            "support_decision_sha256": self.support_decision_sha256,
            "intended_entry_sha256": self.intended_entry_sha256,
            "case_evidence": _case_evidence_dicts(self.case_evidence),
            "independent_review_sha256": self.independent_review_sha256,
            "support_matrix_sha256": self.support_matrix_sha256,
            "owner_authority": self.owner_authority,
            "admitted": True,
            "fixed_relative_path": self.fixed_relative_path,
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class NativeExecutionAdmission:
    """Pure owner-derived execution context; it makes no fixture-account claim."""

    execution_id: str
    operation: str
    runtime: str
    state_root: str
    home: str
    payload_root: str
    config_path: str
    source_file_exists: bool
    source_identity_sha256: str
    ownership: str
    neutral_cwd: str
    write_set: tuple
    environment_keys: tuple
    environment_sha256: str
    observer_policy_sha256: str
    quiescent_decision_sha256: str
    owner_authority: str
    admitted: bool

    def __post_init__(self):
        if not isinstance(self.execution_id, str) or not _CASE_ID.fullmatch(self.execution_id):
            raise QualificationInputError("native execution admission id is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        for label, path in (("state root", self.state_root), ("home", self.home),
                            ("payload root", self.payload_root),
                            ("config path", self.config_path),
                            ("neutral cwd", self.neutral_cwd)):
            _absolute_normalized(label, path)
        if not isinstance(self.write_set, tuple) or self.write_set != (self.config_path,):
            raise QualificationInputError("native execution write set is invalid")
        if self.source_file_exists is not True:
            raise QualificationInputError("native execution requires an existing source file")
        if self.ownership not in NATIVE_OWNERSHIP:
            raise QualificationInputError("native execution ownership is invalid")
        if (not isinstance(self.environment_keys, tuple) or
                self.environment_keys != tuple(sorted(self.environment_keys)) or
                len(self.environment_keys) != len(set(self.environment_keys))):
            raise QualificationInputError("native execution environment keys are invalid")
        for key in self.environment_keys:
            if not isinstance(key, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key):
                raise QualificationInputError("native execution environment key is invalid")
        for value in (self.source_identity_sha256, self.environment_sha256,
                      self.observer_policy_sha256,
                      self.quiescent_decision_sha256):
            if not _is_digest(value):
                raise QualificationInputError("native execution admission digest is invalid")
        if self.owner_authority != "council_lifecycle_execution_owner" or self.admitted is not True:
            raise QualificationInputError("native execution admission authority is invalid")

    def public_dict(self):
        return {
            "execution_id": self.execution_id,
            "operation": self.operation,
            "runtime": self.runtime,
            "state_root": self.state_root,
            "home": self.home,
            "payload_root": self.payload_root,
            "config_path": self.config_path,
            "source_file_exists": True,
            "source_identity_sha256": self.source_identity_sha256,
            "ownership": self.ownership,
            "neutral_cwd": self.neutral_cwd,
            "write_set": list(self.write_set),
            "environment_keys": list(self.environment_keys),
            "environment_sha256": self.environment_sha256,
            "observer_policy_sha256": self.observer_policy_sha256,
            "quiescent_decision_sha256": self.quiescent_decision_sha256,
            "owner_authority": self.owner_authority,
            "admitted": True,
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class RuntimeTuple:
    """Exact runtime tuple supplied by, and later verified on, the runner."""

    runtime: str
    executable_path: str
    executable_realpath: str
    executable_sha256: str
    version: str
    os_name: str
    architecture: str

    def __post_init__(self):
        if self.runtime not in {"claude", "codex"}:
            raise QualificationInputError("runtime tuple runtime is invalid")
        for label, value in (
            ("executable path", self.executable_path),
            ("executable realpath", self.executable_realpath),
        ):
            _absolute_normalized(label, value)
        if not _is_digest(self.executable_sha256):
            raise QualificationInputError("executable digest is invalid")
        for label, value in (
            ("version", self.version),
            ("os name", self.os_name),
            ("architecture", self.architecture),
        ):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise QualificationInputError(label + " is invalid")

    def public_dict(self):
        return {
            "runtime": self.runtime,
            "executable_path": self.executable_path,
            "executable_realpath": self.executable_realpath,
            "executable_sha256": self.executable_sha256,
            "version": self.version,
            "os_name": self.os_name,
            "architecture": self.architecture,
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class FixtureAdmission:
    """A declaration from an external runner controller, never proof by itself."""

    declaration_id: str
    declaration_sha256: str
    authority: str
    evidence_kind: str
    account_kind: str
    fixture_home: str
    pwd_home: str
    pathlib_home: str
    environment_home: str
    clean_fixture_state: str
    credential_state: str
    admitted_config_paths: tuple
    admitted_neutral_cwd: str

    def __post_init__(self):
        if not isinstance(self.declaration_id, str) or not _CASE_ID.fullmatch(
            self.declaration_id
        ):
            raise QualificationInputError("fixture declaration id is invalid")
        if not _is_digest(self.declaration_sha256):
            raise QualificationInputError("fixture declaration digest is invalid")
        for label, value in (
            ("fixture home", self.fixture_home),
            ("pwd home", self.pwd_home),
            ("pathlib home", self.pathlib_home),
            ("environment home", self.environment_home),
            ("neutral cwd", self.admitted_neutral_cwd),
        ):
            _absolute_normalized(label, value)
        if not isinstance(self.admitted_config_paths, tuple):
            raise QualificationInputError("admitted config paths must be a tuple")
        if len(self.admitted_config_paths) > 8:
            raise QualificationInputError("too many admitted config paths")
        for path in self.admitted_config_paths:
            _absolute_normalized("admitted config path", path)

    def digest(self):
        return _digest_json(
            {
                "declaration_id": self.declaration_id,
                "declaration_sha256": self.declaration_sha256,
                "authority": self.authority,
                "evidence_kind": self.evidence_kind,
                "account_kind": self.account_kind,
                "fixture_home": self.fixture_home,
                "pwd_home": self.pwd_home,
                "pathlib_home": self.pathlib_home,
                "environment_home": self.environment_home,
                "clean_fixture_state": self.clean_fixture_state,
                "credential_state": self.credential_state,
                "admitted_config_paths": list(self.admitted_config_paths),
                "admitted_neutral_cwd": self.admitted_neutral_cwd,
            }
        )


@dataclass(frozen=True)
class QualificationCase:
    """One fixed operation and its explicit source/tuple expectations."""

    case_id: str
    operation: str
    expected_version: str
    expected_os_name: str
    expected_architecture: str
    expected_initial_state: str
    before: ConfigDocument
    stdio: StdioSpec
    neutral_cwd: str
    expected_target_complement_sha256: str
    permitted_write_paths: tuple

    def __post_init__(self):
        if not isinstance(self.case_id, str) or not _CASE_ID.fullmatch(self.case_id):
            raise QualificationInputError("case id is invalid")
        if self.operation not in NATIVE_OPERATIONS:
            raise QualificationInputError("operation is not a fixed native operation")
        if self.expected_initial_state not in INITIAL_STATES:
            raise QualificationInputError("initial state is invalid")
        for label, value in (
            ("expected version", self.expected_version),
            ("expected os name", self.expected_os_name),
            ("expected architecture", self.expected_architecture),
        ):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise QualificationInputError(label + " is invalid")
        _absolute_normalized("neutral cwd", self.neutral_cwd)
        if not _is_digest(self.expected_target_complement_sha256):
            raise QualificationInputError("target complement digest is invalid")
        if not isinstance(self.permitted_write_paths, tuple):
            raise QualificationInputError("permitted write paths must be a tuple")
        if len(self.permitted_write_paths) > 8:
            raise QualificationInputError("too many permitted write paths")
        for path in self.permitted_write_paths:
            _absolute_normalized("permitted write path", path)

    @property
    def runtime(self):
        return "claude" if self.operation.startswith("claude_") else "codex"


@dataclass(frozen=True)
class LaunchReceipt:
    """One injected launch observation.  Raw output is hashed then discarded."""

    case_id: str
    argv: tuple
    runtime_tuple_digest: str
    result_kind: str
    process_state: str
    process_generation_sha256: object
    network_state: str
    network_evidence_sha256: object
    returncode: object
    timed_out: bool
    output_lost: bool
    stdout: bytes
    stderr: bytes

    def __post_init__(self):
        if self.result_kind not in RESULT_KINDS:
            raise QualificationInputError("launch result kind is invalid")
        if self.process_state not in PROCESS_STATES:
            raise QualificationInputError("process state is invalid")
        if self.network_state not in NETWORK_STATES:
            raise QualificationInputError("network state is invalid")
        if not isinstance(self.argv, tuple) or not all(
            isinstance(value, str) for value in self.argv
        ):
            raise QualificationInputError("launch argv must be a string tuple")
        if not _is_digest(self.runtime_tuple_digest):
            raise QualificationInputError("launch tuple digest is invalid")
        if self.returncode is not None and type(self.returncode) is not int:
            raise QualificationInputError("return code is invalid")
        if not isinstance(self.timed_out, bool) or not isinstance(self.output_lost, bool):
            raise QualificationInputError("launch flags must be booleans")
        for label, value in (("stdout", self.stdout), ("stderr", self.stderr)):
            if not isinstance(value, bytes):
                raise QualificationInputError(label + " must be bytes")
            if len(value) > MAX_OUTPUT_BYTES:
                raise QualificationInputError(label + " exceeds byte limit")
        if self.process_state == "not_started" and self.result_kind != "pre_spawn_failure":
            raise QualificationInputError("not-started receipt must be pre-spawn failure")
        if self.result_kind == "pre_spawn_failure" and self.process_state != "not_started":
            raise QualificationInputError("pre-spawn failure cannot report a process")
        if self.timed_out != (self.result_kind == "timeout"):
            raise QualificationInputError("timed_out must match result kind")
        if self.output_lost != (self.result_kind == "output_lost"):
            raise QualificationInputError("output_lost must match result kind")
        if self.result_kind == "exit" and self.returncode is None:
            raise QualificationInputError("exit receipt requires a return code")
        if self.result_kind == "signal" and (
            self.returncode is None or self.returncode >= 0
        ):
            raise QualificationInputError("signal receipt requires negative return code")
        if self.process_state in {"not_started", "surviving", "unidentified"} and self.returncode is not None:
            raise QualificationInputError("nonterminal process cannot have return code")
        if self.process_state == "not_started":
            if self.process_generation_sha256 is not None:
                raise QualificationInputError("not-started receipt has process generation")
            if self.network_state != "not_applicable" or self.network_evidence_sha256 is not None:
                raise QualificationInputError("not-started receipt has network evidence")
        else:
            if not _is_digest(self.process_generation_sha256):
                raise QualificationInputError("process generation digest is invalid")
            if self.network_state == "not_applicable":
                raise QualificationInputError("started process requires network observation")
            if not _is_digest(self.network_evidence_sha256):
                raise QualificationInputError("network evidence digest is invalid")


@dataclass(frozen=True)
class ObservationReceipt:
    """One injected post-launch snapshot from an independent runner observer."""

    case_id: str
    after: ConfigDocument
    runtime_tuple_after: RuntimeTuple
    independent_complement_sha256: str
    changed_paths: tuple
    sentinel_started: bool

    def __post_init__(self):
        if not _is_digest(self.independent_complement_sha256):
            raise QualificationInputError("independent complement digest is invalid")
        if not isinstance(self.changed_paths, tuple):
            raise QualificationInputError("changed paths must be a tuple")
        if len(self.changed_paths) > MAX_CHANGED_PATHS:
            raise QualificationInputError("too many changed paths")
        if len(set(self.changed_paths)) != len(self.changed_paths):
            raise QualificationInputError("changed paths contain duplicates")
        for path in self.changed_paths:
            _absolute_normalized("changed path", path)
        if not isinstance(self.sentinel_started, bool):
            raise QualificationInputError("sentinel_started must be boolean")


@dataclass(frozen=True)
class NativeAttemptFamilyIdentity:
    """Stable target identity shared by at most two immutable attempt sequences."""

    operation_id: str
    mode: str
    operation: str
    runtime: str
    state_root: str
    source_path: str
    source_scope: str
    initial_source_sha256: str
    source_identity_sha256: str
    prior_state: str
    prior_entry_sha256: object
    prior_complement_sha256: str
    intended_state: str
    intended_entry_sha256: object
    expected_complement_sha256: str
    ownership: str
    runtime_tuple_sha256: str
    executable_path: str
    python_executable: str
    adapter_path: str
    argv: tuple
    permitted_inverse: str
    parser: str
    normalization: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    observer_policy_id: str
    observer_policy_sha256: str
    write_set: tuple
    neutral_cwd: str
    stdin: str
    environment_keys: tuple
    environment_sha256: str
    qualification_admission_sha256: str
    implementation_sha256: str
    max_attempt_sequences: int = 2

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _CASE_ID.fullmatch(
            self.operation_id
        ):
            raise QualificationInputError("native attempt family id is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        if self.mode not in ATTEMPT_MODES:
            raise QualificationInputError("native attempt family mode is invalid")
        if type(self.max_attempt_sequences) is not int or self.max_attempt_sequences != 2:
            raise QualificationInputError("native attempt family bound is invalid")
        for label, path in (
            ("state root", self.state_root),
            ("source path", self.source_path),
            ("executable path", self.executable_path),
            ("python executable", self.python_executable),
            ("adapter path", self.adapter_path),
            ("neutral cwd", self.neutral_cwd),
        ):
            _absolute_normalized(label, path)
        for value in (
            self.initial_source_sha256,
            self.source_identity_sha256,
            self.prior_complement_sha256,
            self.expected_complement_sha256,
            self.runtime_tuple_sha256,
            self.policy_sha256,
            self.observer_policy_sha256,
            self.environment_sha256,
            self.qualification_admission_sha256,
            self.implementation_sha256,
        ):
            if not _is_digest(value):
                raise QualificationInputError("native attempt family digest is invalid")
        for value in (self.prior_entry_sha256, self.intended_entry_sha256):
            if value is not None and not _is_digest(value):
                raise QualificationInputError("native attempt family entry is invalid")
        if self.ownership not in NATIVE_OWNERSHIP:
            raise QualificationInputError("native attempt family ownership is invalid")
        if not isinstance(self.argv, tuple) or not self.argv:
            raise QualificationInputError("native attempt family argv is invalid")
        if not isinstance(self.write_set, tuple) or self.write_set != (self.source_path,):
            raise QualificationInputError("native attempt family write set is invalid")
        if not isinstance(self.environment_keys, tuple):
            raise QualificationInputError("native attempt family environment is invalid")

    def public_dict(self):
        return {
            name: (list(value) if name in {"argv", "write_set", "environment_keys"} else value)
            for name, value in self.__dict__.items()
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class NativeAttemptBinding:
    """Exact pre-effect identity for one native-v3 attempt sequence."""

    operation_id: str
    attempt_family_sha256: str
    sequence: int
    mode: str
    operation: str
    runtime: str
    state_root: str
    source_path: str
    source_scope: str
    source_sha256: str
    source_identity_sha256: str
    prior_state: str
    prior_entry_sha256: object
    prior_complement_sha256: str
    intended_state: str
    intended_entry_sha256: object
    expected_complement_sha256: str
    ownership: str
    runtime_tuple_sha256: str
    executable_path: str
    python_executable: str
    adapter_path: str
    argv: tuple
    permitted_inverse: str
    parser: str
    normalization: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    observer_policy_id: str
    observer_policy_sha256: str
    write_set: tuple
    neutral_cwd: str
    stdin: str
    environment_keys: tuple
    environment_sha256: str
    qualification_admission_sha256: str
    implementation_sha256: str
    execution_admission_sha256: str
    quiescent_decision_sha256: str
    previous_attempt_terminal_sha256: object

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _CASE_ID.fullmatch(self.operation_id):
            raise QualificationInputError("native attempt operation id is invalid")
        if type(self.sequence) is not int or self.sequence not in (0, 1):
            raise QualificationInputError("native attempt sequence is invalid")
        if not _is_digest(self.attempt_family_sha256):
            raise QualificationInputError("native attempt family digest is invalid")
        if (self.sequence == 0) != (self.previous_attempt_terminal_sha256 is None):
            raise QualificationInputError("native attempt previous sequence is invalid")
        if self.previous_attempt_terminal_sha256 is not None and not _is_digest(
            self.previous_attempt_terminal_sha256
        ):
            raise QualificationInputError("native attempt previous terminal digest is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        if self.mode not in ATTEMPT_MODES:
            raise QualificationInputError("native attempt mode is invalid")
        if (self.mode == "forward" and not self.operation.endswith("_ensure")) or (
            self.mode == "inverse" and not self.operation.endswith("_remove")
        ):
            raise QualificationInputError("native attempt mode differs from operation")
        for label, path in (("state root", self.state_root),
                            ("source path", self.source_path),
                            ("executable path", self.executable_path),
                            ("python executable", self.python_executable),
                            ("adapter path", self.adapter_path),
                            ("neutral cwd", self.neutral_cwd)):
            _absolute_normalized(label, path)
        expected_scope = CLAUDE_USER if self.runtime == "claude" else CODEX_USER
        if self.source_scope != expected_scope:
            raise QualificationInputError("native attempt source scope is invalid")
        if self.prior_state not in INITIAL_STATES:
            raise QualificationInputError("native attempt prior state is invalid")
        if self.intended_state not in {"matching", "absent"}:
            raise QualificationInputError("native attempt intended state is invalid")
        expected_state = "matching" if self.operation.endswith("_ensure") else "absent"
        if self.intended_state != expected_state:
            raise QualificationInputError("native attempt target differs from operation")
        for label, value in (("prior entry", self.prior_entry_sha256),
                             ("intended entry", self.intended_entry_sha256)):
            if value is not None and not _is_digest(value):
                raise QualificationInputError("native attempt %s digest is invalid" % label)
        for value in (self.source_sha256, self.source_identity_sha256,
                      self.prior_complement_sha256,
                      self.expected_complement_sha256, self.runtime_tuple_sha256,
                      self.policy_sha256, self.observer_policy_sha256,
                      self.environment_sha256, self.qualification_admission_sha256,
                      self.implementation_sha256, self.execution_admission_sha256,
                      self.quiescent_decision_sha256):
            if not _is_digest(value):
                raise QualificationInputError("native attempt digest is invalid")
        if self.ownership not in NATIVE_OWNERSHIP:
            raise QualificationInputError("native attempt ownership is invalid")
        if ((self.intended_state == "matching") !=
                (self.intended_entry_sha256 is not None)):
            raise QualificationInputError("native attempt intended entry differs from target")
        if not isinstance(self.argv, tuple) or not self.argv or not all(
            isinstance(value, str) for value in self.argv
        ):
            raise QualificationInputError("native attempt argv is invalid")
        if self.permitted_inverse != _native_inverse(self.operation):
            raise QualificationInputError("native attempt inverse is invalid")
        for label, value in (("parser", self.parser), ("normalization", self.normalization),
                             ("policy id", self.policy_id),
                             ("observer policy id", self.observer_policy_id)):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise QualificationInputError("native attempt %s is invalid" % label)
        if type(self.policy_version) is not int or self.policy_version != 1:
            raise QualificationInputError("native attempt policy version is invalid")
        if not isinstance(self.write_set, tuple) or self.write_set != (self.source_path,):
            raise QualificationInputError("native attempt write set is invalid")
        if (not isinstance(self.environment_keys, tuple) or
                self.environment_keys != tuple(sorted(self.environment_keys)) or
                len(self.environment_keys) != len(set(self.environment_keys))):
            raise QualificationInputError("native attempt environment keys are invalid")
        if self.stdin != "closed":
            raise QualificationInputError("native attempt stdin policy is invalid")

    def public_dict(self):
        return {
            name: (list(value) if name in {"argv", "write_set", "environment_keys"} else value)
            for name, value in self.__dict__.items()
        }

    def digest(self):
        return _digest_json(self.public_dict())


@dataclass(frozen=True)
class SemanticNativeResultIdentity:
    """Prepared terminal meaning; post-source evidence belongs only in the journal."""

    operation_id: str
    mode: str
    operation: str
    runtime: str
    source_path: str
    source_scope: str
    source_sha256: str
    source_identity_sha256: str
    prior_entry_sha256: object
    prior_complement_sha256: str
    intended_state: str
    intended_entry_sha256: object
    expected_complement_sha256: str
    ownership: str
    parser: str
    normalization: str
    runtime_tuple_sha256: str
    policy_sha256: str
    qualification_admission_sha256: str
    attempt_family_sha256: str
    implementation_sha256: str
    observer_policy_sha256: str
    max_attempt_sequences: int

    def __post_init__(self):
        if not isinstance(self.operation_id, str) or not _CASE_ID.fullmatch(self.operation_id):
            raise QualificationInputError("semantic native result operation id is invalid")
        if type(self.max_attempt_sequences) is not int or self.max_attempt_sequences != 2:
            raise QualificationInputError("semantic native result family bound is invalid")
        _validate_operation_runtime(self.operation, self.runtime)
        _absolute_normalized("semantic native source path", self.source_path)
        if self.mode not in ATTEMPT_MODES or self.source_scope not in {CLAUDE_USER, CODEX_USER}:
            raise QualificationInputError("semantic native result mode or scope is invalid")
        if self.intended_state not in {"matching", "absent"} or self.ownership not in NATIVE_OWNERSHIP:
            raise QualificationInputError("semantic native target identity is invalid")
        for value in (self.source_sha256, self.source_identity_sha256,
                      self.prior_complement_sha256,
                      self.expected_complement_sha256, self.runtime_tuple_sha256,
                      self.policy_sha256, self.qualification_admission_sha256,
                      self.attempt_family_sha256, self.implementation_sha256,
                      self.observer_policy_sha256):
            if not _is_digest(value):
                raise QualificationInputError("semantic native result digest is invalid")
        for value in (self.prior_entry_sha256, self.intended_entry_sha256):
            if value is not None and not _is_digest(value):
                raise QualificationInputError("semantic native entry digest is invalid")
        for value in (self.parser, self.normalization):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise QualificationInputError("semantic native parser identity is invalid")

    def public_dict(self):
        return dict(self.__dict__)

    def digest(self):
        return _digest_json(self.public_dict())


def fixed_argv(case, runtime_tuple):
    """Return the only argv forms the collector accepts; never execute them."""
    if runtime_tuple.runtime != case.runtime:
        raise QualificationInputError("case and runtime tuple differ")
    executable = runtime_tuple.executable_path
    if case.operation == CLAUDE_ENSURE:
        return (
            executable,
            "mcp",
            "add",
            "--scope",
            "user",
            "--transport",
            "stdio",
            "council",
            "--",
            case.stdio.python_executable,
            case.stdio.adapter_path,
        )
    if case.operation == CLAUDE_REMOVE:
        return (executable, "mcp", "remove", "--scope", "user", "council")
    if case.operation == CODEX_ENSURE:
        return (
            executable,
            "mcp",
            "add",
            "council",
            "--",
            case.stdio.python_executable,
            case.stdio.adapter_path,
        )
    if case.operation == CODEX_REMOVE:
        return (executable, "mcp", "remove", "council")
    raise QualificationInputError("operation is not a fixed native operation")


def collect_case(case, admission, runtime_tuple, launch_once, observe_once):
    """Collect one case through injected seams, with no retry and no qualification."""
    preflight = _preflight(case, admission, runtime_tuple)
    if preflight:
        return _refusal_packet(case, admission, runtime_tuple, preflight)

    before_observation = _observe(case, case.before)
    if before_observation.state != case.expected_initial_state:
        return _refusal_packet(
            case,
            admission,
            runtime_tuple,
            ("initial_state_mismatch",),
            before_observation,
        )
    argv = fixed_argv(case, runtime_tuple)
    launch = launch_once(argv, case)
    if not isinstance(launch, LaunchReceipt):
        raise QualificationInputError("launch seam returned the wrong receipt type")
    _validate_launch(case, runtime_tuple, argv, launch)
    post = observe_once(case)
    if not isinstance(post, ObservationReceipt):
        raise QualificationInputError("observation seam returned the wrong receipt type")
    _validate_post(case, post)
    after_observation = _observe(case, post.after)
    classification, issues = _classify(
        case,
        runtime_tuple,
        launch,
        post,
        before_observation,
        after_observation,
    )
    return _evidence_packet(
        case,
        admission,
        runtime_tuple,
        argv,
        launch,
        post,
        before_observation,
        after_observation,
        classification,
        issues,
    )


def run_qualified_attempt(
    decision,
    case,
    admission,
    runtime_tuple,
    mode,
    journal_before_spawn,
    launch_once,
    observe_once,
):
    """Run one decision-bound attempt entirely through injected effect seams."""
    if not all(callable(seam) for seam in (
        journal_before_spawn, launch_once, observe_once
    )):
        raise QualificationInputError("qualified attempt seams must be callable")
    selected = _validate_decision_for_attempt(
        decision, case, admission, runtime_tuple, mode
    )
    argv = fixed_argv(case, runtime_tuple)
    journal = {
        "format": ATTEMPT_JOURNAL_FORMAT,
        "decision_id": decision.decision_id,
        "decision_sha256": decision.digest(),
        "mode": mode,
        "operation": case.operation,
        "runtime": case.runtime,
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "case_id": case.case_id,
        "case_sha256": _case_digest(case),
        "qualified_case_packet_sha256": selected[2],
        "argv_sha256": _digest_json(list(argv)),
        "permitted_write_paths_sha256": _digest_json(
            sorted(case.permitted_write_paths)
        ),
        "prior_source_sha256": _sha256(case.before.content),
        "target_complement_sha256": case.expected_target_complement_sha256,
    }
    journal_sha256 = _digest_json(journal)
    issued = journal_before_spawn(dict(journal), journal_sha256)
    if issued != journal_sha256:
        raise QualificationInputError(
            "journal seam did not bind the exact pre-spawn record"
        )
    counts = {"launch": 0, "observe": 0}

    def guarded_launch(supplied_argv, supplied_case):
        if counts["launch"]:
            raise QualificationInputError("qualified attempt cannot retry launch")
        counts["launch"] += 1
        return launch_once(supplied_argv, supplied_case)

    def guarded_observe(supplied_case):
        if counts["observe"]:
            raise QualificationInputError("qualified attempt cannot retry observation")
        counts["observe"] += 1
        return observe_once(supplied_case)

    packet = collect_case(
        case,
        admission,
        runtime_tuple,
        guarded_launch,
        guarded_observe,
    )
    if packet.get("collection_status") != "evidence_collected":
        raise QualificationInputError(
            "qualified attempt changed between decision and launch"
        )
    return {
        "format": ATTEMPT_FORMAT,
        "qualification_decision": decision.public_dict(),
        "decision_id": decision.decision_id,
        "decision_sha256": decision.digest(),
        "mode": mode,
        "operation": case.operation,
        "runtime": case.runtime,
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "case_id": case.case_id,
        "case_sha256": _case_digest(case),
        "qualified_case_packet_sha256": selected[2],
        "journal_sha256": journal_sha256,
        "journal_issued_before_launch": True,
        "launch_count": counts["launch"],
        "observation_count": counts["observe"],
        "classification": packet["classification"],
        "issues": packet["issues"],
        "collection_packet_sha256": _digest_json(packet),
        "collection": packet,
        "qualification_claimed": False,
    }


def _validate_decision_for_attempt(decision, case, admission, runtime_tuple, mode):
    if not isinstance(decision, QualificationDecision):
        raise QualificationInputError("a qualification decision is required")
    if (not isinstance(case, QualificationCase) or
            not isinstance(admission, FixtureAdmission) or
            not isinstance(runtime_tuple, RuntimeTuple)):
        raise QualificationInputError("qualified attempt inputs have invalid types")
    # Re-run frozen-record validation in case a caller bypassed dataclass creation.
    decision.__post_init__()
    if (
        decision.mode != mode
        or decision.operation != case.operation
        or decision.runtime != case.runtime
        or decision.runtime_tuple_sha256 != runtime_tuple.digest()
    ):
        raise QualificationInputError("qualification decision differs from attempt")
    expected = FIXED_CASES.get(case.case_id)
    if expected is None or expected[:3] != (
        case.runtime,
        case.operation,
        case.expected_initial_state,
    ):
        raise QualificationInputError("attempt case differs from fixed inventory")
    issues = _preflight(case, admission, runtime_tuple)
    before = _observe(case, case.before)
    if issues or before.state != case.expected_initial_state:
        raise QualificationInputError("attempt inputs fail qualification preflight")
    selected = next(
        (item for item in decision.case_evidence if item[0] == case.case_id), None
    )
    if selected is None or selected[1] != _case_digest(case):
        raise QualificationInputError("qualification decision case binding differs")
    return selected


def run_admitted_attempt(
    binding,
    semantic_identity,
    attempt_family,
    qualification_admission,
    support,
    implementation,
    policy,
    case,
    execution_admission,
    runtime_tuple,
    journal_before_spawn,
    launch_once,
    observe_once,
):
    """Run one native-v3 attempt through already admitted supervisor seams."""
    if not all(callable(seam) for seam in (
        journal_before_spawn, launch_once, observe_once
    )):
        raise QualificationInputError("admitted attempt seams must be callable")
    if not isinstance(binding, NativeAttemptBinding):
        raise QualificationInputError("native attempt binding is required")
    expected_binding = build_native_attempt_binding(
        binding.operation_id, binding.sequence, binding.mode, case,
        execution_admission, runtime_tuple, qualification_admission,
        support, implementation, policy, attempt_family,
        binding.previous_attempt_terminal_sha256,
    )
    if binding != expected_binding:
        raise QualificationInputError("current native attempt binding differs")
    expected_semantic = build_semantic_native_result_identity(
        binding, execution_admission.ownership, attempt_family
    )
    if not isinstance(semantic_identity, SemanticNativeResultIdentity) or (
        semantic_identity != expected_semantic
    ):
        raise QualificationInputError("semantic native result identity differs")
    admitted = validate_qualification_admission(
        qualification_admission, support, implementation, policy,
        runtime_tuple, binding.operation,
    )
    journal = {
        "format": NATIVE_JOURNAL_FORMAT,
        "operation_id": binding.operation_id,
        "sequence": binding.sequence,
        "mode": binding.mode,
        "operation": binding.operation,
        "runtime": binding.runtime,
        "attempt_binding_sha256": binding.digest(),
        "attempt_family_sha256": attempt_family.digest(),
        "previous_attempt_terminal_sha256": binding.previous_attempt_terminal_sha256,
        "semantic_result_sha256": semantic_identity.digest(),
        "qualification_admission_sha256": admitted.digest(),
        "support_decision_sha256": support.digest(),
        "implementation_sha256": implementation.digest(),
        "policy_sha256": policy.digest(),
        "execution_admission_sha256": execution_admission.digest(),
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "quiescent_decision_sha256": execution_admission.quiescent_decision_sha256,
        "state": "issued",
    }
    journal_sha256 = _digest_json(journal)
    if journal_before_spawn(dict(journal), journal_sha256) != journal_sha256:
        raise QualificationInputError("admitted journal seam did not bind issued state")
    counts = {"launch": 0, "observe": 0}

    def guarded_launch(argv, supplied_binding):
        if counts["launch"]:
            raise QualificationInputError("admitted attempt cannot retry launch")
        counts["launch"] += 1
        return launch_once(argv, supplied_binding)

    def guarded_observe(supplied_binding):
        if counts["observe"]:
            raise QualificationInputError("admitted attempt cannot retry observation")
        counts["observe"] += 1
        return observe_once(supplied_binding)

    launch = guarded_launch(binding.argv, binding)
    if not isinstance(launch, LaunchReceipt):
        raise QualificationInputError("admitted launch returned the wrong receipt type")
    _validate_launch(case, runtime_tuple, binding.argv, launch)
    post = guarded_observe(binding)
    if not isinstance(post, ObservationReceipt):
        raise QualificationInputError("admitted observer returned the wrong receipt type")
    _validate_post(case, post)
    before = _observe(case, case.before)
    after = _observe(case, post.after)
    classification, issues = _classify(
        case, runtime_tuple, launch, post, before, after
    )
    issues = list(issues)
    if classification == "observed_target" and (
        after.state != semantic_identity.intended_state or
        after.entry_sha256 != semantic_identity.intended_entry_sha256 or
        after.complement_sha256 != semantic_identity.expected_complement_sha256
    ):
        classification = "unknown"
        issues.append("semantic_target_mismatch")
    if classification == "observed_prior" and (
        after.source_sha256 != semantic_identity.source_sha256 or
        after.entry_sha256 != semantic_identity.prior_entry_sha256 or
        after.complement_sha256 != semantic_identity.prior_complement_sha256
    ):
        classification = "unknown"
        issues.append("semantic_prior_mismatch")
    evidence = _admitted_attempt_evidence(launch, post, after)
    return {
        "format": NATIVE_ATTEMPT_FORMAT,
        "operation_id": binding.operation_id,
        "sequence": binding.sequence,
        "mode": binding.mode,
        "operation": binding.operation,
        "runtime": binding.runtime,
        "attempt_binding_sha256": binding.digest(),
        "semantic_result_sha256": semantic_identity.digest(),
        "qualification_admission_sha256": admitted.digest(),
        "implementation_sha256": implementation.digest(),
        "policy_sha256": policy.digest(),
        "execution_admission_sha256": execution_admission.digest(),
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "journal_sha256": journal_sha256,
        "journal_issued_before_launch": True,
        "launch_count": counts["launch"],
        "observation_count": counts["observe"],
        "classification": classification,
        "issues": sorted(set(issues)),
        "post_source_sha256": after.source_sha256,
        "post_observation_sha256": _digest_json(after.public_dict()),
        "evidence": evidence,
        "qualification_claimed": False,
        "native_support_claimed": False,
    }


def _admitted_attempt_evidence(launch, post, after):
    unexpected = sorted(set(post.changed_paths) - {post.after.path})
    return {
        "passive_after": after.public_dict(),
        "process": {
            "result_kind": launch.result_kind,
            "process_state": launch.process_state,
            "process_generation_sha256": launch.process_generation_sha256,
            "network_state": launch.network_state,
            "network_evidence_sha256": launch.network_evidence_sha256,
            "returncode": launch.returncode,
            "timed_out": launch.timed_out,
            "output_lost": launch.output_lost,
            "stdout_sha256": _sha256(launch.stdout),
            "stdout_bytes": len(launch.stdout),
            "stderr_sha256": _sha256(launch.stderr),
            "stderr_bytes": len(launch.stderr),
        },
        "write_observation": {
            "changed_path_count": len(post.changed_paths),
            "changed_paths_sha256": _digest_json(sorted(post.changed_paths)),
            "unexpected_path_count": len(unexpected),
            "unexpected_paths_sha256": _digest_json(unexpected),
            "independent_complement_sha256": post.independent_complement_sha256,
            "sentinel_started": post.sentinel_started,
        },
    }


def validate_case_manifest(raw):
    """Validate the checked-in fixed case inventory without creating commands."""
    if not isinstance(raw, bytes) or len(raw) > 128 * 1024:
        raise QualificationInputError("case manifest must be bounded bytes")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise QualificationInputError("case manifest has duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                QualificationInputError("case manifest has nonfinite number")
            ),
        )
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, QualificationInputError):
            raise
        raise QualificationInputError("case manifest is invalid JSON")
    if not isinstance(value, dict) or set(value) != {
        "format",
        "qualification_eligible",
        "cases",
    }:
        raise QualificationInputError("case manifest shape is invalid")
    if value["format"] != FORMAT or value["qualification_eligible"] is not False:
        raise QualificationInputError("case manifest cannot claim qualification")
    cases = value["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > 64:
        raise QualificationInputError("case manifest case count is invalid")
    seen = set()
    safe = []
    required = {
        "case_id",
        "runtime",
        "operation",
        "expected_version",
        "expected_os_name",
        "expected_architecture",
        "expected_initial_state",
        "fixture_condition",
    }
    for record in cases:
        if not isinstance(record, dict) or set(record) != required:
            raise QualificationInputError("case manifest record shape is invalid")
        case_id = record["case_id"]
        if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
            raise QualificationInputError("manifest case id is invalid")
        if case_id in seen:
            raise QualificationInputError("manifest case id is duplicated")
        seen.add(case_id)
        runtime = record["runtime"]
        operation = record["operation"]
        if runtime not in {"claude", "codex"} or operation not in NATIVE_OPERATIONS:
            raise QualificationInputError("manifest runtime or operation is invalid")
        if not operation.startswith(runtime + "_"):
            raise QualificationInputError("manifest runtime and operation differ")
        if record["expected_initial_state"] not in INITIAL_STATES:
            raise QualificationInputError("manifest initial state is invalid")
        if record["expected_os_name"] != "Darwin":
            raise QualificationInputError("manifest is not the selected macOS surface")
        if record["fixture_condition"] not in {
            "ordinary",
            "malformed_config",
            "unwritable_config",
        }:
            raise QualificationInputError("manifest fixture condition is invalid")
        for key in ("expected_version", "expected_architecture"):
            if not isinstance(record[key], str) or not record[key]:
                raise QualificationInputError("manifest tuple field is invalid")
        expected = FIXED_CASES.get(case_id)
        actual = (
            runtime,
            operation,
            record["expected_initial_state"],
            record["fixture_condition"],
        )
        if expected is None or actual != expected:
            raise QualificationInputError("manifest case differs from fixed inventory")
        if record["expected_version"] != SELECTED_VERSIONS[runtime]:
            raise QualificationInputError("manifest version differs from selected tuple")
        if record["expected_architecture"] != "arm64":
            raise QualificationInputError("manifest architecture differs from selected tuple")
        safe.append(
            {
                "case_id": case_id,
                "runtime": runtime,
                "operation": operation,
                "expected_version": record["expected_version"],
                "expected_os_name": record["expected_os_name"],
                "expected_architecture": record["expected_architecture"],
                "expected_initial_state": record["expected_initial_state"],
                "fixture_condition": record["fixture_condition"],
            }
        )
    if seen != set(FIXED_CASES):
        raise QualificationInputError("manifest case inventory is incomplete")
    return {
        "format": FORMAT,
        "manifest_sha256": _sha256(raw),
        "case_count": len(safe),
        "cases": safe,
        "qualification_eligible": False,
    }


def validate_native_shape_policy(raw):
    """Parse the closed native-v3 policy; the policy never grants authority."""
    value = _parse_bounded_json(raw, "native shape policy")
    _exact_keys(value, ("format", "policies", "qualification_eligible"),
                "native shape policy")
    if value["format"] != NATIVE_POLICY_FORMAT or value["qualification_eligible"] is not False:
        raise QualificationInputError("native shape policy cannot claim qualification")
    policies = value["policies"]
    if not isinstance(policies, list) or len(policies) != len(NATIVE_OPERATIONS):
        raise QualificationInputError("native shape policy inventory is incomplete")
    expected_order = (CLAUDE_ENSURE, CLAUDE_REMOVE, CODEX_ENSURE, CODEX_REMOVE)
    safe = []
    for index, record in enumerate(policies):
        if not isinstance(record, dict):
            raise QualificationInputError("native shape policy record must be an object")
        _exact_keys(
            record,
            ("accepted_source_form", "allowed_initial_states", "argv_rule",
             "complement_rule", "environment_allowlist", "intended_state", "modes",
             "neutral_cwd", "normalization", "observer_policy_id", "operation",
             "parser", "path_rule", "policy_id", "promised_raw_format_preservation",
             "runtime", "scope", "source_file_must_exist", "stdin",
             "target_entry_rule", "version", "write_set_rule"),
            "native shape policy record",
        )
        operation = expected_order[index]
        runtime = "claude" if operation.startswith("claude_") else "codex"
        ensure = operation.endswith("_ensure")
        expected = {
            "accepted_source_form": (
                "strict-json-object-v1" if runtime == "claude"
                else "canonical-toml-subset-no-comments-v1"
            ),
            "allowed_initial_states": ["absent" if ensure else "matching"],
            "argv_rule": record["policy_id"],
            "complement_rule": (
                "raw-selected-entry-mask-v1" if runtime == "claude"
                else "semantic-tomllib-without-selected-entry-v1"
            ),
            "environment_allowlist": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"],
            "intended_state": "matching" if ensure else "absent",
            "modes": ["forward" if ensure else "inverse", "recovery"],
            "neutral_cwd": "/private/tmp",
            "normalization": "none" if runtime == "claude" else "semantic-tomllib-v1",
            "observer_policy_id": "darwin-whole-process-group-v1",
            "operation": operation,
            "parser": "strict-json-span-v1" if runtime == "claude" else "stdlib-tomllib-v1",
            "path_rule": (
                "home-dot-claude-json-v1" if runtime == "claude"
                else "home-dot-codex-config-toml-v1"
            ),
            "policy_id": operation.replace("_", "-").replace("stdio-ensure", "stdio-ensure-v1").replace("stdio-remove", "stdio-remove-v1"),
            "promised_raw_format_preservation": runtime == "claude",
            "runtime": runtime,
            "scope": CLAUDE_USER if runtime == "claude" else CODEX_USER,
            "source_file_must_exist": True,
            "stdin": "closed",
            "target_entry_rule": (
                "fixed-council-stdio-entry-v1" if ensure
                else "fixed-council-stdio-absence-v1"
            ),
            "version": 1,
            "write_set_rule": "qualification-admission-exact-v1",
        }
        if record != expected:
            raise QualificationInputError("native shape policy record differs from closed policy")
        safe.append(dict(record))
    canonical = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if canonical != raw:
        raise QualificationInputError("native shape policy bytes are not canonical")
    return NativeShapePolicy(
        NATIVE_POLICY_FORMAT, _sha256(raw), tuple(safe), False
    )


def validate_qualification_admission(
    record, support, implementation, policy, runtime_tuple, operation
):
    """Validate an owner-read trust-root record against every consistency input."""
    if not isinstance(support, QualificationSupportDecision):
        raise QualificationInputError("qualification support decision is required")
    if not isinstance(implementation, NativeImplementationIdentity):
        raise QualificationInputError("native implementation identity is required")
    if not isinstance(runtime_tuple, RuntimeTuple):
        raise QualificationInputError("runtime tuple is required")
    support.__post_init__()
    implementation.__post_init__()
    selected = _policy_for(policy, operation)
    _validate_support_decision(
        support, implementation, policy, selected, runtime_tuple, operation
    )
    if isinstance(record, QualificationAdmission):
        admission_record = record
    else:
        _exact_keys(
            record,
            ("admission_id", "operation", "runtime", "runtime_tuple_sha256",
             "policy_id", "policy_version", "policy_sha256",
             "implementation_sha256", "support_decision_sha256",
             "intended_entry_sha256", "case_evidence",
             "independent_review_sha256", "support_matrix_sha256", "owner_authority",
             "admitted", "fixed_relative_path"),
            "qualification admission",
        )
        expected_path = (
            ".council-lifecycle/v1/native-qualification-admissions/%s.json" % operation
        )
        if record["fixed_relative_path"] != expected_path:
            raise QualificationInputError("qualification admission path is not fixed")
        admission_record = QualificationAdmission(
            admission_id=record["admission_id"], operation=record["operation"],
            runtime=record["runtime"], runtime_tuple_sha256=record["runtime_tuple_sha256"],
            policy_id=record["policy_id"], policy_version=record["policy_version"],
            policy_sha256=record["policy_sha256"],
            implementation_sha256=record["implementation_sha256"],
            support_decision_sha256=record["support_decision_sha256"],
            intended_entry_sha256=record["intended_entry_sha256"],
            case_evidence=_parse_case_evidence(record["case_evidence"]),
            independent_review_sha256=record["independent_review_sha256"],
            support_matrix_sha256=record["support_matrix_sha256"],
            owner_authority=record["owner_authority"], admitted=record["admitted"],
        )
    admission_record.__post_init__()
    expected = {
        "operation": operation,
        "runtime": runtime_tuple.runtime,
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "policy_id": selected["policy_id"],
        "policy_version": selected["version"],
        "policy_sha256": policy.digest(),
        "implementation_sha256": implementation.digest(),
        "support_decision_sha256": support.digest(),
        "intended_entry_sha256": support.intended_entry_sha256,
        "case_evidence": support.case_evidence,
        "independent_review_sha256": support.independent_review_sha256,
        "support_matrix_sha256": support.support_matrix_sha256,
    }
    for name, value in expected.items():
        if getattr(admission_record, name) != value:
            raise QualificationInputError("qualification admission %s differs" % name)
    return admission_record


def _native_attempt_stable_values(
    operation_id,
    mode,
    case,
    execution_admission,
    runtime_tuple,
    qualification_admission,
    support,
    implementation,
    policy,
):
    """Derive the stable family fields from owner and closed-policy inputs."""
    if not isinstance(case, QualificationCase):
        raise QualificationInputError("native qualification case is required")
    if not isinstance(execution_admission, NativeExecutionAdmission):
        raise QualificationInputError("native execution admission is required")
    selected = _policy_for(policy, case.operation, mode)
    admitted = validate_qualification_admission(
        qualification_admission, support, implementation, policy,
        runtime_tuple, case.operation,
    )
    execution_admission.__post_init__()
    _validate_execution_admission(
        execution_admission, case, selected, runtime_tuple, implementation
    )
    before = _observe(case, case.before)
    if (before.state not in selected["allowed_initial_states"] or
            before.state != case.expected_initial_state):
        raise QualificationInputError("native current source state is unsupported")
    intended_entry = admitted.intended_entry_sha256
    argv = fixed_argv(case, runtime_tuple)
    return {
        "operation_id": operation_id,
        "mode": mode,
        "operation": case.operation,
        "runtime": case.runtime,
        "state_root": execution_admission.state_root,
        "source_path": case.before.path,
        "source_scope": case.before.scope,
        "initial_source_sha256": before.source_sha256,
        "source_identity_sha256": execution_admission.source_identity_sha256,
        "prior_state": before.state,
        "prior_entry_sha256": before.entry_sha256,
        "prior_complement_sha256": before.complement_sha256,
        "intended_state": selected["intended_state"],
        "intended_entry_sha256": intended_entry,
        "expected_complement_sha256": case.expected_target_complement_sha256,
        "ownership": execution_admission.ownership,
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "executable_path": runtime_tuple.executable_path,
        "python_executable": case.stdio.python_executable,
        "adapter_path": case.stdio.adapter_path,
        "argv": argv,
        "permitted_inverse": _native_inverse(case.operation),
        "parser": selected["parser"],
        "normalization": selected["normalization"],
        "policy_id": selected["policy_id"],
        "policy_version": selected["version"],
        "policy_sha256": policy.digest(),
        "observer_policy_id": selected["observer_policy_id"],
        "observer_policy_sha256": implementation.observer_policy_sha256,
        "write_set": execution_admission.write_set,
        "neutral_cwd": execution_admission.neutral_cwd,
        "stdin": selected["stdin"],
        "environment_keys": execution_admission.environment_keys,
        "environment_sha256": execution_admission.environment_sha256,
        "qualification_admission_sha256": admitted.digest(),
        "implementation_sha256": implementation.digest(),
        "max_attempt_sequences": 2,
    }


def build_native_attempt_family(
    operation_id,
    mode,
    case,
    execution_admission,
    runtime_tuple,
    qualification_admission,
    support,
    implementation,
    policy,
):
    return NativeAttemptFamilyIdentity(
        **_native_attempt_stable_values(
            operation_id,
            mode,
            case,
            execution_admission,
            runtime_tuple,
            qualification_admission,
            support,
            implementation,
            policy,
        )
    )


def build_native_attempt_binding(
    operation_id,
    sequence,
    mode,
    case,
    execution_admission,
    runtime_tuple,
    qualification_admission,
    support,
    implementation,
    policy,
    attempt_family=None,
    previous_attempt_terminal_sha256=None,
):
    """Derive one sequence binding under an immutable two-attempt family."""
    stable = _native_attempt_stable_values(
        operation_id,
        mode,
        case,
        execution_admission,
        runtime_tuple,
        qualification_admission,
        support,
        implementation,
        policy,
    )
    expected_family = NativeAttemptFamilyIdentity(**stable)
    if attempt_family is None:
        attempt_family = expected_family
    if not isinstance(attempt_family, NativeAttemptFamilyIdentity) or (
        attempt_family != expected_family
    ):
        raise QualificationInputError("native attempt family differs")
    binding_values = dict(stable)
    binding_values["source_sha256"] = binding_values.pop("initial_source_sha256")
    binding_values.pop("max_attempt_sequences")
    return NativeAttemptBinding(
        attempt_family_sha256=attempt_family.digest(),
        sequence=sequence,
        execution_admission_sha256=execution_admission.digest(),
        quiescent_decision_sha256=execution_admission.quiescent_decision_sha256,
        previous_attempt_terminal_sha256=previous_attempt_terminal_sha256,
        **binding_values,
    )


def build_semantic_native_result_identity(binding, ownership, attempt_family=None):
    """Build the immutable pre-intent meaning without a post-source digest."""
    if not isinstance(binding, NativeAttemptBinding):
        raise QualificationInputError("native attempt binding is required")
    binding.__post_init__()
    if not isinstance(attempt_family, NativeAttemptFamilyIdentity):
        raise QualificationInputError("native attempt family is required")
    attempt_family.__post_init__()
    if binding.attempt_family_sha256 != attempt_family.digest():
        raise QualificationInputError("semantic native attempt family differs")
    if ownership != binding.ownership:
        raise QualificationInputError("semantic native ownership differs from attempt")
    return SemanticNativeResultIdentity(
        operation_id=binding.operation_id, mode=binding.mode,
        operation=binding.operation, runtime=binding.runtime,
        source_path=binding.source_path, source_scope=binding.source_scope,
        source_sha256=binding.source_sha256,
        source_identity_sha256=binding.source_identity_sha256,
        prior_entry_sha256=binding.prior_entry_sha256,
        prior_complement_sha256=binding.prior_complement_sha256,
        intended_state=binding.intended_state,
        intended_entry_sha256=binding.intended_entry_sha256,
        expected_complement_sha256=binding.expected_complement_sha256,
        ownership=binding.ownership, parser=binding.parser,
        normalization=binding.normalization,
        runtime_tuple_sha256=binding.runtime_tuple_sha256,
        policy_sha256=binding.policy_sha256,
        qualification_admission_sha256=binding.qualification_admission_sha256,
        attempt_family_sha256=attempt_family.digest(),
        implementation_sha256=binding.implementation_sha256,
        observer_policy_sha256=binding.observer_policy_sha256,
        max_attempt_sequences=attempt_family.max_attempt_sequences,
    )


def _policy_for(policy, operation, mode=None):
    if not isinstance(policy, NativeShapePolicy):
        raise QualificationInputError("validated native shape policy is required")
    policy.__post_init__()
    selected = next((item for item in policy.policies if item["operation"] == operation), None)
    if selected is None:
        raise QualificationInputError("native operation has no closed policy")
    if mode is not None and mode not in selected["modes"]:
        raise QualificationInputError("native attempt mode is outside closed policy")
    return selected


def _expected_policy_record(operation):
    _validate_operation_runtime(
        operation, "claude" if str(operation).startswith("claude_") else "codex"
    )
    runtime = "claude" if operation.startswith("claude_") else "codex"
    ensure = operation.endswith("_ensure")
    policy_id = (
        operation.replace("_", "-")
        .replace("stdio-ensure", "stdio-ensure-v1")
        .replace("stdio-remove", "stdio-remove-v1")
    )
    return {
        "accepted_source_form": (
            "strict-json-object-v1" if runtime == "claude"
            else "canonical-toml-subset-no-comments-v1"
        ),
        "allowed_initial_states": ["absent" if ensure else "matching"],
        "argv_rule": policy_id,
        "complement_rule": (
            "raw-selected-entry-mask-v1" if runtime == "claude"
            else "semantic-tomllib-without-selected-entry-v1"
        ),
        "environment_allowlist": ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"],
        "intended_state": "matching" if ensure else "absent",
        "modes": ["forward" if ensure else "inverse", "recovery"],
        "neutral_cwd": "/private/tmp",
        "normalization": "none" if runtime == "claude" else "semantic-tomllib-v1",
        "observer_policy_id": "darwin-whole-process-group-v1",
        "operation": operation,
        "parser": "strict-json-span-v1" if runtime == "claude" else "stdlib-tomllib-v1",
        "path_rule": (
            "home-dot-claude-json-v1" if runtime == "claude"
            else "home-dot-codex-config-toml-v1"
        ),
        "policy_id": policy_id,
        "promised_raw_format_preservation": runtime == "claude",
        "runtime": runtime,
        "scope": CLAUDE_USER if runtime == "claude" else CODEX_USER,
        "source_file_must_exist": True,
        "stdin": "closed",
        "target_entry_rule": (
            "fixed-council-stdio-entry-v1" if ensure
            else "fixed-council-stdio-absence-v1"
        ),
        "version": 1,
        "write_set_rule": "qualification-admission-exact-v1",
    }


def _validate_support_decision(support, implementation, policy, selected,
                               runtime_tuple, operation):
    support.__post_init__()
    expected = {
        "operation": operation,
        "runtime": runtime_tuple.runtime,
        "runtime_tuple_sha256": runtime_tuple.digest(),
        "policy_id": selected["policy_id"],
        "policy_version": selected["version"],
        "policy_sha256": policy.digest(),
        "implementation_sha256": implementation.digest(),
    }
    for name, value in expected.items():
        if getattr(support, name) != value:
            raise QualificationInputError("qualification support %s differs" % name)


def _parse_case_evidence(value):
    if not isinstance(value, list):
        raise QualificationInputError("qualification case evidence must be a list")
    result = []
    for item in value:
        _exact_keys(
            item, ("case_id", "case_sha256", "packet_sha256", "evidence_kind"),
            "qualification case evidence",
        )
        result.append((item["case_id"], item["case_sha256"], item["packet_sha256"],
                       item["evidence_kind"]))
    return tuple(result)


def _validate_execution_admission(admission_value, case, selected, runtime_tuple,
                                  implementation):
    if (admission_value.operation != case.operation or
            admission_value.runtime != case.runtime):
        raise QualificationInputError("native execution admission operation differs")
    expected_ownership = (
        {"created"} if case.operation.endswith("_ensure")
        else {"already_owned", "adopted_by_explicit_plan"}
    )
    if admission_value.ownership not in expected_ownership:
        raise QualificationInputError("native execution ownership differs from operation")
    expected_config = str(
        PurePosixPath(admission_value.home) /
        (".claude.json" if case.runtime == "claude" else ".codex/config.toml")
    )
    expected_state = str(PurePosixPath(admission_value.home) / ".claude/peer-consults")
    expected_adapter = str(
        PurePosixPath(admission_value.payload_root) / "scripts/council_mcp.py"
    )
    expected_payload = str(
        PurePosixPath(admission_value.home) / ".claude/skills/council"
    )
    if (admission_value.config_path != expected_config or
            admission_value.state_root != expected_state or
            admission_value.payload_root != expected_payload or
            case.before.path != expected_config or case.before.scope != selected["scope"] or
            case.neutral_cwd != selected["neutral_cwd"] or
            case.permitted_write_paths != admission_value.write_set or
            case.stdio.python_executable != "/usr/bin/python3" or
            case.stdio.adapter_path != expected_adapter or
            admission_value.neutral_cwd != selected["neutral_cwd"] or
            list(admission_value.environment_keys) != selected["environment_allowlist"] or
            admission_value.observer_policy_sha256 != implementation.observer_policy_sha256):
        raise QualificationInputError("native execution paths or policies differ")
    if (runtime_tuple.runtime != case.runtime or runtime_tuple.version != case.expected_version or
            runtime_tuple.os_name != case.expected_os_name or
            runtime_tuple.architecture != case.expected_architecture):
        raise QualificationInputError("native execution tuple differs from case")


def _preflight(case, admission, runtime_tuple):
    issues = []
    if admission.authority != FIXTURE_AUTHORITY:
        issues.append("fixture_authority_unrecognized")
    if admission.evidence_kind not in EVIDENCE_KINDS:
        issues.append("evidence_kind_unrecognized")
    if admission.account_kind != FIXTURE_ACCOUNT_KIND:
        issues.append("not_fixture_account")
    homes = {
        admission.fixture_home,
        admission.pwd_home,
        admission.pathlib_home,
        admission.environment_home,
    }
    if len(homes) != 1:
        issues.append("home_rebinding_or_mismatch")
    if admission.clean_fixture_state != CLEAN_FIXTURE_STATE:
        issues.append("fixture_cleanliness_unadmitted")
    if admission.credential_state != CREDENTIAL_STATE:
        issues.append("credential_state_not_clean")
    if case.before.path not in admission.admitted_config_paths:
        issues.append("config_source_unadmitted")
    if case.neutral_cwd != admission.admitted_neutral_cwd:
        issues.append("neutral_cwd_unadmitted")
    if _within(case.neutral_cwd, admission.fixture_home):
        issues.append("neutral_cwd_inside_fixture_home")
    if not _within(case.before.path, admission.fixture_home):
        issues.append("config_source_outside_fixture_home")
    if not _within(case.stdio.adapter_path, admission.fixture_home):
        issues.append("adapter_outside_fixture_home")
    expected_path = (
        str(PurePosixPath(admission.fixture_home) / ".claude.json")
        if case.runtime == "claude"
        else str(PurePosixPath(admission.fixture_home) / ".codex/config.toml")
    )
    if case.before.path != expected_path:
        issues.append("config_source_not_canonical")
    expected_scope = CLAUDE_USER if case.runtime == "claude" else CODEX_USER
    if case.before.scope != expected_scope:
        issues.append("config_scope_mismatch")
    if runtime_tuple.runtime != case.runtime:
        issues.append("runtime_tuple_mismatch")
    if runtime_tuple.version != case.expected_version:
        issues.append("runtime_version_mismatch")
    if runtime_tuple.os_name != case.expected_os_name:
        issues.append("runtime_os_mismatch")
    if runtime_tuple.architecture != case.expected_architecture:
        issues.append("runtime_architecture_mismatch")
    if set(case.permitted_write_paths) - set(admission.admitted_config_paths):
        issues.append("write_path_unadmitted")
    if set(case.permitted_write_paths) != {case.before.path}:
        issues.append("write_surface_not_single_config")
    return tuple(sorted(set(issues)))


def _observe(case, document):
    if case.runtime == "claude":
        return observe_claude_config(
            document, case.stdio, scope_inputs_complete=True
        )
    return observe_codex_config(document, case.stdio, layer_inputs_complete=True)


def _validate_launch(case, runtime_tuple, argv, receipt):
    if receipt.case_id != case.case_id:
        raise QualificationInputError("launch receipt case differs")
    if receipt.argv != argv:
        raise QualificationInputError("launch receipt argv differs")
    if receipt.runtime_tuple_digest != runtime_tuple.digest():
        raise QualificationInputError("launch receipt tuple differs")


def _validate_post(case, receipt):
    if receipt.case_id != case.case_id:
        raise QualificationInputError("observation receipt case differs")
    if receipt.after.path != case.before.path:
        raise QualificationInputError("observation source path differs")
    if receipt.after.scope != case.before.scope:
        raise QualificationInputError("observation source scope differs")


def _classify(case, runtime_tuple, launch, post, before_observation, after_observation):
    issues = []
    unexpected = set(post.changed_paths) - set(case.permitted_write_paths)
    if unexpected:
        issues.append("incidental_write_mismatch")
    if post.runtime_tuple_after != runtime_tuple:
        issues.append("runtime_tuple_changed")
    if post.sentinel_started:
        issues.append("unexpected_sentinel_start")
    if launch.process_state in {"surviving", "unidentified"}:
        issues.append("possible_live_writer")
    if launch.network_state == "activity_observed":
        issues.append("unexpected_network_activity")
    elif launch.network_state == "unobserved":
        issues.append("network_unobserved")
    if post.independent_complement_sha256 != after_observation.complement_sha256:
        issues.append("complement_mismatch")
    prior_exact = after_observation.source_sha256 == before_observation.source_sha256
    target_state = "matching" if case.operation.endswith("_ensure") else "absent"
    target = after_observation.state == target_state
    if target and after_observation.complement_sha256 != case.expected_target_complement_sha256:
        issues.append("target_complement_mismatch")
    if target:
        return (
            ("unknown", tuple(sorted(issues)))
            if issues else ("observed_target", ())
        )
    if prior_exact:
        return (
            ("unknown", tuple(sorted(issues)))
            if issues else ("observed_prior", ())
        )
    issues.append("third_state")
    return "unknown", tuple(sorted(set(issues)))


def _base_packet(case, admission, runtime_tuple):
    return {
        "format": FORMAT,
        "case_id": case.case_id,
        "case_sha256": _case_digest(case),
        "operation": case.operation,
        "runtime": case.runtime,
        "evidence_kind": admission.evidence_kind,
        "qualification_eligible": False,
        "qualification_status": "independent_genuine_runner_review_required",
        "self_declaration_is_qualification": False,
        "runtime_tuple": {
            "executable_path": runtime_tuple.executable_path,
            "executable_realpath": runtime_tuple.executable_realpath,
            "executable_sha256": runtime_tuple.executable_sha256,
            "version": runtime_tuple.version,
            "os_name": runtime_tuple.os_name,
            "architecture": runtime_tuple.architecture,
            "tuple_sha256": runtime_tuple.digest(),
        },
        "source": {
            "path": case.before.path,
            "scope": case.before.scope,
            "before_sha256": _sha256(case.before.content),
            "expected_target_complement_sha256": case.expected_target_complement_sha256,
        },
        "authority_assumptions": {
            "declaration_authority": admission.authority,
            "declaration_sha256": admission.declaration_sha256,
            "declaration_fields_sha256": admission.digest(),
            "fixture_account_declared": admission.account_kind == FIXTURE_ACCOUNT_KIND,
            "clean_fixture_declared": admission.clean_fixture_state == CLEAN_FIXTURE_STATE,
            "credentials_absent_declared": admission.credential_state == CREDENTIAL_STATE,
            "home_agreement_declared": len(
                {
                    admission.fixture_home,
                    admission.pwd_home,
                    admission.pathlib_home,
                    admission.environment_home,
                }
            )
            == 1,
            "declarations_require_external_verification": True,
        },
        "evidence_gaps": [
            "fixture admission requires independent genuine-runner verification",
            "runtime provenance and tuple require independent genuine-runner verification",
            "native process, network and whole-home write observations are caller supplied",
            "C2 admission, transaction, recovery and receipt integration is absent",
        ],
    }


def _refusal_packet(
    case, admission, runtime_tuple, reasons, before_observation=None
):
    packet = _base_packet(case, admission, runtime_tuple)
    packet.update(
        {
            "collection_status": "refused_before_launch",
            "classification": "unknown",
            "issues": list(reasons),
            "launch_count": 0,
            "observation_count": 0,
            "argv": None,
        }
    )
    if before_observation is not None:
        packet["passive_before"] = before_observation.public_dict()
    return packet


def _evidence_packet(
    case,
    admission,
    runtime_tuple,
    argv,
    launch,
    post,
    before_observation,
    after_observation,
    classification,
    issues,
):
    changed_digest = _digest_json(sorted(post.changed_paths))
    unexpected = sorted(
        set(post.changed_paths) - set(case.permitted_write_paths)
    )
    packet = _base_packet(case, admission, runtime_tuple)
    packet.update(
        {
            "collection_status": "evidence_collected",
            "classification": classification,
            "issues": list(issues),
            "launch_count": 1,
            "observation_count": 1,
            "argv": list(argv),
            "neutral_cwd": case.neutral_cwd,
            "passive_before": before_observation.public_dict(),
            "passive_after": after_observation.public_dict(),
            "process": {
                "result_kind": launch.result_kind,
                "process_state": launch.process_state,
                "process_generation_sha256": launch.process_generation_sha256,
                "network_state": launch.network_state,
                "network_evidence_sha256": launch.network_evidence_sha256,
                "returncode": launch.returncode,
                "timed_out": launch.timed_out,
                "output_lost": launch.output_lost,
                "stdout_sha256": _sha256(launch.stdout),
                "stdout_bytes": len(launch.stdout),
                "stderr_sha256": _sha256(launch.stderr),
                "stderr_bytes": len(launch.stderr),
            },
            "write_observation": {
                "changed_path_count": len(post.changed_paths),
                "changed_paths_sha256": changed_digest,
                "unexpected_path_count": len(unexpected),
                "unexpected_paths_sha256": _digest_json(unexpected),
                "independent_complement_sha256": post.independent_complement_sha256,
                "sentinel_started": post.sentinel_started,
            },
        }
    )
    return packet


def _parse_bounded_json(raw, label):
    if not isinstance(raw, bytes) or len(raw) > 128 * 1024:
        raise QualificationInputError(label + " must be bounded bytes")

    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise QualificationInputError(label + " has duplicate keys")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _token: (_ for _ in ()).throw(
                QualificationInputError(label + " has nonfinite number")
            ),
        )
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, QualificationInputError):
            raise
        raise QualificationInputError(label + " is invalid JSON")


def _exact_keys(value, names, label):
    if not isinstance(value, dict) or set(value) != set(names):
        raise QualificationInputError(label + " has unsupported fields")


def _absolute_normalized(label, value):
    if not isinstance(value, str):
        raise QualificationInputError(label + " must be absolute")
    path = PurePosixPath(value)
    if not path.is_absolute():
        raise QualificationInputError(label + " must be absolute")
    if ("\x00" in value or "//" in value or value.endswith("/") or
            any(part in (".", "..") for part in value.split("/")) or str(path) != value):
        raise QualificationInputError(label + " must be normalized")


def _case_digest(case):
    return _digest_json(
        {
            "case_id": case.case_id,
            "operation": case.operation,
            "expected_version": case.expected_version,
            "expected_os_name": case.expected_os_name,
            "expected_architecture": case.expected_architecture,
            "expected_initial_state": case.expected_initial_state,
            "source_path": case.before.path,
            "source_scope": case.before.scope,
            "source_sha256": _sha256(case.before.content),
            "python_executable": case.stdio.python_executable,
            "adapter_path": case.stdio.adapter_path,
            "neutral_cwd": case.neutral_cwd,
            "expected_target_complement_sha256": case.expected_target_complement_sha256,
            "permitted_write_paths": list(case.permitted_write_paths),
        }
    )


def _within(path, parent):
    child = PurePosixPath(path)
    ancestor = PurePosixPath(parent)
    return child != ancestor and ancestor in child.parents


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _digest_json(value):
    return _sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _is_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


__all__ = [
    "FORMAT",
    "ATTEMPT_FORMAT",
    "ATTEMPT_JOURNAL_FORMAT",
    "NATIVE_POLICY_FORMAT",
    "NATIVE_ATTEMPT_FORMAT",
    "NATIVE_JOURNAL_FORMAT",
    "MAX_OUTPUT_BYTES",
    "FIXTURE_ACCOUNT_KIND",
    "FIXTURE_AUTHORITY",
    "CLEAN_FIXTURE_STATE",
    "CREDENTIAL_STATE",
    "QualificationDecision",
    "NativeImplementationIdentity",
    "NativeShapePolicy",
    "QualificationSupportDecision",
    "QualificationAdmission",
    "NativeExecutionAdmission",
    "RuntimeTuple",
    "FixtureAdmission",
    "QualificationCase",
    "LaunchReceipt",
    "ObservationReceipt",
    "NativeAttemptFamilyIdentity",
    "NativeAttemptBinding",
    "SemanticNativeResultIdentity",
    "QualificationInputError",
    "fixed_argv",
    "collect_case",
    "run_qualified_attempt",
    "validate_native_shape_policy",
    "validate_qualification_admission",
    "build_native_attempt_family",
    "build_native_attempt_binding",
    "build_semantic_native_result_identity",
    "run_admitted_attempt",
    "validate_case_manifest",
]
