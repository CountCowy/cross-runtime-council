#!/usr/bin/env python3
"""Independent fixture and refusal tests for rehearsal_evidence.py."""

import ast
import copy
import json
import os
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rehearsal_evidence as evidence
from rehearsal_evidence import EvidenceError


FIXTURES = Path(__file__).parent / "fixtures" / "live_rehearsal"


def literal_json(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def private_dir(path):
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def private_file(path, value):
    path.write_bytes(evidence.canonical_json_bytes(value))
    os.chmod(path, 0o600)


class StrictJsonTests(unittest.TestCase):
    def test_duplicate_key_nonfinite_utf8_and_oversize_refuse(self):
        with self.assertRaisesRegex(EvidenceError, "duplicate-key"):
            evidence.strict_json_bytes(b'{"a":1,"a":2}')
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(token=token), self.assertRaisesRegex(
                EvidenceError, "nonfinite-number"
            ):
                evidence.strict_json_bytes(token)
        with self.assertRaisesRegex(EvidenceError, "invalid-utf8"):
            evidence.strict_json_bytes(b'"\xff"')
        exact = b"0" + b" " * (evidence.METADATA_LIMIT_BYTES - 1)
        self.assertEqual(evidence.strict_json_bytes(exact), 0)
        with self.assertRaisesRegex(EvidenceError, "metadata-too-large"):
            evidence.strict_json_bytes(exact + b" ")

    def test_bool_is_not_a_count_and_opaque_refs_are_path_safe(self):
        self.assertFalse(evidence.is_nonnegative_int(True))
        for value in (True, -1, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                evidence.require_nonnegative_int(value, "count")
        for value in ("/tmp/private", "../escape", "session:id", "UPPER"):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                evidence.require_ref(value, "ref")

    def test_utc_shape_and_observation_count_upper_bound_are_strict(self):
        for value in (
            "2026-09-08 20:00:00Z",
            "2026-09-08T20:00:00-04:00",
            "2026-09-08T20:00:00",
        ):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                evidence.require_utc(value, "time")
        result = literal_json("collector-result.fixture.json")
        result["claim"]["expected_count"] = evidence.MAX_OBSERVATION_COUNT + 1
        with self.assertRaisesRegex(EvidenceError, "count-too-large"):
            evidence.validate_collector_result(result)

    def test_unknown_fields_and_unknown_versions_refuse(self):
        result = literal_json("collector-result.fixture.json")
        result["future"] = True
        with self.assertRaisesRegex(EvidenceError, "unknown-field"):
            evidence.validate_collector_result(result)
        result = literal_json("collector-result.fixture.json")
        result["format"] = "collector-result/v2"
        with self.assertRaisesRegex(EvidenceError, "unsupported-format"):
            evidence.validate_collector_result(result)


class CollectorQualificationTests(unittest.TestCase):
    def setUp(self):
        self.result = literal_json("collector-result.fixture.json")
        self.qualification = literal_json("collector-qualification.fixture.json")

    def test_literal_fixture_parses_and_is_fixture_only(self):
        evidence.validate_collector_result(self.result)
        evidence.validate_collector_qualification(self.qualification)
        self.assertTrue(
            evidence.qualification_status(self.qualification, "fixture")["complete"]
        )
        live = evidence.qualification_status(self.qualification, "live")
        self.assertFalse(live["complete"])
        self.assertIn("fixture-qualification-cannot-support-live-claim", live["limitations"])

    def test_every_source_form_omission_fails_after_self_hash_recomputation(self):
        for kind in sorted(evidence.SOURCE_FORM_KINDS):
            damaged = copy.deepcopy(self.qualification)
            damaged["source_forms"] = [
                form for form in damaged["source_forms"] if form["kind"] != kind
            ]
            damaged["inventory_sha256"] = evidence.qualification_inventory_digest(
                damaged["source_forms"]
            )
            evidence.validate_collector_qualification(damaged)
            status = evidence.qualification_status(damaged, "fixture")
            self.assertFalse(status["complete"], kind)
            self.assertIn("source-form-not-inventoried:%s" % kind, status["limitations"])

    def test_inapplicable_form_needs_version_evidence_and_omission_outcome(self):
        for mutation in ("missing-evidence", "empty-flag"):
            damaged = copy.deepcopy(self.qualification)
            form = damaged["source_forms"][1]
            form["applicable"] = False
            form["omission_test"]["result"] = "not_applicable"
            if mutation == "missing-evidence":
                form["applicability_evidence_refs"] = []
            else:
                form["omission_test"]["evidence_refs"] = []
            damaged["inventory_sha256"] = evidence.qualification_inventory_digest(
                damaged["source_forms"]
            )
            status = evidence.qualification_status(damaged, "fixture")
            self.assertFalse(status["complete"], mutation)

    def test_changed_extractor_runtime_or_format_tuple_refuses_completeness(self):
        for path, value in (
            (("implementation_sha256",), "f" * 64),
            (("runtime", "version"), "2.0"),
            (("source_format", "version"), "2.0"),
        ):
            changed = copy.deepcopy(self.qualification)
            node = changed
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            match = evidence.collector_tuple_matches(self.result, changed)
            self.assertFalse(match["matches"], path)

    def test_every_nested_collector_reference_must_resolve_to_imported_bytes(self):
        refs = evidence.collector_evidence_refs(self.result, self.qualification)
        evidence.require_collector_evidence_links(self.result, self.qualification, refs)
        missing = set(refs)
        missing.remove(next(iter(missing)))
        with self.assertRaisesRegex(EvidenceError, "dangling-collector"):
            evidence.require_collector_evidence_links(
                self.result, self.qualification, missing
            )

    def test_candidate_unreviewed_and_missing_real_capture_stay_unqualified(self):
        for mutate in (
            lambda item: item.update(provenance="candidate"),
            lambda item: item.update(reviewed=False),
            lambda item: item.update(validation_evidence_refs=[]),
        ):
            changed = copy.deepcopy(self.qualification)
            mutate(changed)
            status = evidence.qualification_status(changed, "live")
            self.assertFalse(status["complete"])


class NativeEventDecisionTests(unittest.TestCase):
    def setUp(self):
        self.result = literal_json("collector-result.fixture.json")
        self.qualification = literal_json("collector-qualification.fixture.json")

    def decide(self, result=None, qualification=None, context="fixture"):
        return evidence.assess_arrival_count(
            result or self.result,
            qualification or self.qualification,
            context_kind=context,
            recovery_delivery_attempted=True,
            fresh_control_passed=True,
        )

    def test_one_qualified_fixture_arrival_exercises_pass_calculation(self):
        decision = self.decide()
        self.assertEqual(decision["result"], "pass")
        self.assertEqual(decision["verified_lower_bound"], 1)
        self.assertEqual(decision["excluded_event_counts"]["quote"], 1)

    def test_distinct_native_ids_with_same_envelope_count_twice(self):
        changed = copy.deepcopy(self.result)
        duplicate = copy.deepcopy(changed["events"][0])
        duplicate["native_event_id"] = "native-two"
        duplicate["projection_id"] = "projection-two"
        duplicate["native_record_key"] = "record-two"
        duplicate["byte_offset"] = 211
        changed["events"].append(duplicate)
        decision = self.decide(changed)
        self.assertEqual(decision["verified_lower_bound"], 2)
        self.assertEqual(decision["result"], "fail")

        incomplete = copy.deepcopy(self.qualification)
        incomplete["provenance"] = "candidate"
        decision = self.decide(changed, incomplete, context="live")
        self.assertEqual(decision["result"], "fail")
        self.assertEqual(decision["verified_lower_bound"], 2)

    def test_two_projections_of_one_stable_event_count_once(self):
        changed = copy.deepcopy(self.result)
        projection = copy.deepcopy(changed["events"][0])
        projection["projection_id"] = "projection-one-b"
        changed["events"].append(projection)
        decision = self.decide(changed)
        self.assertEqual(decision["result"], "pass")
        self.assertEqual(decision["verified_lower_bound"], 1)

    def test_conflicting_native_mapping_is_unobserved_but_lower_bound_remains(self):
        changed = copy.deepcopy(self.result)
        projection = copy.deepcopy(changed["events"][0])
        projection["projection_id"] = "projection-conflict"
        projection["native_record_key"] = "different-record"
        changed["events"].append(projection)
        decision = self.decide(changed)
        self.assertEqual(decision["verified_lower_bound"], 1)
        self.assertEqual(decision["result"], "unobserved")
        self.assertEqual(decision["mapping_conflicts"], ["native-one"])

    def test_one_visible_occurrence_without_qualification_is_unobserved(self):
        incomplete = copy.deepcopy(self.qualification)
        incomplete["provenance"] = "candidate"
        decision = self.decide(qualification=incomplete, context="live")
        self.assertEqual(decision["verified_lower_bound"], 1)
        self.assertEqual(decision["result"], "unobserved")

    def test_wrong_session_quote_tool_and_retry_do_not_count(self):
        changed = copy.deepcopy(self.result)
        for event_type in ("tool_projection", "local_retry", "ui_repeat"):
            event = copy.deepcopy(changed["events"][0])
            event["native_event_id"] = "native-" + event_type
            event["projection_id"] = "projection-" + event_type
            event["event_type"] = event_type
            changed["events"].append(event)
        wrong = copy.deepcopy(changed["events"][0])
        wrong["native_event_id"] = "native-wrong-session"
        wrong["projection_id"] = "projection-wrong-session"
        wrong["target"]["session_ref"] = "session-other"
        changed["events"].append(wrong)
        normalized = evidence.normalized_arrivals(changed)
        self.assertEqual(normalized["verified_lower_bound"], 1)
        self.assertEqual(normalized["wrong_target_events"], 1)
        self.assertEqual(normalized["excluded_event_counts"]["local_retry"], 1)

    def test_bool_expected_count_refuses(self):
        changed = copy.deepcopy(self.result)
        changed["claim"]["expected_count"] = True
        with self.assertRaisesRegex(EvidenceError, "nonnegative-integer-required"):
            evidence.validate_collector_result(changed)


class PrivateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rehearsal-evidence-")
        self.root = Path(self.temporary.name) / "run"
        private_dir(self.root)
        private_dir(self.root / "objects")
        private_file(self.root / "private-index.json", evidence.empty_private_index())
        self.source = Path(self.temporary.name) / "selected.bin"
        self.source.write_bytes(b"selected test dialogue bytes\n")

    def tearDown(self):
        self.temporary.cleanup()

    def spec(self, source=None, kind="capture"):
        return {
            "format": "rehearsal-import/v1",
            "collected_utc": "2026-09-08T20:00:00Z",
            "items": [
                {
                    "source": str(source or self.source),
                    "source_identity": "private-session-fixture",
                    "classification": "private_capture",
                    "content_kind": kind,
                    "transformations": ["none"],
                    "qualification_refs": [],
                    "selection_scope": "test_dialogue",
                    "reviewed_safe": True,
                }
            ],
        }

    def test_import_is_0700_0600_hash_verified_and_public_projection_is_allowlisted(self):
        old_umask = os.umask(0)
        try:
            imported = evidence.import_evidence(self.root, self.spec())
        finally:
            os.umask(old_umask)
        self.assertEqual(len(imported), 1)
        reference = imported[0]["ref"]
        self.assertNotIn(str(self.source), json.dumps(imported))
        self.assertNotIn("private-session-fixture", json.dumps(imported))
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / "objects" / reference).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / "private-index.json").stat().st_mode), 0o600)
        report = evidence.verify_evidence(self.root, imported)
        self.assertEqual(report["public_inventory"], imported)

    def test_duplicate_source_symlink_relative_source_and_bad_scope_refuse(self):
        evidence.import_evidence(self.root, self.spec())
        with self.assertRaisesRegex(EvidenceError, "duplicate-import"):
            evidence.import_evidence(self.root, self.spec())
        symlink = Path(self.temporary.name) / "source-link"
        symlink.symlink_to(self.source)
        with self.assertRaisesRegex(EvidenceError, "regular-source-required"):
            evidence.import_evidence(self.root, self.spec(symlink))
        relative = self.spec()
        relative["items"][0]["source"] = "relative.json"
        with self.assertRaisesRegex(EvidenceError, "absolute-path-required"):
            evidence.validate_import_spec(relative)
        bad_scope = self.spec(Path(self.temporary.name) / "other")
        bad_scope["items"][0]["selection_scope"] = "recursive-home"
        with self.assertRaisesRegex(EvidenceError, "unapproved-selection-scope"):
            evidence.validate_import_spec(bad_scope)

    def test_tamper_missing_object_and_mode_change_refuse(self):
        imported = evidence.import_evidence(self.root, self.spec())
        object_path = self.root / "objects" / imported[0]["ref"]
        object_path.write_bytes(b"tampered")
        with self.assertRaises(EvidenceError):
            evidence.verify_evidence(self.root, imported)
        object_path.unlink()
        with self.assertRaises(EvidenceError):
            evidence.verify_evidence(self.root, imported)

        # A new root proves mode checks independently of the hash failure above.
        other = Path(self.temporary.name) / "mode-run"
        private_dir(other)
        private_dir(other / "objects")
        private_file(other / "private-index.json", evidence.empty_private_index())
        os.chmod(other, 0o755)
        with self.assertRaisesRegex(EvidenceError, "unsafe-directory-mode"):
            evidence.verify_evidence(other)

    def test_changed_source_snapshot_is_removed_before_publication(self):
        destination = self.root / "objects" / "ev-test"
        descriptor = os.open(str(self.source), os.O_RDONLY)
        real = os.fstat(descriptor)
        inconsistent = (real.st_dev, real.st_ino, real.st_size + 1, real.st_mtime_ns)
        with mock.patch.object(evidence, "_open_source", return_value=(descriptor, inconsistent)):
            with self.assertRaisesRegex(EvidenceError, "source-changed"):
                evidence._copy_source_to_object(self.source, destination, "source")
        self.assertFalse(destination.exists())

    def test_private_marker_detection_blocks_path_and_session_leak(self):
        imported = evidence.import_evidence(self.root, self.spec())
        index = evidence.load_private_index(self.root)
        evidence.assert_no_private_markers(b'{"ref":"%s"}' % imported[0]["ref"].encode(), index)
        with self.assertRaisesRegex(EvidenceError, "private-marker-in-public-export"):
            evidence.assert_no_private_markers(str(self.source).encode(), index)
        with self.assertRaisesRegex(EvidenceError, "private-marker-in-public-export"):
            evidence.assert_no_private_markers(b"private-session-fixture", index)

    def test_collector_import_validates_fixed_kind_before_copy(self):
        invalid = Path(self.temporary.name) / "collector.json"
        invalid.write_text('{"format":"collector-result/v2"}', encoding="utf-8")
        with self.assertRaises(EvidenceError):
            evidence.import_evidence(self.root, self.spec(invalid, "collector_result"))
        self.assertEqual(list((self.root / "objects").iterdir()), [])


class NoLiveSurfaceTests(unittest.TestCase):
    def test_module_has_no_network_process_or_runtime_imports(self):
        tree = ast.parse((Path(__file__).parent / "rehearsal_evidence.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(
            imported.isdisjoint({"socket", "subprocess", "urllib", "requests", "council"}),
            imported,
        )

    def test_fixture_validation_never_touches_network_process_or_home_discovery(self):
        result = literal_json("collector-result.fixture.json")
        qualification = literal_json("collector-qualification.fixture.json")
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network")), mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("process")
        ), mock.patch.object(Path, "home", side_effect=AssertionError("home")):
            decision = evidence.assess_arrival_count(
                result,
                qualification,
                context_kind="fixture",
                recovery_delivery_attempted=True,
                fresh_control_passed=True,
            )
        self.assertEqual(decision["result"], "pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
