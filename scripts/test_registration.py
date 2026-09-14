#!/usr/bin/env python3
"""Independent passive-registration and byte-preservation fixtures."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import council_registration as registration
import council_registration_qualification as qualification
from council_registration import (
    CLAUDE_PROJECT,
    CLAUDE_USER,
    CODEX_USER,
    OPENCODE_ENSURE,
    OPENCODE_GLOBAL,
    OPENCODE_REMOVE,
    ArtifactReceiptBinding,
    ConfigDocument,
    OwnershipEvidence,
    RegistrationInputError,
    StdioSpec,
    build_native_plan_core,
    canonical_native_execution_bytes,
    canonical_native_plan_core_bytes,
    compare_candidate,
    finalize_native_execution,
    observe_claude_config,
    observe_codex_config,
    observe_opencode_config,
    plan_opencode_candidate,
    render_plan_summary,
)


FIXTURES = Path(__file__).parent / "fixtures" / "registration"
OPENCODE_PATH = "/synthetic/config/opencode/opencode.json"
CLAUDE_PATH = "/synthetic/config/claude.json"
CODEX_PATH = "/synthetic/config/codex/config.toml"


class PublicDigestRecord:
    def __init__(self, kind, value):
        self.value = {"kind": kind, "value": value}

    def public_dict(self):
        return dict(self.value)

    def digest(self):
        return hashlib.sha256(
            json.dumps(
                self.value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.spec = StdioSpec(
            "/usr/bin/python3", "/opt/council/scripts/council_mcp.py"
        )

    def opencode(self, content, path=OPENCODE_PATH):
        return ConfigDocument(path, OPENCODE_GLOBAL, content)

    def claude(self, content, scope=CLAUDE_USER, path=CLAUDE_PATH):
        return ConfigDocument(path, scope, content)

    def codex(self, content):
        return ConfigDocument(CODEX_PATH, CODEX_USER, content)

    def opencode_claim(self, document, origin="created"):
        observation = observe_opencode_config(
            document, source_inputs_complete=True
        )
        self.assertEqual(observation.state, "matching")
        return OwnershipEvidence(
            "opencode", document.path, observation.entry_sha256, origin
        )

    def test_inputs_are_explicit_absolute_and_bounded(self):
        with self.assertRaisesRegex(RegistrationInputError, "absolute"):
            ConfigDocument("relative.json", OPENCODE_GLOBAL, b"{}")
        with self.assertRaisesRegex(RegistrationInputError, "bytes"):
            ConfigDocument(OPENCODE_PATH, OPENCODE_GLOBAL, "{}")
        with self.assertRaisesRegex(RegistrationInputError, "absolute"):
            StdioSpec("python3", self.spec.adapter_path)
        with self.assertRaisesRegex(RegistrationInputError, "council_mcp.py"):
            StdioSpec("/usr/bin/python3", "/opt/council/scripts/other.py")
        with self.assertRaisesRegex(RegistrationInputError, "normalized"):
            StdioSpec(
                "/usr/bin/python3", "/opt/council/other/../scripts/council_mcp.py"
            )
        huge = self.opencode(b" " * (registration.MAX_CONFIG_BYTES + 1))
        with self.assertRaisesRegex(RegistrationInputError, "byte limit"):
            observe_opencode_config(huge)

    def test_native_v3_plan_core_and_final_execution_are_authority_free(self):
        observation = observe_claude_config(
            self.claude(b'{"mcpServers":{}}'),
            self.spec,
            scope_inputs_complete=True,
        )
        receipt = ArtifactReceiptBinding(
            "receipt-native-v3",
            "1" * 64,
            "2" * 64,
            "3" * 64,
        )
        other_records = [
            PublicDigestRecord(name, str(index))
            for index, name in enumerate(
                (
                    "implementation",
                    "support",
                    "admission",
                    "runtime-tuple",
                )
            )
        ]
        core = build_native_plan_core(
            receipt,
            "claude-council",
            registration.CLAUDE_ENSURE,
            observation,
            self.spec,
            other_records[0],
            qualification.validate_native_shape_policy(
                (FIXTURES / "native-v3-shape-policy.json").read_bytes()
            ),
            *other_records[1:],
        )
        core_bytes = canonical_native_plan_core_bytes(core)
        self.assertFalse(core["executable"])
        self.assertFalse(core["native_success_activated"])
        self.assertNotIn("quiescent_decision", core)
        self.assertNotIn("apply_authorized", core_bytes.decode())
        binding = PublicDigestRecord("attempt-binding", "bound")
        family = PublicDigestRecord("attempt-family", "stable")
        identity = PublicDigestRecord("semantic-result", "target")
        execution_admission = PublicDigestRecord("execution-admission", "current")
        execution = finalize_native_execution(
            core, family, binding, identity, execution_admission
        )
        self.assertEqual(
            canonical_native_execution_bytes(execution),
            (
                json.dumps(execution, indent=2, sort_keys=True) + "\n"
            ).encode(),
        )
        self.assertFalse(execution["native_success_activated"])

        promoted = json.loads(core_bytes)
        promoted["native_success_activated"] = True
        with self.assertRaisesRegex(RegistrationInputError, "invalid"):
            canonical_native_plan_core_bytes(promoted)
        changed = dict(execution)
        changed["attempt_binding"] = dict(execution["attempt_binding"])
        changed["attempt_binding"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(RegistrationInputError, "digest differs"):
            canonical_native_execution_bytes(changed)

    def test_opencode_ensure_preserves_every_unrelated_byte(self):
        before = (FIXTURES / "opencode-preserve.json").read_bytes()
        document = self.opencode(before)
        result = plan_opencode_candidate(
            OPENCODE_ENSURE, document, source_inputs_complete=True
        )
        self.assertTrue(result.changed)
        self.assertEqual(result.entry_disposition, "created")
        self.assertEqual(result.patch.candidate(before), result.candidate_bytes)
        prefix = b'    ["file:///tmp/unrelated-plugin.ts", {"z": 1e+09, "a": [true, null]}]'
        self.assertIn(prefix + b',"./council-plugin.ts"', result.candidate_bytes)
        self.assertIn(b"6.022000e+023", result.candidate_bytes)
        self.assertIn(b"SYNTHETIC_REGISTRATION_SECRET_7f1139", result.candidate_bytes)
        self.assertEqual(
            result.candidate_bytes[: result.patch.start], before[: result.patch.start]
        )
        self.assertEqual(
            result.candidate_bytes[result.patch.start + len(result.patch.replacement) :],
            before[result.patch.end :],
        )
        parsed = observe_opencode_config(
            self.opencode(result.candidate_bytes), source_inputs_complete=True
        )
        self.assertEqual(parsed.state, "matching")

    def test_huge_valid_number_is_preserved_without_integer_conversion(self):
        number = b"9" * 10000
        before = b'{"huge":' + number + b',"plugin":[]}'
        result = plan_opencode_candidate(
            OPENCODE_ENSURE,
            self.opencode(before),
            source_inputs_complete=True,
        )
        self.assertTrue(result.changed)
        self.assertIn(number, result.candidate_bytes)
        self.assertEqual(
            result.candidate_bytes,
            b'{"huge":' + number + b',"plugin":["./council-plugin.ts"]}',
        )

    def test_missing_plugin_key_is_inserted_without_reformatting(self):
        before = b'{\n "n": 1e+000,\n "tail": ["x", 2]\n}\n'
        result = plan_opencode_candidate(
            OPENCODE_ENSURE,
            self.opencode(before),
            source_inputs_complete=True,
        )
        self.assertEqual(
            result.candidate_bytes,
            b'{\n "n": 1e+000,\n "tail": ["x", 2],"plugin":["./council-plugin.ts"]\n}\n',
        )

    def test_empty_object_and_whitespace_array_remain_strict_json(self):
        empty = plan_opencode_candidate(
            OPENCODE_ENSURE, self.opencode(b"{  }"), source_inputs_complete=True
        )
        self.assertEqual(empty.candidate_bytes, b'{"plugin":["./council-plugin.ts"]  }')
        spaced = plan_opencode_candidate(
            OPENCODE_ENSURE,
            self.opencode(b'{"plugin":[ \n ]}'),
            source_inputs_complete=True,
        )
        self.assertEqual(spaced.candidate_bytes, b'{"plugin":["./council-plugin.ts" \n ]}')
        self.assertEqual(
            observe_opencode_config(
                self.opencode(spaced.candidate_bytes), source_inputs_complete=True
            ).state,
            "matching",
        )

    def test_owned_remove_preserves_unrelated_members_and_options_tuple(self):
        original = (FIXTURES / "opencode-preserve.json").read_bytes()
        ensured = plan_opencode_candidate(
            OPENCODE_ENSURE,
            self.opencode(original),
            source_inputs_complete=True,
        ).candidate_bytes
        document = self.opencode(ensured)
        claim = self.opencode_claim(document)
        result = plan_opencode_candidate(
            OPENCODE_REMOVE,
            document,
            claim,
            source_inputs_complete=True,
        )
        self.assertEqual(result.candidate_bytes, original)
        self.assertEqual(result.entry_disposition, "already_owned")

    def test_later_unrelated_edits_do_not_invalidate_entry_ownership(self):
        first = self.opencode(
            b'{"setting":1,"plugin":["./council-plugin.ts","npm:x"]}'
        )
        claim = self.opencode_claim(first)
        later = self.opencode(
            b'{"setting":2000e-3,"new":"value","plugin":["./council-plugin.ts","npm:x"]}'
        )
        result = plan_opencode_candidate(
            OPENCODE_REMOVE, later, claim, source_inputs_complete=True
        )
        self.assertEqual(
            result.candidate_bytes,
            b'{"setting":2000e-3,"new":"value","plugin":["npm:x"]}',
        )

    def test_matching_preexisting_entry_is_never_adopted_or_removed(self):
        document = self.opencode(b'{"plugin":["./council-plugin.ts"]}')
        observation = observe_opencode_config(
            document, source_inputs_complete=True
        )
        self.assertEqual(
            observation.entry_disposition, "matching_preexisting_unowned"
        )
        ensure = plan_opencode_candidate(
            OPENCODE_ENSURE, document, source_inputs_complete=True
        )
        remove = plan_opencode_candidate(
            OPENCODE_REMOVE, document, source_inputs_complete=True
        )
        self.assertEqual(ensure.reason, "matching_preexisting_unowned")
        self.assertEqual(remove.reason, "matching_preexisting_unowned_preserved")
        self.assertFalse(ensure.changed)
        self.assertFalse(remove.changed)

    def test_explicit_adoption_remains_distinct(self):
        document = self.opencode(b'{"plugin":["./council-plugin.ts"]}')
        claim = self.opencode_claim(document, "adopted_by_explicit_plan")
        observation = observe_opencode_config(
            document, claim, source_inputs_complete=True
        )
        self.assertEqual(
            observation.entry_disposition, "adopted_by_explicit_plan"
        )
        removed = plan_opencode_candidate(
            OPENCODE_REMOVE, document, claim, source_inputs_complete=True
        )
        self.assertEqual(removed.candidate_bytes, b'{"plugin":[]}')

    def test_changed_owned_entry_refuses_removal(self):
        original = self.opencode(b'{"plugin":["./council-plugin.ts"]}')
        claim = self.opencode_claim(original)
        changed = self.opencode(b'{"plugin":[".\\/council-plugin.ts"]}')
        result = plan_opencode_candidate(
            OPENCODE_REMOVE, changed, claim, source_inputs_complete=True
        )
        self.assertEqual(result.outcome, "refused")
        self.assertEqual(result.reason, "ownership_mismatch")

    def test_wrong_ownership_refuses_ensure_without_reclassifying_equality(self):
        document = self.opencode(b'{"plugin":["./council-plugin.ts"]}')
        wrong = OwnershipEvidence(
            "opencode", document.path, "0" * 64, "created"
        )
        result = plan_opencode_candidate(
            OPENCODE_ENSURE, document, wrong, source_inputs_complete=True
        )
        self.assertEqual((result.outcome, result.reason), ("refused", "ownership_mismatch"))
        self.assertFalse(result.changed)

    def test_missing_owned_entry_refuses_and_unowned_absence_is_noop(self):
        present = self.opencode(b'{"plugin":["./council-plugin.ts"]}')
        claim = self.opencode_claim(present)
        absent = self.opencode(b'{"plugin":[]}')
        owned = plan_opencode_candidate(
            OPENCODE_REMOVE, absent, claim, source_inputs_complete=True
        )
        unowned = plan_opencode_candidate(
            OPENCODE_REMOVE, absent, source_inputs_complete=True
        )
        self.assertEqual((owned.outcome, owned.reason), ("refused", "missing_owned_entry"))
        self.assertEqual((unowned.outcome, unowned.reason), ("unchanged", "already_absent"))

    def test_duplicate_alias_and_options_council_identities_refuse(self):
        documents = (
            b'{"plugin":["./council-plugin.ts","./council-plugin.ts"]}',
            b'{"plugin":["/other/council-plugin.ts"]}',
            b'{"plugin":[["./council-plugin.ts", {"disabled":false}]]}',
            b'{"plugin":["./x/../council-plugin.ts"]}',
        )
        for raw in documents:
            with self.subTest(raw=raw):
                observation = observe_opencode_config(
                    self.opencode(raw), source_inputs_complete=True
                )
                self.assertEqual(observation.state, "ambiguous_identity")
                result = plan_opencode_candidate(
                    OPENCODE_ENSURE,
                    self.opencode(raw),
                    source_inputs_complete=True,
                )
                self.assertEqual(result.outcome, "refused")

    def test_unrelated_options_tuple_is_preserved(self):
        before = b'{"plugin":[["npm:x",{"b":2,"a":1}],"npm:y"]}'
        result = plan_opencode_candidate(
            OPENCODE_ENSURE, self.opencode(before), source_inputs_complete=True
        )
        self.assertIn(b'[["npm:x",{"b":2,"a":1}],"npm:y"', result.candidate_bytes)

    def test_duplicate_and_escaped_duplicate_keys_refuse(self):
        for raw in (
            b'{"plugin":[],"plugin":[]}',
            b'{"plugin":[],"pl\\u0075gin":[]}',
            b'{"x":{"key":1,"k\\u0065y":2},"plugin":[]}',
        ):
            with self.subTest(raw=raw):
                observation = observe_opencode_config(
                    self.opencode(raw), source_inputs_complete=True
                )
                self.assertEqual(observation.state, "malformed")
                self.assertEqual(observation.reason, "duplicate_json_key")

    def test_jsonc_trailing_commas_nonfinite_and_plural_key_refuse(self):
        cases = (
            (b'{// comment\n"plugin":[]}', "strict_json_required"),
            (b'{"plugin":[],}', "strict_json_required"),
            (b'{"number":NaN,"plugin":[]}', "strict_json_required"),
            (b'{"number":Infinity,"plugin":[]}', "strict_json_required"),
            (b'{"plugins":[]}', "unsupported_plural_plugin"),
        )
        for raw, reason in cases:
            with self.subTest(reason=reason):
                observation = observe_opencode_config(
                    self.opencode(raw), source_inputs_complete=True
                )
                self.assertFalse(observation.automatic_eligible)
                self.assertEqual(observation.reason, reason)

    def test_json_depth_and_node_bounds_fail_closed(self):
        deep = b"[" * 66 + b"]" * 66
        depth = observe_opencode_config(
            self.opencode(deep), source_inputs_complete=True
        )
        many = (
            b'{"items":['
            + b",".join([b"null"] * (registration.MAX_JSON_NODES + 1))
            + b'],"plugin":[]}'
        )
        nodes = observe_opencode_config(
            self.opencode(many), source_inputs_complete=True
        )
        self.assertEqual(depth.reason, "json_depth_exceeded")
        self.assertEqual(nodes.reason, "json_node_limit_exceeded")

    def test_unsupported_plugin_member_and_schema_refuse(self):
        for raw in (
            b'{"plugin":"./council-plugin.ts"}',
            b'{"plugin":[42]}',
            b'{"plugin":[["npm:x"]]}',
            b'[]',
        ):
            with self.subTest(raw=raw):
                result = plan_opencode_candidate(
                    OPENCODE_ENSURE,
                    self.opencode(raw),
                    source_inputs_complete=True,
                )
                self.assertEqual(result.outcome, "refused")

    def test_ambiguous_or_incomplete_opencode_sources_refuse(self):
        selected = self.opencode(b'{"plugin":[]}')
        other = self.opencode(b"{}", "/synthetic/config/opencode/opencode.jsonc")
        incomplete = plan_opencode_candidate(OPENCODE_ENSURE, selected)
        multiple = plan_opencode_candidate(
            OPENCODE_ENSURE,
            selected,
            competing_documents=(other,),
            source_inputs_complete=True,
        )
        self.assertEqual(incomplete.reason, "scope_ambiguous")
        self.assertEqual(multiple.reason, "scope_ambiguous")
        self.assertFalse(incomplete.changed)
        self.assertFalse(multiple.changed)

    def test_claude_exact_entry_keeps_equality_and_ownership_distinct(self):
        document = self.claude((FIXTURES / "claude-user.json").read_bytes())
        unowned = observe_claude_config(
            document, self.spec, scope_inputs_complete=True
        )
        self.assertEqual(unowned.state, "matching")
        self.assertEqual(
            unowned.entry_disposition, "matching_preexisting_unowned"
        )
        claim = OwnershipEvidence(
            "claude", document.path, unowned.entry_sha256, "created"
        )
        owned = observe_claude_config(
            document, self.spec, claim, scope_inputs_complete=True
        )
        self.assertEqual(owned.entry_disposition, "already_owned")
        self.assertEqual(owned.unrelated_entry_count, 1)
        self.assertEqual(len(owned.complement_sha256), 64)
        self.assertEqual(owned.effective_scope, "unobserved")
        self.assertNotIn(
            "fixture-only", json.dumps(owned.public_dict())
        )

    def test_claude_unknown_disabled_and_changed_fields_are_local_changes(self):
        templates = (
            (b'"env":{"TOKEN":"SYNTHETIC_FIELD_SECRET"}', "unknown_fields", ("env",)),
            (b'"disabled":true', "disabled", ("disabled",)),
        )
        for extra, state, fields in templates:
            raw = (
                b'{"mcpServers":{"council":{"type":"stdio","command":"/usr/bin/python3",'
                b'"args":["/opt/council/scripts/council_mcp.py"],'
                + extra
                + b'}}}'
            )
            with self.subTest(state=state):
                observation = observe_claude_config(
                    self.claude(raw), self.spec, scope_inputs_complete=True
                )
                self.assertEqual(observation.state, state)
                self.assertEqual(observation.unknown_fields, fields)
                self.assertFalse(observation.automatic_eligible)
                self.assertNotIn(
                    "SYNTHETIC_FIELD_SECRET", json.dumps(observation.public_dict())
                )

    def test_arbitrary_unknown_field_name_is_hashed_in_public_report(self):
        raw = (
            b'{"mcpServers":{"council":{"type":"stdio","command":"/usr/bin/python3",'
            b'"args":["/opt/council/scripts/council_mcp.py"],'
            b'"SYNTHETIC_SECRET_FIELD_NAME":true}}}'
        )
        observation = observe_claude_config(
            self.claude(raw), self.spec, scope_inputs_complete=True
        )
        self.assertEqual(observation.state, "unknown_fields")
        public = json.dumps(observation.public_dict())
        self.assertNotIn("SYNTHETIC_SECRET_FIELD_NAME", public)
        self.assertRegex(observation.unknown_fields[0], r"^other:[0-9a-f]{12}$")

    def test_changed_supported_fields_are_customized(self):
        raw = (
            b'{"mcpServers":{"council":{"type":"stdio","command":"/bin/other",'
            b'"args":["/opt/council/scripts/council_mcp.py"]}}}'
        )
        observation = observe_claude_config(
            self.claude(raw), self.spec, scope_inputs_complete=True
        )
        self.assertEqual(observation.state, "customized")

    def test_claude_missing_required_raw_field_is_not_matching(self):
        raw = (
            b'{"mcpServers":{"council":{"command":"/usr/bin/python3",'
            b'"args":["/opt/council/scripts/council_mcp.py"]}}}'
        )
        observation = observe_claude_config(
            self.claude(raw), self.spec, scope_inputs_complete=True
        )
        self.assertEqual(observation.state, "unsupported")

    def test_claude_duplicate_escaped_key_and_alias_server_refuse(self):
        duplicates = b'{"mcpServers":{},"mcp\\u0053ervers":{}}'
        duplicate = observe_claude_config(
            self.claude(duplicates), self.spec, scope_inputs_complete=True
        )
        self.assertEqual(duplicate.state, "duplicate_json_key")
        entry = (
            b'{"type":"stdio","command":"/usr/bin/python3",'
            b'"args":["/opt/council/scripts/council_mcp.py"]}'
        )
        alias = self.claude(
            b'{"mcpServers":{"other-name":' + entry + b'}}'
        )
        observation = observe_claude_config(
            alias, self.spec, scope_inputs_complete=True
        )
        self.assertEqual(observation.state, "ambiguous_identity")

    def test_claude_project_and_local_scope_ambiguity_is_explicit(self):
        user_raw = (FIXTURES / "claude-user.json").read_bytes()
        project = self.claude(
            b'{"mcpServers":{"council":{"type":"stdio"}}}',
            CLAUDE_PROJECT,
            "/synthetic/project/.mcp.json",
        )
        local_entry = (
            b'{"mcpServers":{"council":{"type":"stdio"}}}'
        )
        user_with_local = self.claude(
            user_raw[:-2]
            + b',"projects":{"/synthetic/project":'
            + local_entry
            + b'}}\n'
        )
        project_observation = observe_claude_config(
            self.claude(user_raw),
            self.spec,
            project_documents=(project,),
            scope_inputs_complete=True,
        )
        local_observation = observe_claude_config(
            user_with_local,
            self.spec,
            current_project_key="/synthetic/project",
            scope_inputs_complete=True,
        )
        incomplete = observe_claude_config(self.claude(user_raw), self.spec)
        for observation in (project_observation, local_observation, incomplete):
            self.assertEqual(observation.reason, "scope_ambiguous")
            self.assertFalse(observation.automatic_eligible)

    def test_codex_parser_capability_is_current_interpreter_only(self):
        document = self.codex((FIXTURES / "codex-user.toml").read_bytes())
        observation = observe_codex_config(
            document, self.spec, layer_inputs_complete=True
        )
        if registration._tomllib is None:
            self.assertEqual(observation.state, "parser_unavailable")
            self.assertEqual(
                observation.parser_capability,
                "parser_unavailable:stdlib_tomllib",
            )
        else:
            self.assertEqual(observation.state, "matching")
            self.assertTrue(
                observation.parser_capability.endswith(":" + os.sys.executable)
            )
        self.assertFalse(observation.automatic_eligible)

    def test_codex_explicit_parser_unavailable_fallback(self):
        document = self.codex(b'[mcp_servers.council]\ncommand="secret"\n')
        with mock.patch.object(registration, "_tomllib", None):
            observation = observe_codex_config(
                document, self.spec, layer_inputs_complete=True
            )
        self.assertEqual(observation.state, "parser_unavailable")
        self.assertIsNone(observation.entry_sha256)
        self.assertNotIn("secret", json.dumps(observation.public_dict()))

    @unittest.skipIf(registration._tomllib is None, "stdlib tomllib requires Python 3.11+")
    def test_codex_unknown_fields_and_aliases_refuse_when_parser_available(self):
        unknown = self.codex(
            b'[mcp_servers.council]\ncommand="/usr/bin/python3"\n'
            b'args=["/opt/council/scripts/council_mcp.py"]\nenabled=false\n'
        )
        alias = self.codex(
            b'[mcp_servers.alias]\ncommand="/usr/bin/python3"\n'
            b'args=["/opt/council/scripts/council_mcp.py"]\n'
        )
        first = observe_codex_config(
            unknown, self.spec, layer_inputs_complete=True
        )
        second = observe_codex_config(
            alias, self.spec, layer_inputs_complete=True
        )
        self.assertEqual(first.state, "disabled")
        self.assertEqual(first.unknown_fields, ("enabled",))
        self.assertEqual(second.state, "ambiguous_identity")
        self.assertFalse(first.automatic_eligible)
        self.assertFalse(second.automatic_eligible)

    def test_redacted_reports_never_include_unrelated_secret_sentinels(self):
        before = (FIXTURES / "opencode-preserve.json").read_bytes()
        result = plan_opencode_candidate(
            OPENCODE_ENSURE,
            self.opencode(before),
            source_inputs_complete=True,
        )
        public = json.dumps(result.public_dict(), sort_keys=True)
        self.assertNotIn("SYNTHETIC_REGISTRATION_SECRET_7f1139", public)
        self.assertNotIn("npm:unrelated", public)
        self.assertNotIn("6.022", public)
        self.assertIn("<council-plugin-entry>", public)
        self.assertIn("file:///tmp/unrelated-plugin.ts", result.private_unified_diff(before))
        observation = observe_opencode_config(
            self.opencode(before), source_inputs_complete=True
        )
        summary = render_plan_summary(OPENCODE_ENSURE, observation, result)
        summary_text = json.dumps(summary, sort_keys=True)
        self.assertNotIn("SYNTHETIC_REGISTRATION_SECRET_7f1139", summary_text)
        self.assertIsNone(summary["native_argv"])
        self.assertFalse(summary["native_qualified"])
        self.assertFalse(summary["apply_authorized"])

    def test_explicit_candidate_comparison_keeps_exact_diff_local(self):
        before = self.opencode(b'{"secret":"SYNTHETIC_COMPARE_SECRET","plugin":[]}\n')
        after = b'{"secret":"SYNTHETIC_COMPARE_SECRET","plugin":["./council-plugin.ts"]}\n'
        comparison = compare_candidate(before, after)
        self.assertIn("SYNTHETIC_COMPARE_SECRET", comparison.exact_diff)
        self.assertNotIn(
            "SYNTHETIC_COMPARE_SECRET", json.dumps(comparison.public_dict())
        )

    def test_passive_apis_do_not_open_write_or_spawn(self):
        document = self.opencode(b'{"plugin":[]}')
        with tempfile.TemporaryDirectory(prefix="registration-passive-") as temp:
            before = sorted(Path(temp).rglob("*"))
            with mock.patch("builtins.open", side_effect=AssertionError("open")), mock.patch.object(
                subprocess, "run", side_effect=AssertionError("spawn")
            ), mock.patch.object(
                subprocess, "Popen", side_effect=AssertionError("spawn")
            ):
                observation = observe_opencode_config(
                    document, source_inputs_complete=True
                )
                candidate = plan_opencode_candidate(
                    OPENCODE_ENSURE, document, source_inputs_complete=True
                )
                compare_candidate(document, candidate.candidate_bytes)
            self.assertEqual(observation.state, "absent")
            self.assertEqual(before, sorted(Path(temp).rglob("*")))


if __name__ == "__main__":
    unittest.main()
