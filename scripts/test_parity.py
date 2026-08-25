#!/usr/bin/env python3
"""Cross-representation parity tests (v0.19 verification floor).

Deliberately bounded scope: mechanical parity between machine-readable
representations (broker constants and contract builder, MCP tool schemas,
TypeScript tool definitions), plus inventory-level presence checks against
the prose docs. No semantic parsing of prose, no schema generation - work
that needs either belongs to the deferred consolidation effort, not here.
"""

import re
import unittest
from pathlib import Path

import council
import council_mcp

ROOT = Path(__file__).resolve().parent.parent
TS_TOOLS_SRC = (ROOT / "scripts" / "opencode_council_tools.ts").read_text()
TS_PLUGIN_SRC = (ROOT / "scripts" / "opencode_council_plugin.ts").read_text()
SKILL_SRC = (ROOT / "SKILL.md").read_text()
PROTOCOL_SRC = (ROOT / "references" / "protocol.md").read_text()
COUNCIL_SRC = (ROOT / "scripts" / "council.py").read_text()


def mcp_tool(name):
    for tool in council_mcp.TOOLS:
        if tool["name"] == name:
            return tool
    raise AssertionError("MCP tool not found: %s" % name)


def broker_request_kind_mapping():
    """Extract the request-kind -> submit-kind mapping from the broker's
    contract builder. Source-level extraction is intentional: the mapping is
    a literal inside response_contract_for, and this test exists to notice
    when any other representation drifts from it."""
    match = re.search(
        r"submit_kind = \{\s*(.*?)\}\.get\(request_kind\)", COUNCIL_SRC, re.S
    )
    assert match, "request-kind mapping not found in council.py"
    return re.findall(r'"([a-z_]+_request)":\s*"([a-z_]+)"', match.group(1))


class ToolNameParity(unittest.TestCase):
    # The wake router is a Codex-only mechanism: OpenCode delivery goes
    # through the plugin-owned session relay and never polls wakes, so its
    # native tools intentionally omit the router pair. Any OTHER divergence
    # between the two tool surfaces is drift and must fail here.
    CODEX_ROUTER_ONLY_TOOLS = {"council_pending_wakes", "council_wake_ack"}

    def test_mcp_and_typescript_expose_identical_tool_sets(self):
        mcp_names = [tool["name"] for tool in council_mcp.TOOLS]
        self.assertEqual(
            len(mcp_names), len(set(mcp_names)), "duplicate MCP tool names"
        )
        ts_names = re.findall(
            r'delegate\(\s*"(council_[a-z_]+)"', TS_TOOLS_SRC
        )
        self.assertEqual(
            len(ts_names), len(set(ts_names)), "duplicate TS tool names"
        )
        self.assertTrue(
            self.CODEX_ROUTER_ONLY_TOOLS <= set(mcp_names),
            "router tools missing from the MCP surface",
        )
        self.assertEqual(
            sorted(set(mcp_names) - self.CODEX_ROUTER_ONLY_TOOLS),
            sorted(ts_names),
        )

    def test_every_tool_name_appears_in_the_prose_docs(self):
        prose = SKILL_SRC + PROTOCOL_SRC
        missing = [
            tool["name"]
            for tool in council_mcp.TOOLS
            if tool["name"] not in prose
        ]
        self.assertEqual(missing, [])


class SubmitKindParity(unittest.TestCase):
    def broker_submit_kinds(self):
        return [kind for _, kind in broker_request_kind_mapping()]

    def test_request_kinds_follow_the_naming_invariant(self):
        for request_kind, kind in broker_request_kind_mapping():
            self.assertEqual(request_kind, kind + "_request")

    def test_mcp_submit_enum_matches_the_broker_mapping(self):
        schema = mcp_tool("council_submit")["inputSchema"]
        enum = schema["properties"]["kind"]["enum"]
        self.assertEqual(enum, self.broker_submit_kinds())

    def test_typescript_submit_enum_matches_the_broker_mapping(self):
        match = re.search(
            r'"council_submit".*?z\.enum\(\[(.*?)\]\)', TS_TOOLS_SRC, re.S
        )
        assert match, "council_submit z.enum not found in TS tools"
        ts_enum = re.findall(r'"([a-z_]+)"', match.group(1))
        self.assertEqual(ts_enum, self.broker_submit_kinds())

    def test_every_submit_kind_appears_in_the_protocol_reference(self):
        missing = [
            kind
            for kind in self.broker_submit_kinds()
            if kind not in PROTOCOL_SRC
        ]
        self.assertEqual(missing, [])


class EnumAndBoundParity(unittest.TestCase):
    def test_concession_bases_appear_in_the_protocol_reference(self):
        missing = [
            basis
            for basis in council.CONCESSION_BASES
            if basis not in PROTOCOL_SRC
        ]
        self.assertEqual(missing, [])

    def test_mcp_start_round_bounds_match_broker_constants(self):
        schema = mcp_tool("council_start")["inputSchema"]["properties"]
        for field in ("rounds", "max_rounds", "minimum_rounds"):
            self.assertEqual(schema[field]["minimum"], 1, field)
            self.assertEqual(
                schema[field]["maximum"], council.MAX_COUNCIL_ROUNDS, field
            )

    def test_mcp_submit_requires_the_contract_fields(self):
        schema = mcp_tool("council_submit")["inputSchema"]
        self.assertEqual(
            schema["required"],
            ["dialogue_id", "participant", "kind", "round_number", "payload"],
        )


class RelayEnvelopeParity(unittest.TestCase):
    """Both session relays must verify the exact envelope preamble and kind
    allow-list the broker emits. council.py is the source of truth; the
    OpenCode plugin carries TypeScript copies that these tests pin."""

    def ts_plugin_preamble(self):
        match = re.search(
            r"const ENVELOPE_PREAMBLE =\s*((?:\"[^\"]*\"\s*\+?\s*)+)",
            TS_PLUGIN_SRC,
        )
        assert match, "ENVELOPE_PREAMBLE not found in the OpenCode plugin"
        parts = re.findall(r'"([^"]*)"', match.group(1))
        return "".join(parts).replace("\\n", "\n")

    def test_plugin_preamble_matches_the_broker_preamble(self):
        self.assertEqual(self.ts_plugin_preamble(), council.ENVELOPE_PREAMBLE)

    def test_plugin_verifies_the_full_preamble(self):
        self.assertIn(
            "content.startsWith(ENVELOPE_PREAMBLE)",
            TS_PLUGIN_SRC,
            "the OpenCode relay must exact-match the preamble, not just line 1",
        )

    def test_plugin_kind_allow_list_matches_the_broker(self):
        match = re.search(
            r"const RELAY_ENVELOPE_KINDS = new Set\(\[(.*?)\]\)",
            TS_PLUGIN_SRC,
            re.S,
        )
        assert match, "RELAY_ENVELOPE_KINDS not found in the OpenCode plugin"
        ts_kinds = re.findall(r'"([a-z_]+)"', match.group(1))
        self.assertEqual(ts_kinds, list(council.RELAY_ENVELOPE_KINDS))

    def test_relay_kinds_cover_the_submit_mapping_and_terminals(self):
        request_kinds = {request for request, _ in broker_request_kind_mapping()}
        self.assertEqual(
            set(council.RELAY_ENVELOPE_KINDS),
            request_kinds | {"dialogue_complete", "cancelled"},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
