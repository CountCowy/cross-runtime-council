#!/usr/bin/env python3
"""Offline provenance fixtures; no live payload, host config or broker state."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from build_release import ROOT, RUNTIME_FILES, release, tracked_inputs


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="council-release-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        for name, data in tracked_inputs(ROOT).items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        subprocess.run(["git", "init", "-q"], cwd=self.source, check=True)
        subprocess.run(["git", "add", "."], cwd=self.source, check=True)

    def run_builder(self, *args, success=True):
        result = subprocess.run([sys.executable, "-B", str(self.source / "scripts/build_release.py"), *args],
                                cwd=self.source, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def test_repeat_output_and_final_hashes_include_real_external_layout(self):
        left, right = self.base / "left", self.base / "right"
        self.run_builder("--output", str(left))
        self.run_builder("--output", str(right))
        manifest = json.loads((left / "release_manifest.json").read_text())
        self.assertEqual((left / "release_manifest.json").read_bytes(), (right / "release_manifest.json").read_bytes())
        files = {str(path.relative_to(left)) for path in left.rglob("*") if path.is_file()}
        self.assertEqual(files, set(manifest["artifacts"]) | {"release_manifest.json"})
        for name, expected in manifest["artifacts"].items():
            self.assertEqual(hashlib.sha256((left / name).read_bytes()).hexdigest(), expected, name)
            self.assertEqual((left / name).read_bytes(), (right / name).read_bytes(), name)
        # Imports use the same paths from the documented copied-file layout.
        (left / "opencode/node_modules").symlink_to(ROOT / "node_modules", target_is_directory=True)
        script = ('import * as tools from "./tools/council.ts"; '
                  'await import("./council-plugin.ts"); '
                  'if (Object.keys(tools).length !== 11) throw new Error("tool inventory");')
        subprocess.run(["node", "--experimental-transform-types", "--input-type=module", "-e", script],
                       cwd=left / "opencode", check=True, capture_output=True)
        for name in ("council-plugin.ts", "opencode_delivery_registry.ts", "tools/council.ts"):
            path = left / "opencode" / name
            original = path.read_bytes()
            path.write_bytes(original.replace(manifest["runtime_cohort"].encode(), b"stale-component"))
            result = subprocess.run(["node", "--experimental-transform-types", "--input-type=module", "-e", script],
                                    cwd=left / "opencode", capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, name)
            self.assertIn("cohort mismatch", result.stderr, name)
            path.write_bytes(original)

    def test_documentation_and_tests_do_not_change_runtime_cohort(self):
        _, _, original = release(self.source)
        for name in ("README.md", "scripts/test_parity.py"):
            path = self.source / name
            path.write_bytes(path.read_bytes() + b"\n# fixture edit\n")
        _, _, changed = release(self.source)
        first, second = json.loads(original), json.loads(changed)
        self.assertNotEqual(first["package_id"], second["package_id"])
        self.assertEqual(first["runtime_cohort"], second["runtime_cohort"])

    def test_executed_source_changes_every_component_cohort(self):
        _, _, original = release(self.source)
        path = self.source / "scripts/council.py"
        path.write_bytes(path.read_bytes() + b"\n# runtime generation fixture\n")
        stamped, _, changed = release(self.source)
        first, second = json.loads(original), json.loads(changed)
        self.assertNotEqual(first["runtime_cohort"], second["runtime_cohort"])
        for name in RUNTIME_FILES:
            self.assertIn(('RUNTIME_COHORT = "' + second["runtime_cohort"] + '"').encode(), stamped[name])

    def test_loaded_identity_survives_source_replacement_and_mixed_python_helpers_refuse(self):
        old, _, original = release(self.source)
        entry = self.source / "scripts/council.py"
        entry.write_bytes(entry.read_bytes() + b"\n# next runtime fixture\n")
        new, _, changed = release(self.source)
        loaded_path = self.base / "loaded.py"
        loaded_path.write_bytes(old["scripts/council_protocol.py"])
        spec = importlib.util.spec_from_file_location("fixture_protocol", loaded_path)
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        loaded_path.write_bytes(new["scripts/council_protocol.py"])
        self.assertEqual(loaded.RUNTIME_COHORT, json.loads(original)["runtime_cohort"])
        self.assertNotEqual(loaded.RUNTIME_COHORT, json.loads(changed)["runtime_cohort"])
        for entry_set, helper_set in ((old, new), (new, old)):
            for component in ("council", "council_mcp", "council_opencode"):
                with self.subTest(component=component, direction=entry_set is old):
                    for name in RUNTIME_FILES:
                        (self.source / name).write_bytes(helper_set[name])
                    (self.source / ("scripts/" + component + ".py")).write_bytes(entry_set["scripts/" + component + ".py"])
                    result = subprocess.run([sys.executable, "-B", "-c", "import " + component],
                                            cwd=self.source / "scripts", capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("cohort mismatch", result.stderr)
        # A loaded entry cannot impersonate a new helper merely by sharing its path.
        with mock.patch.dict(sys.modules, {"council_protocol": loaded}):
            entry.write_bytes(new["scripts/council.py"])
            spec = importlib.util.spec_from_file_location("fixture_broker", entry)
            module = importlib.util.module_from_spec(spec)
            with self.assertRaisesRegex(RuntimeError, "cohort mismatch"):
                spec.loader.exec_module(module)

    def test_stale_definition_stamp_or_manifest_fails_readonly_check(self):
        self.run_builder("--write")
        self.run_builder("--check")
        path = self.source / "scripts/council_mcp.py"
        path.write_bytes(path.read_bytes() + b"\n# stale stamp fixture\n")
        before = {p: p.read_bytes() for p in self.source.rglob("*") if p.is_file() and ".git" not in p.parts}
        self.run_builder("--check", success=False)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        generated = self.source / "scripts/council_protocol.ts"
        generated.write_text(generated.read_text().replace('MAX_COUNCIL_ROUNDS = 100', 'MAX_COUNCIL_ROUNDS = 99'))
        result = self.run_builder("--write", success=False)
        self.assertIn("TypeScript protocol is stale", result.stderr)

    def test_unknown_files_ignored_and_missing_or_symlink_inputs_refuse(self):
        (self.source / "untracked-private.txt").write_text("must not be packaged")
        _, artifacts, _ = release(self.source)
        self.assertNotIn("payload/untracked-private.txt", artifacts)
        readme = self.source / "README.md"
        readme.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            release(self.source)
        readme.symlink_to(ROOT / "README.md")
        with self.assertRaisesRegex(ValueError, "escapes"):
            release(self.source)
        readme.unlink()
        shutil.copyfile(ROOT / "README.md", readme)
        subprocess.run(["git", "rm", "--cached", "-q", "scripts/council_mcp.py"], cwd=self.source, check=True)
        with self.assertRaisesRegex(ValueError, "not tracked"):
            release(self.source)

    def test_output_refuses_existing_directory_and_source_overlap(self):
        destination = self.base / "existing"
        destination.mkdir()
        marker = destination / "keep"
        marker.write_text("untouched")
        self.run_builder("--output", str(destination), success=False)
        self.assertEqual(marker.read_text(), "untouched")
        self.run_builder("--output", str(self.source / "output"), success=False)
        self.assertFalse((self.source / "output").exists())

    def test_write_refuses_manifest_symlinks_and_nonregular_targets_before_stamping(self):
        manifest = self.source / "release_manifest.json"
        outside = self.base / "preserve.txt"
        outside.write_bytes(b"independent file\n")
        manifest.symlink_to(outside)
        subprocess.run(["git", "add", "release_manifest.json"], cwd=self.source, check=True)
        before = {name: (self.source / name).read_bytes() for name in RUNTIME_FILES}

        result = self.run_builder("--write", success=False)
        self.assertIn("release manifest must be a regular file", result.stderr)
        self.assertTrue(manifest.is_symlink())
        self.assertEqual(outside.read_bytes(), b"independent file\n")
        self.assertEqual(before, {name: (self.source / name).read_bytes() for name in RUNTIME_FILES})

        manifest.unlink()
        manifest.mkdir()
        self.run_builder("--write", success=False)
        self.assertTrue(manifest.is_dir())
        self.assertEqual(before, {name: (self.source / name).read_bytes() for name in RUNTIME_FILES})


if __name__ == "__main__":
    unittest.main(verbosity=2)
