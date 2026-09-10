#!/usr/bin/env python3
"""Offline provenance fixtures; no live payload, host config or broker state."""

import hashlib
import importlib.util
import io
import itertools
import json
import os
import py_compile
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from build_release import ROOT, RUNTIME_FILES, main as build_main, release, tracked_inputs


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

    def test_runtime_entrypoints_suppress_custom_bytecode_writes_at_every_optimization(self):
        self.run_builder("--write")
        prefix = self.base / "entrypoint-cache"
        env = dict(os.environ, PYTHONPYCACHEPREFIX=str(prefix), COUNCIL_STATE_ROOT=str(self.base / "absent-state"))
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        env.pop("PYTHONOPTIMIZE", None)
        runtime_stems = {Path(name).stem for name in RUNTIME_FILES if name.endswith(".py")}
        def own_caches():
            return {str(path): path.read_bytes() for base in (prefix, self.source / "scripts")
                    if base.exists() for path in base.rglob("*.pyc")
                    if any(path.name.startswith(stem + ".") for stem in runtime_stems)}
        for optimization in ([], ["-O"], ["-OO"]):
            for component, arguments, payload in (
                ("council.py", ["--help"], ""),
                ("council_mcp.py", [], ""),
                ("council_opencode.py", [], '{"action":"ping","runtime_cohort":"stale"}\n'),
                ("council_inspect.py", ["--state-root", str(self.base / "absent-state"), "--payload-root", str(self.source), "--opencode-root", str(self.base / "fixture-opencode")], ""),
            ):
                with self.subTest(component=component, optimization=optimization):
                    before = own_caches()
                    command = [sys.executable, *optimization, str(self.source / "scripts" / component), *arguments]
                    if component == "council_inspect.py":
                        # This subprocess-only hook makes a missing root argument
                        # fail before any live-home file open. The canary proves
                        # the hook runs even when the live installation is absent.
                        program = "\n".join([
                            "import os,runpy,sys",
                            "live_home = " + repr(str(Path.home().resolve())),
                            "fixture = " + repr(str(self.base.resolve())),
                            "stdlib = os.path.dirname(os.__file__)",
                            "def within(path, root): return path == root or path.startswith(root + os.sep)",
                            "def audit(event, args):",
                            "    if event == 'open' and not isinstance(args[0], int):",
                            "        path = os.path.abspath(os.fsdecode(args[0]))",
                            "        if within(path, live_home) and not within(path, fixture) and not within(path, stdlib):",
                            "            raise RuntimeError('fixture isolation: live-home read blocked')",
                            "sys.addaudithook(audit)",
                            "try:",
                            "    open(os.path.join(live_home, '.council-forbidden-fixture-read'), 'rb')",
                            "except RuntimeError as error:",
                            "    assert str(error) == 'fixture isolation: live-home read blocked'",
                            "else: raise AssertionError('isolation canary was not blocked')",
                            "print('guard_canary_passed')",
                            "sys.path.insert(0, " + repr(str(self.source / "scripts")) + ")",
                            "sys.argv = " + repr([str(self.source / "scripts" / component), *arguments]),
                            "runpy.run_path(sys.argv[0], run_name='__main__')",
                        ])
                        command = [sys.executable, *optimization, "-c", program]
                    result = subprocess.run(command, input=payload, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2 if component == "council_opencode.py" else 0, result.stderr)
                    if component == "council_inspect.py":
                        self.assertIn("guard_canary_passed", result.stdout)
                    self.assertEqual(own_caches(), before)
        self.assertFalse((self.base / "absent-state").exists())

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
            for component in ("council", "council_mcp", "council_opencode", "council_inspect"):
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

    def test_output_validates_current_canonical_bytes_despite_cached_definitions(self):
        source = self.source.resolve()
        protocol = source / "scripts/council_protocol.py"
        original = protocol.read_bytes()
        changed = original.replace(b"DEFAULT_ROUNDS = 2\n", b"DEFAULT_ROUNDS = 3\n")
        self.assertNotEqual(original, changed)
        self.assertEqual(len(original), len(changed))
        timestamp = 1_700_000_000
        os.utime(protocol, (timestamp, timestamp))
        prefix = str(self.base.resolve() / "definition-cache")
        with mock.patch.object(sys, "pycache_prefix", prefix):
            cache = Path(py_compile.compile(str(protocol), doraise=True, optimize=0,
                                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
        self.assertEqual(int.from_bytes(cache.read_bytes()[4:8], "little"), 0)
        protocol.write_bytes(changed)
        os.utime(protocol, (timestamp, timestamp))
        env = dict(os.environ, PYTHONPYCACHEPREFIX=prefix)
        env.pop("PYTHONOPTIMIZE", None)

        def run(*args):
            return subprocess.run([sys.executable, "-B", *args], cwd=source,
                                  env=env, capture_output=True, text=True)

        cached = run("-c", "import sys; sys.path.insert(0, 'scripts'); "
                     "import council_protocol; print(council_protocol.DEFAULT_ROUNDS)")
        self.assertEqual(cached.returncode, 0, cached.stderr)
        self.assertEqual(cached.stdout.strip(), "2")
        checked = run("scripts/generate_protocol.py", "--check")
        self.assertNotEqual(checked.returncode, 0)
        self.assertIn("TypeScript protocol is stale", checked.stderr)
        output = self.base / "canonical-output"
        rejected = run("scripts/build_release.py", "--output", str(output))
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("TypeScript protocol is stale", rejected.stderr)
        self.assertFalse(output.exists())
        generated = run("scripts/generate_protocol.py")
        self.assertEqual(generated.returncode, 0, generated.stderr)
        exported = run("scripts/build_release.py", "--output", str(output))
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertIn(b"DEFAULT_ROUNDS = 3\n", (output / "payload/scripts/council_protocol.py").read_bytes())
        self.assertIn("export const DEFAULT_ROUNDS = 3\n", (output / "opencode/council_protocol.ts").read_text())

    def test_stamping_invalidates_same_second_runtime_bytecode(self):
        source = self.source.resolve()
        python_sources = [source / name for name in RUNTIME_FILES if name.endswith(".py")]
        timestamp = 1_700_000_000
        write_bytes = Path.write_bytes

        def same_second_write(path, data):
            result = write_bytes(path, data)
            if path in python_sources:
                os.utime(path, (timestamp, timestamp))
            return result

        modes = (py_compile.PycInvalidationMode.TIMESTAMP, py_compile.PycInvalidationMode.CHECKED_HASH)
        prefixes = (None, str(self.base.resolve() / "python-cache"))
        for prefix, mode in itertools.product(prefixes, modes):
            with self.subTest(cache_prefix=prefix, mode=mode), mock.patch.object(sys, "pycache_prefix", prefix):
                broker = source / "scripts/council.py"
                broker.write_bytes(broker.read_bytes() + b"\n# runtime generation fixture\n")
                for path in python_sources:
                    os.utime(path, (timestamp, timestamp))
                    for optimization in (0, 1, 2):
                        cache = Path(py_compile.compile(str(path), doraise=True, optimize=optimization,
                                                        invalidation_mode=mode))
                        self.assertEqual(int.from_bytes(cache.read_bytes()[4:8], "little"),
                                         0 if mode == py_compile.PycInvalidationMode.TIMESTAMP else 3)
                sizes = {path: path.stat().st_size for path in python_sources}
                env = dict(os.environ)
                env.pop("PYTHONOPTIMIZE", None)
                script = ("import json, sys; sys.pycache_prefix = " + repr(prefix) + "; "
                          "import council_protocol, council_admission, council, council_mcp, council_opencode, council_inspect; "
                          "print(json.dumps({m.__name__: m.RUNTIME_COHORT for m in "
                          "(council_protocol, council_admission, council, council_mcp, council_opencode, council_inspect)}))")

                def loaded_cohorts(optimization):
                    result = subprocess.run([sys.executable, "-B", *optimization, "-c", script],
                                            cwd=source / "scripts", env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    return json.loads(result.stdout)

                expected_cohort = json.loads(release(source)[2])["runtime_cohort"]
                expected = {name: expected_cohort for name in
                            ("council_protocol", "council_admission", "council", "council_mcp", "council_opencode", "council_inspect")}
                for optimization in ([], ["-O"], ["-OO"]):
                    # Imports succeed for a coherent old generation; the parent
                    # oracle must still distinguish it at every optimization level.
                    self.assertNotEqual(loaded_cohorts(optimization), expected)
                # Model a coarse filesystem clock without depending on wall-clock timing.
                with mock.patch("build_release.ROOT", source), \
                        mock.patch.object(sys, "argv", ["build_release.py", "--write"]), \
                        mock.patch.object(Path, "write_bytes", same_second_write):
                    build_main()
                self.assertEqual(sizes, {path: path.stat().st_size for path in python_sources})
                self.assertTrue(all(int(path.stat().st_mtime) == timestamp for path in python_sources))
                manifest = json.loads((source / "release_manifest.json").read_text())
                self.assertEqual(manifest["runtime_cohort"], expected_cohort)
                for optimization in ([], ["-O"], ["-OO"]):
                    with self.subTest(optimization=optimization):
                        self.assertEqual(loaded_cohorts(optimization), expected)

    def test_checked_hash_cache_observes_changed_source(self):
        protocol = self.source.resolve() / "scripts/council_protocol.py"
        original = protocol.read_bytes()
        changed = original.replace(b"DEFAULT_ROUNDS = 2\n", b"DEFAULT_ROUNDS = 3\n")
        self.assertNotEqual(original, changed)
        self.assertEqual(len(original), len(changed))
        timestamp = 1_700_000_000
        os.utime(protocol, (timestamp, timestamp))
        prefix = str(self.base.resolve() / "checked-hash-cache")
        with mock.patch.object(sys, "pycache_prefix", prefix):
            cache = Path(py_compile.compile(str(protocol), doraise=True, optimize=0,
                                           invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH))
        self.assertEqual(int.from_bytes(cache.read_bytes()[4:8], "little"), 3)
        protocol.write_bytes(changed)
        os.utime(protocol, (timestamp, timestamp))
        env = dict(os.environ, PYTHONPYCACHEPREFIX=prefix)
        env.pop("PYTHONOPTIMIZE", None)
        result = subprocess.run([sys.executable, "-B", "-c",
                                 "import council_protocol; print(council_protocol.DEFAULT_ROUNDS)"],
                                cwd=protocol.parent, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "3")

    def test_cache_enumeration_failure_preserves_sources_and_manifest(self):
        self.run_builder("--write")
        source = self.source.resolve()
        broker = source / "scripts/council.py"
        broker.write_bytes(broker.read_bytes() + b"\n# pending source edit\n")
        before = {name: (source / name).read_bytes() for name in (*RUNTIME_FILES, "release_manifest.json")}
        scandir = os.scandir
        for prefix in (None, str(self.base.resolve() / "restricted-cache")):
            with self.subTest(cache_prefix=prefix), mock.patch.object(sys, "pycache_prefix", prefix):
                directory = Path(importlib.util.cache_from_source(str(broker))).parent
                directory.mkdir(parents=True, exist_ok=True)
                (directory / "council.fixture.pyc").write_bytes(b"readable cache fixture")
                encountered = []

                def unavailable(path):
                    if Path(path) == directory:
                        encountered.append(path)
                        raise PermissionError("cannot enumerate fixture cache directory")
                    return scandir(path)

                with mock.patch("build_release.ROOT", source), \
                        mock.patch.object(sys, "argv", ["build_release.py", "--write"]), \
                        mock.patch("os.scandir", side_effect=unavailable), \
                        mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    with self.assertRaises(SystemExit) as failure:
                        build_main()
                self.assertEqual(failure.exception.code, 1)
                self.assertTrue(encountered)
                self.assertIn("cannot enumerate fixture cache directory", stderr.getvalue())
                self.assertEqual(before, {name: (source / name).read_bytes() for name in before})

    def test_missing_cache_directory_and_unrelated_files_are_preserved(self):
        source = self.source.resolve()
        directory = source / "scripts/__pycache__"
        self.assertFalse(directory.exists())
        for prefix in (None, str(self.base.resolve() / "preserved-cache")):
            with self.subTest(cache_prefix=prefix), \
                    mock.patch("build_release.ROOT", source), \
                    mock.patch.object(sys, "argv", ["build_release.py", "--write"]), \
                    mock.patch.object(sys, "pycache_prefix", prefix):
                build_main()
                directories = {directory,
                               Path(importlib.util.cache_from_source(str(source / "scripts/council.py"))).parent}
                preserved, tagged = [], []
                for cache_directory in directories:
                    cache_directory.mkdir(parents=True, exist_ok=True)
                    for name in ("other.fixture.pyc", "council.pyc"):
                        unrelated = cache_directory / name
                        unrelated.write_bytes(b"unrelated cache")
                        preserved.append(unrelated)
                    cache = cache_directory / "council.fixture.pyc"
                    cache.write_bytes(b"tagged cache")
                    tagged.append(cache)
                build_main()
                for unrelated in preserved:
                    self.assertEqual(unrelated.read_bytes(), b"unrelated cache")
                self.assertTrue(all(not cache.exists() for cache in tagged))

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
