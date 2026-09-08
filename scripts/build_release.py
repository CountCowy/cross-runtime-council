#!/usr/bin/env python3
"""Stamp/check a tracked source checkout or emit a new offline release directory.

This developer tool never installs, updates, or inspects a live Council runtime.
Git selects tracked inputs; Python 3.9 standard-library code does all generation.
"""

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from generate_protocol import normalized_stamps, render

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "release_manifest.json"
RUNTIME_FILES = (
    "scripts/council_protocol.py", "scripts/council_protocol.ts",
    "scripts/council.py", "scripts/council_mcp.py", "scripts/council_opencode.py",
    "scripts/opencode_council_plugin.ts", "scripts/opencode_delivery_registry.ts",
    "scripts/tools/council.ts",
)
OPENCODE_ARTIFACTS = {
    "council-plugin.ts": "scripts/opencode_council_plugin.ts",
    "council_protocol.ts": "scripts/council_protocol.ts",
    "opencode_delivery_registry.ts": "scripts/opencode_delivery_registry.ts",
    "tools/council.ts": "scripts/tools/council.ts",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(files):
    # JSON binds names and contents unambiguously; neither location nor mtime enters.
    records = [[name, digest(data)] for name, data in sorted(files.items())]
    return digest(json.dumps(records, separators=(",", ":")).encode())


def tracked_inputs(root):
    root = root.resolve()
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    names = [name.decode("utf-8") for name in output.split(b"\0") if name]
    inputs = {}
    for name in names:
        if name == MANIFEST:
            continue
        path = root / name
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise ValueError("release input is missing, nonregular, or escapes the checkout: " + name)
        inputs[name] = path.read_bytes()
    missing = set(RUNTIME_FILES) - inputs.keys()
    if missing:
        raise ValueError("runtime inputs are not tracked: " + ", ".join(sorted(missing)))
    return inputs


def release(root):
    inputs = tracked_inputs(root)
    generated = inputs["scripts/council_protocol.ts"].decode()
    if normalized_stamps(generated) != render(inputs["scripts/council_protocol.py"]):
        raise ValueError("TypeScript protocol is stale; run python3 scripts/generate_protocol.py")
    normalized = dict(inputs)
    for name in RUNTIME_FILES:
        text = inputs[name].decode()
        for field in ("PACKAGE_ID", "RUNTIME_COHORT"):
            if len(re.findall(r'(?m)^(?:(?:export )?const )?' + field + r' = "[^\"]+"', text)) != 1:
                raise ValueError("missing or duplicate %s stamp in %s" % (field, name))
        normalized[name] = normalized_stamps(text).encode()
    package = identity(normalized)
    cohort = identity({name: normalized[name] for name in RUNTIME_FILES})
    stamped = dict(inputs)
    for name in RUNTIME_FILES:
        text = normalized[name].decode()
        text = text.replace('PACKAGE_ID = "unstamped"', 'PACKAGE_ID = "' + package + '"')
        text = text.replace('RUNTIME_COHORT = "unstamped"', 'RUNTIME_COHORT = "' + cohort + '"')
        stamped[name] = text.encode()
    artifacts = {"payload/" + name: data for name, data in stamped.items()}
    artifacts.update({"opencode/" + dest: stamped[source] for dest, source in OPENCODE_ARTIFACTS.items()})
    manifest = {
        "format": 1,
        "package_id": package,
        "runtime_cohort": cohort,
        "runtime_sources": list(RUNTIME_FILES),
        "opencode_sources": OPENCODE_ARTIFACTS,
        "artifacts": {name: digest(data) for name, data in sorted(artifacts.items())},
    }
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return stamped, artifacts, encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true", help="read-only generation/stamp check")
    modes.add_argument("--write", action="store_true", help="refresh committed stamps and manifest")
    modes.add_argument("--output", type=Path, help="emit a new directory; never overwrite one")
    args = parser.parse_args()
    try:
        installed = (Path.home() / ".claude/skills/council").resolve()
        if args.write and (ROOT == installed or installed in ROOT.parents):
            raise ValueError("stamp a separate development checkout, not the installed payload")
        stamped, artifacts, manifest = release(ROOT)
        if args.check:
            stale = [name for name in RUNTIME_FILES if (ROOT / name).read_bytes() != stamped[name]]
            if not (ROOT / MANIFEST).is_file() or (ROOT / MANIFEST).read_bytes() != manifest:
                stale.append(MANIFEST)
            if stale:
                raise ValueError("release stamps are stale; run python3 scripts/build_release.py --write: " + ", ".join(stale))
        elif args.write:
            manifest_path = ROOT / MANIFEST
            if manifest_path.is_symlink() or (manifest_path.exists() and not manifest_path.is_file()):
                raise ValueError("release manifest must be a regular file, not a symlink")
            # Fixed-width stamps can leave timestamp/size bytecode caches valid.
            # Clear caches before any source writes, including optimized variants.
            for name in RUNTIME_FILES:
                path = ROOT / name
                if path.suffix == ".py":
                    cache_dirs = {path.parent / "__pycache__",
                                  Path(importlib.util.cache_from_source(str(path))).parent}
                    for directory in cache_dirs:
                        try:
                            with os.scandir(directory) as entries:
                                caches = [directory / entry.name for entry in entries
                                          if fnmatch.fnmatchcase(entry.name, path.stem + ".*.pyc")]
                        except FileNotFoundError:
                            continue
                        for cache in caches:
                            cache.unlink(missing_ok=True)
            for name in RUNTIME_FILES:
                (ROOT / name).write_bytes(stamped[name])
            manifest_path.write_bytes(manifest)
        else:
            output = args.output.expanduser().resolve()
            if output == ROOT or ROOT in output.parents or output in ROOT.parents:
                raise ValueError("output must be outside the source checkout")
            # mkdir is exclusive. Cleanup owns only the directory created here.
            output.mkdir(mode=0o700)
            try:
                for name, data in artifacts.items():
                    path = output / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    source = name.removeprefix("payload/") if name.startswith("payload/") else OPENCODE_ARTIFACTS[name.removeprefix("opencode/")]
                    path.chmod(0o644 | ((ROOT / source).stat().st_mode & 0o111))
                (output / MANIFEST).write_bytes(manifest)
            except BaseException:
                shutil.rmtree(output)
                raise
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, "release: %s\n" % error)


if __name__ == "__main__":
    main()
