#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an offline, unqualified Kernel Hub candidate from committed Git bytes.

No network, credentials, source imports, or provider publication. The existing
LICENSE-only publisher is intentionally unable to publish this candidate.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "torch-ext/szl_govsign"
VARIANT = "build/torch-universal"
ENTRY = b"from .szl_govsign import *\nfrom .szl_govsign import __all__, __version__\n"


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True).stdout


def safe_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "\\" in value
            or str(path) != value or any(":" in p for p in path.parts)):
        raise ValueError("unsafe candidate path")
    return path


def b64digest(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def strict_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(result, dict):
        raise ValueError("metadata must be an object")
    return result


def committed_package(root: Path, revision: str) -> dict[str, bytes]:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("an immutable source commit is required")
    if git(root, "cat-file", "-t", revision).strip() != b"commit":
        raise ValueError("source revision must identify a commit")
    files = {}
    listing = git(root, "ls-tree", "-r", "-z", revision, "--", SOURCE)
    for item in listing.split(b"\0"):
        if not item:
            continue
        header, raw_path = item.split(b"\t", 1)
        mode, kind, oid = header.split()
        source_path = raw_path.decode("utf-8")
        rel = source_path.removeprefix(SOURCE + "/")
        safe_path(rel)
        if mode != b"100644" or kind != b"blob" or not rel.endswith((".py", ".json")):
            raise ValueError("candidate source must contain regular Python/JSON blobs only")
        data = git(root, "cat-file", "blob", oid.decode("ascii"))
        if len(data) > 256_000 or len(files) >= 100 or sum(map(len, files.values())) + len(data) > 1_000_000:
            raise ValueError("candidate source exceeds the size bound")
        files["szl_govsign/" + rel] = data
    if "szl_govsign/__init__.py" not in files or "szl_govsign/metadata.json" not in files:
        raise ValueError("canonical source package is incomplete")
    return files


def candidate_records(root: Path, revision: str) -> tuple[dict[str, bytes], dict, dict]:
    files = committed_package(root, revision)
    legacy = strict_json(files["szl_govsign/metadata.json"])
    requires = legacy.get("requires")
    if (legacy.get("license") != "Apache-2.0" or not isinstance(requires, list)
            or not all(isinstance(x, str) and x for x in requires)):
        raise ValueError("canonical dependency/license declarations are incomplete")
    files["__init__.py"] = ENTRY
    metadata = {
        "id": "_szl_govsign_cpu_" + revision,
        "name": "szl-govsign", "version": 1, "license": "Apache-2.0",
        "backend": {"type": "cpu"}, "universal": True,
        "python-depends": requires,
        "source": "https://github.com/szl-holdings/szl-govsign",
        "provenance": {"kernel": {"commit": revision, "dirty": False}},
        "digest": {"algorithm": "sha256", "files": {
            name: b64digest(data) for name, data in sorted(files.items())}},
    }
    # Curated dependency membership is a documented compatibility boundary,
    # not permission to remove a dependency or pretend the kernel is loadable.
    unsupported = [x for x in requires if x not in {"einops", "helion"}]
    report = {
        "schema": "szl.offline-kernel-candidate/v1",
        "state": "UNQUALIFIED_CANDIDATE", "source_repository": "szl-holdings/szl-govsign",
        "source_revision": revision, "source_input": "immutable Git blobs",
        "publication": "NOT_PERFORMED", "runtime_import": "NOT_PERFORMED",
        "hardware_benchmark": "NOT_PERFORMED", "signature_verification": "NOT_PERFORMED",
        "unsupported_curated_dependencies": unsupported,
        "current_publisher_scope": "LICENSE_ONLY_CANNOT_PUBLISH_THIS_CANDIDATE",
        "metadata_path": VARIANT + "/metadata.json",
    }
    return files, metadata, report


def build_candidate(root: Path, revision: str, output: Path) -> dict:
    if output.exists():
        raise ValueError("candidate destination already exists")
    files, metadata, report = candidate_records(root, revision)
    output.mkdir(parents=True)
    for name, data in files.items():
        target = output.joinpath(VARIANT, *safe_path(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    output.joinpath(VARIANT, "metadata.json").write_bytes(
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    (output / "CANDIDATE.json").write_bytes(
        (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    verify_candidate(output, root=root, revision=revision)
    return report


def verify_candidate(output: Path, *, root: Path, revision: str) -> None:
    # The expected commit and trusted checkout come from the caller, never
    # from the candidate's editable report or metadata.
    expected_files, expected_metadata, expected_report = candidate_records(root, revision)
    if output.is_symlink() or any(p.is_symlink() for p in output.rglob("*")):
        raise ValueError("candidate symlinks are forbidden")
    report = strict_json((output / "CANDIDATE.json").read_bytes())
    if (report.get("schema") != "szl.offline-kernel-candidate/v1"
            or report.get("state") != "UNQUALIFIED_CANDIDATE"
            or report.get("metadata_path") != VARIANT + "/metadata.json"):
        raise ValueError("unexpected candidate report")
    metadata_path = output / VARIANT / "metadata.json"
    metadata = strict_json(metadata_path.read_bytes())
    if report != expected_report:
        raise ValueError("candidate report differs from trusted source binding")
    if metadata != expected_metadata:
        raise ValueError("candidate metadata differs from trusted source binding")
    digest = metadata.get("digest", {})
    hashes = digest.get("files")
    if digest.get("algorithm") != "sha256" or not isinstance(hashes, dict) or not hashes:
        raise ValueError("candidate requires a SHA256 file manifest")
    expected = {"CANDIDATE.json", VARIANT + "/metadata.json"}
    for name, declared in hashes.items():
        rel = safe_path(name)
        target = output.joinpath(VARIANT, *rel.parts)
        if not isinstance(declared, str) or b64digest(target.read_bytes()) != declared:
            raise ValueError("candidate file digest mismatch")
        if target.read_bytes() != expected_files.get(name):
            raise ValueError("candidate bytes differ from committed source")
        expected.add(VARIANT + "/" + name)
    actual = set()
    for target in output.rglob("*"):
        if target.is_symlink():
            raise ValueError("candidate symlinks are forbidden")
        if target.is_file():
            actual.add(target.relative_to(output).as_posix())
    if actual != expected:
        raise ValueError("candidate contains missing or unmanifested files")
    provenance = metadata.get("provenance", {}).get("kernel", {})
    if (provenance.get("commit") != report.get("source_revision")
            or provenance.get("dirty") is not False):
        raise ValueError("candidate source binding differs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_candidate(ROOT, args.source_revision, args.output), indent=2))


if __name__ == "__main__":
    main()
