#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The committed, LICENSE-only writer for the native szl-govsign Kernel Hub.

Validation is local and never reads credentials. Publication is manual, bound to
the current canonical default-branch tip, terminal hosted checks, an exact Hub
parent and the reviewed original notice digest. No remote Python is executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REPO = "szl-holdings/szl-govsign"
HUB_REPO = "SZLHOLDINGS/szl-govsign"
HUB_URL = f"https://huggingface.co/kernels/{HUB_REPO}"
REQUIRED_CHECKS = {"verify canonical kernel", "analyze / Analyze (python)",
                   "scorecard / Scorecard analysis"}
HEX40 = re.compile(r"[0-9a-f]{40}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    return subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-C", str(repo), *args],
        check=True, capture_output=True, env=env,
    ).stdout


def read_json(url: str, token: str | None = None) -> Any:
    headers = {"Accept": "application/json", "User-Agent": "szl-kernel-license-publisher/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def validate_plan(root: Path = ROOT) -> tuple[dict[str, str], bytes]:
    plan = json.loads((root / "hf-publication/license.json").read_text(encoding="utf-8"))
    if (plan.get("schema"), plan.get("repo_id"), plan.get("repo_type"), plan.get("path"),
            plan.get("license"), plan.get("operation")) != (
        "szl.kernel-license-publication/v1", HUB_REPO, "kernel", "LICENSE", "Apache-2.0",
        "append-canonical-terms-preserve-original-bytes",
    ):
        raise ValueError("publication plan exceeds the approved LICENSE-only boundary")
    if HEX40.fullmatch(plan["expected_parent_commit"]) is None:
        raise ValueError("an immutable native Kernel Hub parent is required")
    canonical = (root / "LICENSE").read_bytes()
    if digest(b" ".join(canonical.split())) != plan["source_license_whitespace_sha256"]:
        raise ValueError("canonical Apache-2.0 terms differ from the reviewed digest")
    for section in range(1, 10):
        if re.search(rb"\n\s+" + str(section).encode() + rb"\. ", canonical) is None:
            raise ValueError(f"canonical Apache-2.0 section {section} is absent")
    # Source checkout line endings vary across Windows/Linux; terms do not.
    return plan, b"\n".join(canonical.splitlines()).lstrip(b"\n") + b"\n"


def replacement(original: bytes, canonical: bytes, plan: dict[str, str]) -> bytes:
    if digest(original) != plan["expected_original_sha256"]:
        raise ValueError("native LICENSE differs from the reviewed original notice")
    if b"Copyright 2026 SZL Holdings" not in original:
        raise ValueError("original copyright notice is absent")
    if b"TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in original:
        raise ValueError("native LICENSE already contains full terms")
    return original + b"\n\n" + canonical


def check_source_checks(checks: list[dict[str, Any]]) -> None:
    matching = {name: [item for item in checks if item.get("name") == name
                      and item.get("app", {}).get("slug") == "github-actions"]
                for name in REQUIRED_CHECKS}
    for name, items in matching.items():
        if not items or any(item.get("status") != "completed" or
                            item.get("conclusion") != "success" for item in items):
            raise ValueError(f"canonical hosted check has not passed: {name}")


def source_gate() -> str:
    if os.environ.get("GITHUB_REPOSITORY") != SOURCE_REPO:
        raise ValueError("publication must run in the canonical source repository")
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise ValueError("publication requires a manual workflow_dispatch")
    revision = git(ROOT, "rev-parse", "HEAD").decode().strip()
    if HEX40.fullmatch(revision) is None or revision != os.environ.get("GITHUB_SHA"):
        raise ValueError("checked-out source does not match the dispatched immutable revision")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise ValueError("GitHub read token is unavailable")
    api = f"https://api.github.com/repos/{SOURCE_REPO}"
    repository = read_json(api, token)
    branch = repository["default_branch"]
    if branch != "main" or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("publication requires the canonical default branch")
    current = read_json(f"{api}/git/ref/heads/main", token)["object"]["sha"]
    if current != revision:
        raise ValueError("canonical default-branch tip changed before publication")
    checks = read_json(f"{api}/commits/{revision}/check-runs?per_page=100", token)
    check_source_checks(checks["check_runs"])
    return revision


def tree(repo: Path) -> dict[bytes, bytes]:
    entries: dict[bytes, bytes] = {}
    for line in git(repo, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if line:
            value, path = line.split(b"\t", 1)
            entries[path] = value
    return entries


def check_unchanged_tree(before: dict[bytes, bytes], after: dict[bytes, bytes]) -> None:
    without_license = lambda values: {key: value for key, value in values.items() if key != b"LICENSE"}
    if without_license(before) != without_license(after):
        raise ValueError("native repository changed outside LICENSE")
    if b"LICENSE" not in after or not any(path.startswith(b"build/") for path in after):
        raise ValueError("native license or retained kernel build variants are absent")


def publish(*, dry_run: bool, report: Path, expected_parent: str) -> dict[str, Any]:
    plan, canonical = validate_plan()
    if expected_parent != plan["expected_parent_commit"]:
        raise ValueError("dispatched native parent differs from the reviewed manifest")
    revision = source_gate()
    token = os.environ.get("HF_PUBLISH_TOKEN")
    if not token:
        raise ValueError("Hugging Face organization publisher token is unavailable")
    who = read_json("https://huggingface.co/api/whoami-v2", token)
    org = next((item for item in who.get("orgs", []) if item.get("name") == "SZLHOLDINGS"), None)
    if org is None or str(org.get("roleInOrg") or org.get("role") or "").lower() not in {
        "admin", "write", "contributor",
    }:
        raise ValueError("authenticated publisher lacks a verified SZLHOLDINGS write role")
    expected = plan["expected_parent_commit"]
    metadata = read_json(f"https://huggingface.co/api/kernels/{HUB_REPO}", token)
    if metadata.get("sha") != expected:
        raise ValueError("native Kernel Hub metadata head changed; review a new plan")
    with tempfile.TemporaryDirectory(prefix="szl-kernel-license-") as directory:
        stage = Path(directory)
        hooks = stage / "empty-hooks"
        hooks.mkdir()
        askpass = stage / "askpass.sh"
        askpass.write_text(
            '#!/bin/sh\ncase "$1" in\n'
            '  *Username*) printf "%s\\n" "$HF_PUBLISH_USERNAME" ;;\n'
            '  *Password*) printf "%s\\n" "$HF_PUBLISH_TOKEN" ;;\n'
            '  *) exit 1 ;;\nesac\n', encoding="utf-8",
        )
        askpass.chmod(0o700)
        env = {**os.environ, "GIT_ASKPASS": str(askpass), "GIT_TERMINAL_PROMPT": "0",
               "GIT_LFS_SKIP_SMUDGE": "1", "HF_PUBLISH_USERNAME": str(who["name"])}
        clone = stage / "repo"
        subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", f"core.hooksPath={hooks}",
             "clone", "--depth", "1", "--branch", "main", HUB_URL, str(clone)],
            check=True, capture_output=True, env=env,
        )
        git(clone, "config", "core.hooksPath", str(hooks), env=env)
        git(clone, "config", "commit.gpgsign", "false", env=env)
        before = git(clone, "rev-parse", "HEAD", env=env).decode().strip()
        if before != expected:
            raise ValueError("native Kernel Hub Git parent changed; review a new plan")
        before_tree = tree(clone)
        original = git(clone, "show", "HEAD:LICENSE", env=env)
        desired = replacement(original, canonical, plan)
        (clone / "LICENSE").write_bytes(desired)
        git(clone, "add", "--", "LICENSE", env=env)
        if git(clone, "diff", "--cached", "--name-only", env=env).splitlines() != [b"LICENSE"]:
            raise ValueError("staged mutation is not exactly LICENSE")
        git(clone, "config", "user.name", "szl-release-bot", env=env)
        git(clone, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", env=env)
        git(clone, "commit", "-m", f"docs(license): append full Apache-2.0 terms from {SOURCE_REPO}@{revision}", env=env)
        after = git(clone, "rev-parse", "HEAD", env=env).decode().strip()
        check_unchanged_tree(before_tree, tree(clone))
        result = {"schema": "szl.kernel-license-publication-result/v1", "source_revision": revision,
                  "repo_id": HUB_REPO, "native_parent": before, "candidate_revision": after,
                  "status": "DRY_RUN", "publication_attempted": False,
                  "published_revision": None,
                  "original_sha256": digest(original), "replacement_sha256": digest(desired),
                  "original_notice_bytes_preserved": desired.startswith(original),
                  "all_other_git_blobs_and_modes_preserved": True,
                  "preserved_paths": sorted(path.decode("utf-8") for path in before_tree if path != b"LICENSE"),
                  "runtime_qualification": "NOT_PERFORMED"}
        if not dry_run:
            try:
                source_gate()
                git(clone, "fetch", "origin", "main", env=env)
                if git(clone, "rev-parse", "FETCH_HEAD", env=env).decode().strip() != before:
                    raise ValueError("native parent moved immediately before push")
                result["publication_attempted"] = True
                git(clone, "push", "origin", "HEAD:main", env=env)
                git(clone, "fetch", "origin", "main", env=env)
                observed = git(clone, "rev-parse", "FETCH_HEAD", env=env).decode().strip()
                result["observed_revision_after_push"] = observed
                if observed != after or git(clone, "show", "FETCH_HEAD:LICENSE", env=env) != desired:
                    raise ValueError("native immutable commit/license readback failed")
                git(clone, "checkout", "--detach", "FETCH_HEAD", env=env)
                check_unchanged_tree(before_tree, tree(clone))
                result["status"] = "PUBLISHED_VERIFIED"
                result["published_revision"] = after
            except Exception as exc:
                result["status"] = "FAILED_CLOSED"
                result["error_type"] = type(exc).__name__
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                raise
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--publish", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    parser.add_argument("--expected-parent", default="")
    parser.add_argument("--report", type=Path, default=Path("reports/kernel-license-publication.json"))
    args = parser.parse_args()
    if not args.publish and not args.dry_run:
        plan, canonical = validate_plan()
        print(json.dumps({"status": "LOCAL_CONTRACT_VALIDATED", "repo_id": plan["repo_id"],
                          "canonical_license_sha256": digest(canonical)}))
        return
    print(json.dumps(publish(dry_run=not args.publish, report=args.report,
                             expected_parent=args.expected_parent), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Transport errors may contain captured subprocess details; never emit
        # credential-bearing output from a provider or a credential helper.
        if isinstance(exc, subprocess.CalledProcessError):
            raise SystemExit(f"Kernel license Git operation failed (exit {exc.returncode})") from None
        raise SystemExit(f"Kernel license publication refused: {exc}") from None
