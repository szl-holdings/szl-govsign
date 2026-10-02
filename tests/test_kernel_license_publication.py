# SPDX-License-Identifier: Apache-2.0
"""Refusal boundaries and complete local-Git publication/readback exercise."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import publish_kernel_license as publisher


class LicensePublicationContract(unittest.TestCase):
    def test_reviewed_manifest_is_license_only(self) -> None:
        plan, canonical = publisher.validate_plan()
        self.assertEqual(plan["path"], "LICENSE")
        self.assertIn(b"END OF TERMS AND CONDITIONS", canonical)

    def test_notice_is_preserved_byte_for_byte(self) -> None:
        original = b"Copyright 2026 SZL Holdings\r\nExisting notice.\r\n"
        plan = {"expected_original_sha256": publisher.digest(original)}
        self.assertEqual(publisher.replacement(original, b"terms\n", plan), original + b"\n\nterms\n")
        with self.assertRaises(ValueError):
            publisher.replacement(original + b"unreviewed", b"terms\n", plan)

    def test_non_license_paths_and_modes_cannot_change(self) -> None:
        before = {b"LICENSE": b"100644 blob old", b"build/kernel.py": b"100644 blob code"}
        publisher.check_unchanged_tree(before, {**before, b"LICENSE": b"100644 blob new"})
        for after in (
            {**before, b"build/kernel.py": b"100644 blob changed"},
            {**before, b"build/kernel.py": b"100755 blob code"},
            {b"LICENSE": b"100644 blob new"},
            {**before, b"new-file": b"100644 blob added"},
        ):
            with self.assertRaises(ValueError):
                publisher.check_unchanged_tree(before, after)

    def test_pending_failed_missing_or_foreign_checks_refuse_publication(self) -> None:
        success = [{"name": name, "status": "completed", "conclusion": "success",
                    "app": {"slug": "github-actions"}} for name in publisher.REQUIRED_CHECKS]
        publisher.check_source_checks(success)
        for change in ({"status": "in_progress"}, {"conclusion": "failure"},
                       {"conclusion": "skipped"}, {"app": {"slug": "other-app"}}):
            with self.assertRaises(ValueError):
                publisher.check_source_checks([{**success[0], **change}, *success[1:]])
        with self.assertRaises(ValueError):
            publisher.check_source_checks(success[1:])

    def test_source_gate_rejects_wrong_event_or_moved_source(self) -> None:
        revision = "a" * 40
        checks = [{"name": name, "status": "completed", "conclusion": "success",
                   "app": {"slug": "github-actions"}} for name in publisher.REQUIRED_CHECKS]
        values = [{"default_branch": "main"}, {"object": {"sha": revision}}, {"check_runs": checks}]
        env = {"GITHUB_REPOSITORY": publisher.SOURCE_REPO, "GITHUB_EVENT_NAME": "workflow_dispatch",
               "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": revision, "GH_TOKEN": "unit-test"}
        with patch.dict(os.environ, env, clear=True), patch.object(publisher, "git", return_value=revision.encode()), \
                patch.object(publisher, "read_json", side_effect=values):
            self.assertEqual(publisher.source_gate(), revision)
        for change in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/topic"},
                       {"GITHUB_REPOSITORY": "someone/fork"}, {"GITHUB_SHA": "b" * 40}):
            with patch.dict(os.environ, {**env, **change}, clear=True), \
                    patch.object(publisher, "git", return_value=revision.encode()), \
                    patch.object(publisher, "read_json", side_effect=values), self.assertRaises(ValueError):
                publisher.source_gate()
        with patch.dict(os.environ, env, clear=True), patch.object(publisher, "git", return_value=revision.encode()), \
                patch.object(publisher, "read_json", side_effect=[values[0], {"object": {"sha": "b" * 40}}]), \
                self.assertRaises(ValueError):
            publisher.source_gate()

    def test_dispatched_parent_must_match_reviewed_manifest(self) -> None:
        with patch.object(publisher, "source_gate") as gate, self.assertRaises(ValueError):
            publisher.publish(dry_run=True, report=Path("unused.json"), expected_parent="b" * 40)
        gate.assert_not_called()


class LocalGitPublication(unittest.TestCase):
    """Exercise the real Git transport against a disposable local bare repo."""

    def test_dry_run_does_not_push_and_publish_preserves_all_other_blobs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="szl-license-test-") as directory:
            stage = Path(directory)
            source = stage / "seed"
            remote = stage / "remote.git"
            source.mkdir()
            original = b"Copyright 2026 SZL Holdings\r\nOriginal license notice.\r\n"
            (source / "LICENSE").write_bytes(original)
            (source / "build").mkdir()
            (source / "build/kernel.py").write_bytes(b"# must remain unchanged\n")
            (source / "README.md").write_bytes(b"retained card\n")
            command = lambda *args: subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "commit.gpgsign=false", *args],
                                                   check=True, capture_output=True)
            command("init", "-b", "main", str(source))
            command("-C", str(source), "config", "user.name", "Local test fixture")
            command("-C", str(source), "config", "user.email", "fixture@example.invalid")
            command("-C", str(source), "add", ".")
            command("-C", str(source), "commit", "-m", "fixture")
            command("clone", "--bare", str(source), str(remote))
            parent = command("-C", str(remote), "rev-parse", "HEAD").stdout.decode().strip()
            plan = {"expected_parent_commit": parent, "expected_original_sha256": publisher.digest(original)}
            canonical = b"Complete reviewed terms.\n"
            real_run = subprocess.run

            def local_transport(args, **kwargs):
                substituted = [str(remote) if value == publisher.HUB_URL else value for value in args]
                return real_run(substituted, **kwargs)

            def fake_json(url, token=None):
                if url.endswith("whoami-v2"):
                    return {"name": "test-user", "orgs": [{"name": "SZLHOLDINGS", "roleInOrg": "write"}]}
                return {"sha": parent}

            report = stage / "result.json"
            with patch.object(publisher, "validate_plan", return_value=(plan, canonical)), \
                    patch.object(publisher, "source_gate", return_value="a" * 40) as gate, \
                    patch.object(publisher, "read_json", side_effect=fake_json), \
                    patch.dict(os.environ, {"HF_PUBLISH_TOKEN": "unit-test-nonsecret"}), \
                    patch.object(publisher.subprocess, "run", side_effect=local_transport):
                dry = publisher.publish(dry_run=True, report=report, expected_parent=parent)
                self.assertEqual(dry["status"], "DRY_RUN")
                self.assertEqual(command("-C", str(remote), "rev-parse", "HEAD").stdout.decode().strip(), parent)
                published = publisher.publish(dry_run=False, report=report, expected_parent=parent)
                self.assertEqual(published["status"], "PUBLISHED_VERIFIED")
                self.assertEqual(gate.call_count, 3)
            observed = command("-C", str(remote), "rev-parse", "HEAD").stdout.decode().strip()
            self.assertEqual(observed, published["published_revision"])
            self.assertEqual(command("-C", str(remote), "show", "HEAD:LICENSE").stdout,
                             original + b"\n\n" + canonical)
            self.assertEqual(command("-C", str(remote), "diff", "--name-only", parent, observed).stdout.strip(), b"LICENSE")
            self.assertEqual(json.loads(report.read_text())["preserved_paths"], ["README.md", "build/kernel.py"])


if __name__ == "__main__":
    unittest.main()
