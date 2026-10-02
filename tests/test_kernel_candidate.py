# SPDX-License-Identifier: Apache-2.0
"""Exact committed-byte provenance and refusal boundaries; no remote imports."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_kernel_candidate as builder


class OfflineKernelCandidate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="govsign-manifest-test-")
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.output = Path(self.temp.name) / "candidate"
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "user.name", "Local fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        package = self.root / builder.SOURCE
        package.mkdir(parents=True)
        self.exact = b"# exact CRLF bytes\r\n__all__ = []\r\n"
        (package / "__init__.py").write_bytes(self.exact)
        (package / "metadata.json").write_text(json.dumps({
            "license": "Apache-2.0", "requires": ["cryptography"]}), encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "committed byte fixture")
        self.revision = self.git("rev-parse", "HEAD").decode().strip()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True).stdout

    def build(self):
        return builder.build_candidate(self.root, self.revision, self.output)

    def verify(self):
        return builder.verify_candidate(self.output, root=self.root, revision=self.revision)

    def test_hashes_actual_git_bytes_and_reports_dependency_blocker(self):
        report = self.build()
        artifact = self.output / builder.VARIANT / "szl_govsign/__init__.py"
        self.assertEqual(artifact.read_bytes(), self.exact)
        metadata = json.loads((self.output / report["metadata_path"]).read_bytes())
        expected = base64.b64encode(hashlib.sha256(self.exact).digest()).decode()
        self.assertEqual(metadata["digest"]["files"]["szl_govsign/__init__.py"], expected)
        self.assertEqual(report["unsupported_curated_dependencies"], ["cryptography"])
        self.assertEqual(report["state"], "UNQUALIFIED_CANDIDATE")
        self.assertEqual(report["runtime_import"], "NOT_PERFORMED")

    def test_working_tree_edits_and_untracked_code_are_never_bound_to_commit(self):
        package = self.root / builder.SOURCE
        (package / "__init__.py").write_bytes(b"raise AssertionError('uncommitted')\n")
        (package / "untracked.py").write_bytes(b"raise AssertionError('untracked')\n")
        self.build()
        self.assertEqual((self.output / builder.VARIANT / "szl_govsign/__init__.py").read_bytes(), self.exact)
        self.assertFalse((self.output / builder.VARIANT / "szl_govsign/untracked.py").exists())

    def test_mutation_extra_files_and_missing_files_refuse_verification(self):
        self.build()
        artifact = self.output / builder.VARIANT / "szl_govsign/__init__.py"
        artifact.write_bytes(self.exact + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.verify()
        artifact.write_bytes(self.exact)
        extra = self.output / builder.VARIANT / "unmanifested.py"
        extra.write_bytes(b"# injected\n")
        with self.assertRaisesRegex(ValueError, "unmanifested"):
            self.verify()
        extra.unlink()
        artifact.unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_source_symlink_mode_is_rejected_without_following_it(self):
        oid = subprocess.run(["git", "-C", str(self.root), "hash-object", "-w", "--stdin"],
                             input=b"../../outside", capture_output=True, check=True).stdout.decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "120000," + oid + "," + builder.SOURCE + "/link.py")
        self.git("commit", "-qm", "symlink fixture")
        revision = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(ValueError, "regular Python/JSON"):
            builder.build_candidate(self.root, revision, self.output)
        self.assertFalse(self.output.exists())

    def test_mutable_revision_existing_destination_and_unsafe_paths_refuse(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            builder.build_candidate(self.root, "main", self.output)
        self.output.mkdir()
        (self.output / "preserve.txt").write_bytes(b"existing work")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual((self.output / "preserve.txt").read_bytes(), b"existing work")
        for value in ["../escape.py", "/absolute.py", "C:/file.py", "bad\\file.py", "a//b.py"]:
            with self.assertRaises(ValueError):
                builder.safe_path(value)

    def test_duplicate_metadata_keys_and_wrong_source_binding_refuse(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            builder.strict_json(b'{"license":"Apache-2.0","license":"other"}')
        self.build()
        path = self.output / builder.VARIANT / "metadata.json"
        metadata = json.loads(path.read_bytes())
        metadata["provenance"]["kernel"]["commit"] = "f" * 40
        path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source binding"):
            self.verify()

    def test_rehashed_candidate_and_self_asserted_provenance_are_rejected(self):
        self.build()
        artifact = self.output / builder.VARIANT / "szl_govsign/__init__.py"
        artifact.write_bytes(b"# substituted code\n")
        path = self.output / builder.VARIANT / "metadata.json"
        metadata = json.loads(path.read_bytes())
        metadata["digest"]["files"]["szl_govsign/__init__.py"] = builder.b64digest(artifact.read_bytes())
        path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "trusted source binding"):
            self.verify()
        metadata["provenance"]["kernel"]["commit"] = "f" * 40
        path.write_text(json.dumps(metadata), encoding="utf-8")
        report_path = self.output / "CANDIDATE.json"
        report = json.loads(report_path.read_bytes())
        report["source_revision"] = "f" * 40
        report["runtime_import"] = "VERIFIED"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "trusted source binding"):
            self.verify()

    def test_physical_candidate_symlink_is_rejected_before_read(self):
        self.build()
        artifact = self.output / builder.VARIANT / "szl_govsign/__init__.py"
        artifact.unlink()
        try:
            os.symlink(self.root / builder.SOURCE / "__init__.py", artifact)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink privilege unavailable; exercised on Linux CI")
            raise
        with self.assertRaisesRegex(ValueError, "symlinks are forbidden"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
