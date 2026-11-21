"""Exercise publication guards against accidental local data and archive drift."""

import hashlib
import contextlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from check_release import privacy_findings  # noqa: E402
from source_bundle import build_source  # noqa: E402
from source_manifest import public_files  # noqa: E402
from bmcdhcp import __version__, cli  # noqa: E402


class PublicSourceTest(unittest.TestCase):
    def test_privacy_guard_reports_category_without_printing_credential(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "notes.md"
            path.write_text("gh" + "p_" + "a" * 36)
            self.assertIn("GitHub credential", privacy_findings(path))
            path.write_text("/Users/" + "private-person/notes")
            self.assertIn("private home path", privacy_findings(path))

    def test_source_export_is_deterministic_and_excludes_local_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src/bmcdhcp").mkdir(parents=True)
            (root / "src/bmcdhcp/__init__.py").write_text('__version__ = "1.0.0"\n')
            (root / "LICENSE").write_text("test license")
            (root / "README.md").write_text("test public readme")
            (root / "credentials.txt").write_text("local-only test data")
            (root / "docs/eval").mkdir(parents=True)
            (root / "docs/eval/private.md").write_text("local-only test evidence")
            (root / "src/bmcdhcp.egg-info").mkdir()
            (root / "src/bmcdhcp.egg-info/PKG-INFO").write_text("generated local metadata")
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            build_source(first, root)
            build_source(second, root)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            with tarfile.open(first) as archive:
                names = archive.getnames()
                self.assertIn("bmcdhcp-1.0.0/LICENSE", names)
                self.assertFalse(any("private" in name or "credentials" in name for name in names))
                self.assertFalse(any(".egg-info" in name for name in names))
                self.assertTrue(all(member.uid == 0 and member.mtime == 0 for member in archive.getmembers()))

    def test_source_export_rejects_an_external_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src").mkdir()
            outside = root / "local-only.txt"
            outside.write_text("not public")
            (root / "src/external.txt").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                public_files(root)

    def test_cli_version_matches_package_version(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_status:
            cli.build_parser().parse_args(["--version"])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"bmcd {__version__}")


if __name__ == "__main__":
    unittest.main()
