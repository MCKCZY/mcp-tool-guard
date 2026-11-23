from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mcp_tool_guard.guards.path_guard import check_path
from mcp_tool_guard.policy import FilesystemPolicy


class TestPathGuard(unittest.TestCase):
    def test_symlink_escapes_prefix_collision_and_benign_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "work"
            ws_evil = root / "work_evil"
            outside = root / "outside"
            ws.mkdir()
            ws_evil.mkdir()
            outside.mkdir()
            (ws / "src").mkdir()
            (ws / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (ws_evil / "secret.txt").write_text("prefix bypass\n", encoding="utf-8")
            outside_file = outside / "target.txt"
            outside_file.write_text("outside secret\n", encoding="utf-8")

            os.symlink(outside_file, ws / "link_to_file")
            os.symlink(outside, ws / "link_to_dir")

            pol = FilesystemPolicy(allowed_roots=[str(ws)])

            # Benign paths pass.
            self.assertEqual(check_path("src/main.py", pol, base_dir=ws), [])
            self.assertEqual(check_path("./src/../src/main.py", pol, base_dir=ws), [])
            self.assertEqual(check_path(str(ws / "src" / "new_file.py"), pol), [])

            # Prefix collision /work_evil vs /work blocked.
            f_prefix = check_path(str(ws_evil / "secret.txt"), pol)
            self.assertTrue(any(f.code == "PATH_OUTSIDE_ALLOWED_ROOTS" for f in f_prefix))

            # Symlink escape to existing file AND to non-existent leaf blocked.
            f_sym1 = check_path("link_to_file", pol, base_dir=ws)
            self.assertTrue(f_sym1)
            f_sym2 = check_path("link_to_dir/not_created_yet.txt", pol, base_dir=ws)
            self.assertTrue(f_sym2)

            # Sensitive patterns & control characters blocked even inside workspace.
            for bad in (
                ".env",
                "config/.env.production",
                ".ssh/id_rsa",
                "certs/key.pem",
                ".git/config",
                "../outside/target.txt",
                "src/main.py\x00.txt",
                "",
            ):
                self.assertTrue(check_path(bad, pol, base_dir=ws), f"Expected block for {bad!r}")


if __name__ == "__main__":
    unittest.main()
