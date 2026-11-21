"""Windows 启动器（app_win.py）的环境自愈逻辑。

在 mac 上也能跑：这里只测「文件布局判断 + 决定要不要重建」，
不真的去建 venv、也不碰真实的家目录。
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)          # app_win.py 在项目根目录

import app_win as A  # noqa: E402


class LauncherVenvTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bmcd-launcher-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # bmcd_dir() 读 LOCALAPPDATA；指到临时目录，绝不碰真实路径
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict(os.environ, {"LOCALAPPDATA": self.tmp}).start()
        self.venv = os.path.join(self.tmp, "bmcd", "venv")
        self.scripts = os.path.join(self.venv, "Scripts")
        self.cfg = os.path.join(self.venv, "pyvenv.cfg")

    # ---- 造现场 ----

    def _make_scripts(self):
        os.makedirs(self.scripts, exist_ok=True)
        for name in ("python.exe", "pythonw.exe"):
            with open(os.path.join(self.scripts, name), "wb"):
                pass

    def _make_cfg(self, home):
        with open(self.cfg, "w", encoding="utf-8") as fh:
            fh.write("home = %s\ninclude-system-site-packages = false\n" % home)

    def _make_full(self, home=None):
        self._make_scripts()
        self._make_cfg(home or self.tmp)

    # ---- venv_problem ----

    def test_missing_venv(self):
        self.assertEqual(A.venv_problem(), "还没建")

    def test_half_made_venv_is_rejected(self):
        """用户遇到的那个框：Scripts\\python.exe 在，pyvenv.cfg 不在。"""
        self._make_scripts()
        problem = A.venv_problem()
        self.assertIn("pyvenv.cfg", problem)

    def test_base_python_gone_is_rejected(self):
        self._make_scripts()
        self._make_cfg(os.path.join(self.tmp, "不存在", "Python313"))
        self.assertIn("不在", A.venv_problem())

    def test_missing_windowless_exe_is_rejected(self):
        self._make_scripts()
        os.remove(os.path.join(self.scripts, "pythonw.exe"))
        self._make_cfg(self.tmp)
        self.assertIn("pythonw.exe", A.venv_problem())

    def test_good_layout_passes(self):
        self._make_full()
        with mock.patch.object(A, "_capture", lambda cmd, timeout=25: (0, self.venv, "")):
            self.assertEqual(A.venv_problem(), "")

    def test_wrong_prefix_is_rejected(self):
        """sys.prefix 不是这个 venv：说明 exe 根本不是这套环境里的。"""
        self._make_full()
        with mock.patch.object(A, "_capture", lambda cmd, timeout=25: (0, "/usr/bin", "")):
            self.assertIn("sys.prefix", A.venv_problem())

    def test_broken_exe_is_rejected(self):
        self._make_full()
        with mock.patch.object(A, "_capture",
                               lambda cmd, timeout=25: (1, "", "Unable to create process")):
            self.assertIn("起不来", A.venv_problem())

    # ---- ensure_backend_python 的自愈 ----

    def test_broken_venv_is_removed_and_rebuilt(self):
        self._make_scripts()                       # 缺 pyvenv.cfg
        seen = []

        def fake_capture(cmd, timeout=25):
            seen.append(list(cmd))
            joined = " ".join(str(x) for x in cmd)
            if "venv" in cmd:                      # -m venv <dir>
                self._make_full()
                return 0, "", ""
            if "pip" in joined:
                return 0, "", ""
            return 0, self.venv, ""

        with mock.patch.object(A, "_capture", fake_capture):
            got = A.ensure_backend_python()
        self.assertTrue(seen, "应当尝试过建 venv")
        self.assertIn(os.path.join("venv", "Scripts"), got)
        self.assertTrue(os.path.isfile(self.cfg), "重建后 pyvenv.cfg 应该在")

    def test_rebuild_is_skipped_when_venv_is_healthy(self):
        self._make_full()
        calls = []
        with mock.patch.object(A, "_capture",
                               lambda cmd, timeout=25: (calls.append(1), (0, self.venv, ""))[1]):
            got = A.ensure_backend_python()
        self.assertTrue(got.endswith("pythonw.exe"))
        self.assertEqual(len(calls), 1, "健康时只该跑一次探测，不该重建")

    # ---- 包完整性（残包） ----

    def test_missing_package_files_all_present(self):
        for rel in A.REQUIRED_FILES:
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb"):
                pass
        with mock.patch.object(A, "HERE", self.tmp):
            self.assertEqual(A.missing_package_files(), [])

    def test_missing_package_files_detects_partial_copy(self):
        """只复制了 .py、没带 ui/index.html —— 正是白屏那个故障。"""
        for rel in A.REQUIRED_FILES:
            if rel.endswith("index.html"):
                continue
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb"):
                pass
        with mock.patch.object(A, "HERE", self.tmp):
            missing = A.missing_package_files()
        self.assertEqual(len(missing), 1)
        self.assertTrue(missing[0].endswith(os.path.join("ui", "index.html")))

    # ---- 会话文件 vs backend.log（Windows 上踩过：后端起来了却报超时） ----

    def _write_log(self, text):
        os.makedirs(os.path.dirname(A.log_path()), exist_ok=True)
        with open(A.log_path(), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_url_from_log_picks_matching_token(self):
        self._write_log("BMCD_LISTEN http://127.0.0.1:1111/?t=OLD\n"
                        "BMCD_LISTEN http://127.0.0.1:2222/?t=NEW\n")
        self.assertEqual(A.url_from_log("NEW"), "http://127.0.0.1:2222/?t=NEW")
        self.assertEqual(A.url_from_log("OLD"), "http://127.0.0.1:1111/?t=OLD")
        self.assertEqual(A.url_from_log("NOPE"), "")

    def test_url_from_log_ignores_non_local_urls(self):
        self._write_log("BMCD_LISTEN http://evil.example.com:80/?t=NEW\n")
        self.assertEqual(A.url_from_log("NEW"), "")

    def test_wait_for_session_falls_back_to_log(self):
        """会话文件写失败时，靠日志里的地址也要能开窗口。"""
        self._write_log("BMCD_LISTEN http://127.0.0.1:2222/?t=NEW\n")
        with mock.patch.object(A, "session_file",
                               lambda: os.path.join(self.tmp, "nope", "web.json")):
            url, how = A.wait_for_session("NEW", timeout=0.8)
        self.assertEqual(url, "http://127.0.0.1:2222/?t=NEW")
        self.assertEqual(how, "log")

    def test_wait_for_session_prefers_session_file(self):
        self._write_log("BMCD_LISTEN http://127.0.0.1:2222/?t=NEW\n")
        sess = os.path.join(self.tmp, "web.json")
        with open(sess, "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:3333/?t=NEW", "token": "NEW"}, fh)
        with mock.patch.object(A, "session_file", lambda: sess):
            url, how = A.wait_for_session("NEW", timeout=0.8)
        self.assertEqual(url, "http://127.0.0.1:3333/?t=NEW")
        self.assertEqual(how, "session")

    def test_read_session_prefers_matching_token(self):
        """上一次留下的旧会话文件不能把这次的备用文件挡在后面。"""
        # 用临时路径，别依赖 ~/.bmcd 是否存在（那条依赖会让本用例在只跑
        # tests.test_launcher 时挂掉）
        sess = os.path.join(self.tmp, "web.json")
        fallback = os.path.join(self.tmp, "bmcd", "web.json")
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        with open(sess, "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:6666/?t=OLD", "token": "OLD"}, fh)
        with open(fallback, "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:5555/?t=NEW", "token": "NEW"}, fh)
        with mock.patch.object(A, "session_file", lambda: sess), \
                mock.patch.object(A, "fallback_session_file", lambda: fallback):
            self.assertEqual(A.read_session("NEW")["token"], "NEW")
            self.assertEqual(A.read_session("OLD")["token"], "OLD")
            # 不带 token 时按顺序取第一个能读的
            self.assertEqual(A.read_session()["token"], "OLD")

    def test_wait_for_session_reads_fallback_file(self):
        with open(A.fallback_session_file(), "w", encoding="utf-8") as fh:
            json.dump({"url": "http://127.0.0.1:5555/?t=NEW", "token": "NEW"}, fh)
        url, how = A.wait_for_session("NEW", timeout=0.8)
        self.assertEqual((url, how), ("http://127.0.0.1:5555/?t=NEW", "session"))

    def test_wait_for_session_ignores_other_token(self):
        self._write_log("BMCD_LISTEN http://127.0.0.1:2222/?t=OTHER\n")
        with mock.patch.object(A, "session_file",
                               lambda: os.path.join(self.tmp, "nope.json")):
            url, how = A.wait_for_session("NEW", timeout=0.5)
        self.assertEqual((url, how), ("", ""))

    def test_falls_back_to_system_python_when_venv_impossible(self):
        """连 venv 都建不出来，也要返回一个能用系统解释器，而不是空字符串之外的东西。"""
        with mock.patch.object(A, "_capture", lambda cmd, timeout=25: (1, "", "boom")), \
             mock.patch.object(A, "_resolve_exe", lambda base: "/x/pythonw.exe"):
            got = A.ensure_backend_python()
        self.assertEqual(got, "/x/pythonw.exe")


class TestBatchDiagnostics(unittest.TestCase):
    """bmcd.cmd：venv 建不起来时，ifaces/selftest 仍然要能跑（系统 Python 兜底）。

    Microsoft Store 版 Python 上 `python -m venv` 经常失败，而这两个子命令
    正是排查「网卡下拉为空」的唯一命令行手段 —— 不能跟着 venv 一起死。
    """

    def setUp(self):
        with open(os.path.join(ROOT, "bmcd.cmd"), encoding="utf-8",
                  errors="replace") as fh:
            self.text = fh.read()

    def test_diagnostics_have_system_python_fallback(self):
        self.assertIn(":sysdiag", self.text)
        self.assertIn('if "%CMD%"=="ifaces" goto :sysdiag', self.text)
        self.assertIn('if "%CMD%"=="selftest" goto :sysdiag', self.text)
        self.assertIn("py -3 -m bmcdhcp %*", self.text)
        self.assertIn("python -m bmcdhcp %*", self.text)

    def test_diagnostics_branch_before_venv_build(self):
        # 分流点必须在建 venv 之前，否则「venv 建不起来」时还是走不到诊断分支
        self.assertLess(self.text.index("goto :sysdiag"), self.text.index(":make_venv"))

    def test_sysdiag_prefers_venv_then_falls_back(self):
        block = self.text[self.text.index(":sysdiag"):]
        block = block[:block.index(":verify")]
        self.assertLess(block.index('if exist "%RUNPY%"'), block.index("where py"))
        self.assertLess(block.index("where py"), block.index("where python"))
        self.assertIn("goto :nopython", block)

    def test_no_errorlevel_expansion_inside_parenthesised_block(self):
        """括号块里的 %errorlevel% 在解析时就展开了（那是 if exist / where 的 0）。

        `:sysdiag` 三个块原来是 `exit /b %errorlevel%`，python 的退出码被丢掉 ——
        只能写不带参数的 `exit /b`（原样保留当前 ERRORLEVEL）。
        """
        depth = 0
        for num, line in enumerate(self.text.splitlines(), 1):
            stripped = line.strip()
            if depth > 0 and "%errorlevel%" in stripped:
                self.fail("第 %d 行在括号块里用了 %%errorlevel%%（解析时展开，拿到旧值）：%s"
                          % (num, stripped))
            # `) else (` 这种同一行又收又开，两个都要算
            depth += (1 if stripped.endswith("(") else 0)
            depth -= (1 if stripped.startswith(")") else 0)
            self.assertGreaterEqual(depth, 0, "第 %d 行括号收多了：%s" % (num, stripped))
        self.assertEqual(depth, 0, "括号没配平，扫描结果不可信")

    def test_sysdiag_exit_keeps_child_exit_code(self):
        # 注意 `:sysdiag` 前面还有 `goto :sysdiag`，要定位到标签行本身
        start = self.text.index("\n:sysdiag\n") + 1
        block = self.text[start:]
        block = block[:block.index(":verify")]
        self.assertEqual(block.count("exit /b\n"), 3, block)
        self.assertNotIn("exit /b %errorlevel%", block)

    def test_verify_still_works_without_python(self):
        # verify 只用 bat 自己的 exist 判断，必须在 venv 逻辑之前
        self.assertLess(self.text.index('if "%CMD%"=="verify" goto :verify'),
                        self.text.index(":sysdiag"))


class TestStorePythonDiscovery(unittest.TestCase):
    r"""Microsoft Store 版 Python 只装在 %LOCALAPPDATA%\Microsoft\WindowsApps。"""

    def test_system_pythons_finds_store_alias(self):
        local = r"C:\Users\U\AppData\Local"
        wanted = os.path.join(local, "Microsoft", "WindowsApps", "python3.13.exe")

        def fake_isfile(path):
            return path == wanted

        with mock.patch.dict(os.environ, {"LOCALAPPDATA": local}), \
                mock.patch.object(A.os.path, "isfile", side_effect=fake_isfile):
            found = A.system_pythons()
        self.assertTrue(any(entry and entry[0] == wanted for entry in found))

    def test_system_pythons_keeps_py_and_python_fallbacks(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": r"C:\nope"}), \
                mock.patch.object(A.os.path, "isfile", return_value=False):
            found = A.system_pythons()
        self.assertIn(["py", "-3"], found)
        self.assertIn(["python"], found)


if __name__ == "__main__":
    unittest.main()
