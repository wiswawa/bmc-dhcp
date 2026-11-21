"""Windows 图形界面启动器：双击 `BMC DHCP.cmd` 时跑的就是这个。

跟 mac 版的 app.py 一样，架构是「用户进程开窗口 + 管理员进程跑后端」：

  1. 用普通权限起一个没有控制台的窗口进程（Edge/Chrome 的 --app 窗口）；
  2. 后端需要管理员权限（改网卡地址、抓包），所以用 ShellExecuteW(runas)
     拉起一个**独立**的 pythonw 进程 —— 也就是弹一次 UAC，输一次密码；
  3. 两端靠 `~/.bmcd/web.json` 里的一次性令牌接头（令牌不进命令行，
     避免被别的进程从命令行里看到）。

后端崩了会把 traceback 写到 %LOCALAPPDATA%\\bmcd\\backend.log，启动器
超时后把日志尾巴弹出来 —— 不让你对着一个「没反应」的窗口猜。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time

APPNAME = "BMC DHCP"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")


def bundled_backend() -> str:
    return os.path.join(os.path.dirname(sys.executable), "bmcd.exe")


# ----------------------------------------------------------------------
# 路径 / 日志
# ----------------------------------------------------------------------

def _flags() -> int:
    """CREATE_NO_WINDOW：只在 Windows 上有效，别的平台必须是 0。"""
    return 0x08000000 if os.name == "nt" else 0


def bmcd_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    path = os.path.join(base, "bmcd")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def log_path() -> str:
    return os.path.join(bmcd_dir(), "backend.log")


def launcher_log(text: str) -> None:
    try:
        with open(os.path.join(bmcd_dir(), "launcher.log"), "a", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text))
    except OSError:
        pass


def log_tail(path: str, lines: int = 14) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.readlines()
    except OSError:
        return ""
    return "".join(data[-lines:]).strip()


# 包完整性：这些文件少一个，界面/后端就是残的。
# （最典型的是压缩包只复制了一部分，ui/index.html 没解出来 → 打开是一页白屏）
REQUIRED_FILES = (
    os.path.join("src", "bmcdhcp", "__init__.py"),
    os.path.join("src", "bmcdhcp", "webapp.py"),
    os.path.join("src", "bmcdhcp", "session.py"),
    os.path.join("src", "bmcdhcp", "scan.py"),
    os.path.join("src", "bmcdhcp", "winnet.py"),
    os.path.join("src", "bmcdhcp", "ui", "index.html"),
    "app_win.py",
)


def missing_package_files() -> list:
    """返回缺失的包内文件（绝对路径）。"""
    if getattr(sys, "frozen", False):
        paths = (bundled_backend(), os.path.join(HERE, "bmcdhcp", "ui", "index.html"))
        return [path for path in paths if not os.path.isfile(path)]
    out = []
    for rel in REQUIRED_FILES:
        path = os.path.join(HERE, rel)
        if not os.path.isfile(path):
            out.append(path)
    return out


def session_file() -> str:
    return os.path.join(os.path.expanduser("~"), ".bmcd", "web.json")


def fallback_session_file() -> str:
    """备用会话文件：紧挨着 backend.log。

    那个目录后端一定写得进去（log 就在那儿），主路径因为权限/占位文件
    写不进时，这条能保住「双击即用」。
    """
    return os.path.join(bmcd_dir(), "web.json")


# ----------------------------------------------------------------------
# 找 Python / 建运行环境
# ----------------------------------------------------------------------

def venv_home() -> str:
    return os.path.join(bmcd_dir(), "venv")


def venv_python(windowless: bool = True) -> str:
    root = os.path.join(venv_home(), "Scripts")
    return os.path.join(root, "pythonw.exe" if windowless else "python.exe")


def system_pythons():
    """按可能性列出可用来建 venv 的 python。"""
    out = []
    local = os.environ.get("LOCALAPPDATA") or ""
    for ver in ("313", "312", "311", "310", "39"):
        cand = os.path.join(local, "Programs", "Python", "Python" + ver, "python.exe")
        if os.path.isfile(cand):
            out.append([cand])
    for prog in (os.environ.get("ProgramFiles") or r"C:\Program Files",
                 os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"):
        for ver in ("313", "312", "311", "310"):
            cand = os.path.join(prog, "Python" + ver, "python.exe")
            if os.path.isfile(cand):
                out.append([cand])
    # Microsoft Store 版 Python（Python Software Foundation 的 MSIX 包）只装在这里，
    # 上面两个路径都找不到它。它的 venv 经常建不起来（ensure_backend_python 会
    # 自动退回系统解释器继续跑），但至少要能**发现**它 —— 否则会提示用户
    # 「没找到 Python 3，去官网装一个」，而他明明装了。
    for name in ("python3.13.exe", "python3.12.exe", "python3.exe", "python.exe"):
        cand = os.path.join(local, "Microsoft", "WindowsApps", name)
        if os.path.isfile(cand):
            out.append([cand])
            break
    # py 启动器 / PATH 里的 python 作为兜底
    out.append(["py", "-3"])
    out.append(["python"])
    out.append([sys.executable])
    return out


def _capture(cmd, timeout: float = 25.0):
    """跑子进程，返回 (rc, out, err)，不弹窗、不抛异常、不等 stdin。"""
    try:
        proc = subprocess.run(list(cmd), capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, creationflags=_flags())
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)
    return (proc.returncode,
            (proc.stdout or b"").decode("utf-8", "replace").strip(),
            (proc.stderr or b"").decode("utf-8", "replace").strip())


def _venv_cfg_home(cfg_path: str) -> str:
    """pyvenv.cfg 里的 home= 指向当初建它的那个 Python。"""
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, sep, val = line.partition("=")
                if sep and key.strip().lower() == "home":
                    return val.strip()
    except OSError:
        pass
    return ""


def venv_problem() -> str:
    """venv 能不能用："" 表示能用，否则返回一句原因。

    **必须先做文件检查，再考虑运行里面的 exe。** venv 的 python.exe 是个
    「转发器」：找不到 pyvenv.cfg 时会弹一个原生 MessageBox
    （"Python venv launcher is sorry to say … failed to locate pyvenv.cfg"）
    然后停在那里等人点确定 —— 这就是「双击 App 只弹一句英文错误，别的什么
    都不发生」的来源。文件不对就**不运行它**，直接判死刑重建，用户永远看
    不到那个框。
    """
    home = venv_home()
    cfg = os.path.join(home, "pyvenv.cfg")
    plain = venv_python(windowless=False)
    quiet = venv_python(windowless=True)
    if not os.path.isdir(home):
        return "还没建"
    if not os.path.isfile(cfg):
        return "缺少 pyvenv.cfg（venv 只建了一半）"
    base = _venv_cfg_home(cfg)
    if base and not os.path.isdir(base):
        return "建它的 Python 已经不在：%s" % base
    if not os.path.isfile(plain):
        return "缺少 Scripts\\python.exe"
    if not os.path.isfile(quiet):
        return "缺少 Scripts\\pythonw.exe"
    rc, out, err = _capture([plain, "-c", "import sys;print(sys.prefix)"], timeout=12)
    if rc != 0:
        return "python.exe 起不来：%s" % ((err or out or "rc=%d" % rc).strip()[:160])
    if os.path.normcase(os.path.abspath(home)) != os.path.normcase(os.path.abspath(out.strip())):
        return "sys.prefix 不是这个 venv（%s）" % out.strip()[:120]
    return ""


def _rmtree(path: str) -> None:
    """删目录；Windows 上有文件被占用删不掉时，改名丢下，下次不再用它。"""
    import shutil

    for _ in range(2):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.isdir(path):
            return
        time.sleep(0.4)
    try:
        os.rename(path, "%s.broken-%d" % (path, int(time.time())))
    except OSError:
        pass


def _resolve_exe(base) -> str:
    """把「怎么调 python」解析成真实 exe 路径，优先同目录的无窗口版。"""
    if len(base) == 1 and os.path.isfile(base[0]):
        cand = base[0]
    else:
        rc, out, _ = _capture(list(base) + ["-c", "import sys;print(sys.executable)"])
        if rc != 0 or not out:
            return ""
        cand = out.splitlines()[-1].strip()
    if not os.path.isfile(cand):
        return ""
    quiet = os.path.join(os.path.dirname(cand), "pythonw.exe")
    return quiet if os.path.isfile(quiet) else cand


def ensure_backend_python(force: bool = False) -> str:
    """返回后端要用的解释器：好 venv > 新建 venv > 系统 Python。

    绝不返回「文件存在但起不来」的解释器 —— 那正是 Windows 上
    「failed to locate pyvenv.cfg」那个框的成因。
    """
    if getattr(sys, "frozen", False):
        return bundled_backend() if os.path.isfile(bundled_backend()) else ""
    problem = venv_problem()
    if not force and not problem:
        launcher_log("venv 可用：%s" % venv_home())
        return venv_python()
    if os.path.isdir(venv_home()):
        launcher_log("venv 不可用（%s），删掉重建" % problem)
        _rmtree(venv_home())

    for base in system_pythons():
        exe = _resolve_exe(base)
        if not exe:
            continue
        launcher_log("用 %s 建 venv" % exe)
        rc, out, err = _capture([exe, "-m", "venv", venv_home()], timeout=300)
        if rc != 0:
            launcher_log("建 venv 失败：%s" % ((err or out)[:300]))
            continue
        problem = venv_problem()
        if problem:
            launcher_log("用 %s 建完还是不可用：%s" % (exe, problem))
            _rmtree(venv_home())
            continue
        plain = venv_python(windowless=False)
        rc, out, err = _capture([plain, "-m", "pip", "install", "-q", "--no-input",
                                 "--disable-pip-version-check", "scapy>=2.5"], timeout=900)
        if rc != 0:
            # 装不上 scapy 也能用 udp 引擎发 DHCP，先跑起来
            launcher_log("装 scapy 失败（不影响基本收发）：%s" % ((err or out)[:300]))
        launcher_log("venv 就绪：%s" % venv_home())
        return venv_python()

    # 连 venv 都建不出来：直接用系统解释器跑后端（没 scapy 也能发 DHCP）
    for base in system_pythons():
        exe = _resolve_exe(base)
        if exe:
            launcher_log("退回系统 Python：%s" % exe)
            return exe
    return ""


# ----------------------------------------------------------------------
# 后端 bootstrap：写一个临时 py，让 pythonw 自己带环境起来
# ----------------------------------------------------------------------

BOOTSTRAP = '''# -*- coding: utf-8 -*-
"""由 app_win.py 生成，只跑一次：把环境写进进程，然后起 HTTP 后端。"""
import os
import sys
import time

LOG = {log!r}


def main():
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        log = open(LOG, "a", encoding="utf-8", buffering=1)
    except OSError:
        log = None
    if log is not None:
        sys.stdout = log
        sys.stderr = log
    print("\\n=== %s 后端启动 (pid %s) ===" % (time.strftime("%Y-%m-%d %H:%M:%S"), os.getpid()))
    print("解释器 %s" % sys.executable)
    sys.path.insert(0, {src!r})
    os.environ["BMCD_TOKEN"] = {token!r}
    os.environ["BMCD_HOME"] = {home!r}
    # 会话文件也由启动器指定绝对路径：提权进程的 ~ 未必等于用户的 ~
    # （UAC 换账号、Microsoft Store 版 Python 的目录重定向都会差）
    os.environ["BMCD_SESSION_FILE"] = {session!r}
    os.environ["BMCD_SESSION_FALLBACK"] = {session2!r}
    try:
        from bmcdhcp import webapp
        return webapp.main(host="127.0.0.1", port=0, print_url=True,
                           token=os.environ["BMCD_TOKEN"])
    except SystemExit:
        raise
    except BaseException:
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def write_bootstrap(token: str) -> str:
    if getattr(sys, "frozen", False):
        from bmcdhcp.win_desktop import write_config
        return write_config(bmcd_dir(), token=token, home=os.path.expanduser("~"),
                            session=session_file(), fallback=fallback_session_file(), log=log_path())
    path = os.path.join(bmcd_dir(), "backend_boot.py")
    text = BOOTSTRAP.format(log=log_path(), src=SRC, token=token,
                            home=os.path.expanduser("~"),
                            session=session_file(),
                            session2=fallback_session_file())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:                          # 只让当前用户能读（里面有令牌）
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# ----------------------------------------------------------------------
# 提权 / 读会话
# ----------------------------------------------------------------------

def elevate(pythonw: str, script: str) -> int:
    """返回 ShellExecute 的返回值：>32 成功；5 = 用户点了「否」。

    返回类型必须显式声明成 c_void_p：默认 c_int 在句柄高位为 1 时是负数，
    会把「成功」误判成失败（然后弹一个假的失败框）。
    """
    try:
        import ctypes
    except Exception:                 # noqa: BLE001
        return 0
    SW_HIDE = 0
    try:
        shell32 = ctypes.windll.shell32
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        shell32.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                          ctypes.c_wchar_p, ctypes.c_wchar_p,
                                          ctypes.c_wchar_p, ctypes.c_int]
        arguments = (["--desktop-backend", script] if getattr(sys, "frozen", False) else [script])
        raw = shell32.ShellExecuteW(None, "runas", pythonw, subprocess.list2cmdline(arguments),
                                    os.path.dirname(script), SW_HIDE)
        return int(raw or 0)
    except Exception:                 # noqa: BLE001
        return 0


def _load_session(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def read_session(token: str = ""):
    """读会话文件：主路径优先，读不到就看备用路径（挨着 backend.log 那个）。

    给了 `token` 时**优先返回 token 对得上的那一份**：否则上一次运行留下的
    旧会话文件会把这次的备用文件挡在后面，表现就是「明明起来了却等超时」。
    """
    stale = None
    for path in (session_file(), fallback_session_file()):
        data = _load_session(path)
        if not data:
            continue
        if not token:
            return data
        if str(data.get("token") or "") == token:
            return data
        stale = stale or data
    return stale


def backend_alive(url: str, timeout: float = 1.5) -> bool:
    """会话文件里的后端还活着吗？（拿 /api/ping 试一下）"""
    import urllib.request

    base = url.split("/?")[0].rstrip("/")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(base + "/api/ping", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:                 # noqa: BLE001
        return False


def url_from_log(token: str) -> str:
    """从 backend.log 里捞这一次的 BMCD_LISTEN。

    后端每次启动都会打 `BMCD_LISTEN http://127.0.0.1:PORT/?t=<token>`。
    这条通道比会话文件可靠：日志是追加写的，我们本来就读得到（失败时
    弹框里显示的就是它）。会话文件写失败/写到别处时，靠它救回来。
    """
    needle = "t=%s" % token
    try:
        with open(log_path(), "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-400:]
    except OSError:
        return ""
    for line in reversed(lines):
        text = line.strip()
        if not text.startswith("BMCD_LISTEN "):
            continue
        url = text.split(" ", 1)[1].strip()
        if needle in url and (url.startswith("http://127.0.0.1:")
                              or url.startswith("http://localhost:")):
            return url
    return ""


def wait_for_session(token: str, timeout: float = 35.0):
    """等后端就绪，返回 (url, 来源)。来源是 "session" / "log" / ""。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = read_session(token)
        if data and str(data.get("token") or "") == token:
            url = str(data.get("url") or "")
            if url.startswith("http://127.0.0.1:") or url.startswith("http://localhost:"):
                return url, "session"
        from_log = url_from_log(token)
        if from_log:
            return from_log, "log"
        time.sleep(0.3)
    return "", ""


# ----------------------------------------------------------------------
# 开窗口
# ----------------------------------------------------------------------

def browser_candidates():
    local = os.environ.get("LOCALAPPDATA") or ""
    prog = os.environ.get("ProgramFiles") or r"C:\Program Files"
    prog86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    return [
        os.path.join(prog, "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(prog86, "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(prog, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(prog86, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
    ]


def open_window(url: str) -> bool:
    profile = os.path.join(bmcd_dir(), "browser-profile")
    for exe in browser_candidates():
        if not os.path.isfile(exe):
            continue
        kwargs = {"creationflags": 0x00000008} if os.name == "nt" else {}
        try:
            subprocess.Popen([exe, "--app=%s" % url, "--window-size=1240,880",
                              "--user-data-dir=%s" % profile,
                              "--no-first-run", "--no-default-browser-check"], **kwargs)
            launcher_log("opened with %s" % exe)
            return True
        except OSError:
            continue
    try:
        os.startfile(url)     # 实在没有 Chrome/Edge，就用默认浏览器
        launcher_log("opened with default browser")
        return True
    except OSError:
        return False


# ----------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------

def main() -> int:
    if os.name != "nt":
        print("app_win.py 是给 Windows 用的；mac 上请双击 BMC DHCP.app")
        return 2
    launcher_log("==== launcher start ====")
    if getattr(sys, "frozen", False):
        launcher_log("bundled runtime=%s" % bundled_backend())
    else:
        launcher_log("venv=%s 状态=%s" % (venv_home(), venv_problem() or "可用"))

    # 先查包完整不完整：残包会在后端跑起来之后才报错（一页白屏 + 一行 JSON），
    # 那时光看现象根本猜不到是「少了个文件」。
    missing = missing_package_files()
    if missing:
        launcher_log("包不完整，缺 %d 个文件：%s" % (len(missing), missing))
        _box("程序文件不全，缺这 %d 个：\n\n%s\n\n"
             "多半是压缩包只解压/复制了一部分。\n"
             "请把 zip 重新完整解压到一个空目录（例如 C:\\bmcd），"
             "再双击 BMC DHCP.cmd。\n\n"
             "想自己核对：在本目录开命令行跑  bmcd.cmd verify"
             % (len(missing), "\n".join(missing)))
        return 3

    # 已经有一个后端在跑：直接开窗口，别起第二个
    existing = read_session()
    if existing:
        url = str(existing.get("url") or "")
        try:
            age = time.time() - float(existing.get("ts") or 0)
        except (TypeError, ValueError):
            age = 1e9                      # 会话文件坏了，当成过期的
        if url and age < 12 * 3600 and backend_alive(url):
            launcher_log("reuse existing session %s" % url)
            if open_window(url):
                return 0
            # 后端活着但窗口开不出来：把地址告诉用户就行，
            # 千万别再起一个后端（67 端口会被占，新后端会直接绑不上）
            _box("已经有一个后端在运行，但没能自动打开窗口。\n\n"
                 "请手动在浏览器里打开：\n%s" % url, error=False)
            return 0
        launcher_log("stale session ignored (%s)" % url)

    pythonw = ensure_backend_python()
    if not pythonw:
        message = ("运行环境没准备好，后端起不来。\n\n"
                   "运行环境：%s\n原因：%s\n日志：%s\n\n"
                   "两个办法：\n"
                   "1）在解压出来的目录里开一个命令行，运行  bmcd.cmd repair\n"
                   "2）到 python.org/downloads/windows 装 Python 3（安装第一屏勾上\n"
                   "   「Add python.exe to PATH」），再双击一次 BMC DHCP.cmd"
                   % (venv_home(), venv_problem() or "未知",
                      os.path.join(bmcd_dir(), "launcher.log")))
        launcher_log("放弃：没有可用解释器（%s）" % (venv_problem() or "未知"))
        _box(message)
        return 3

    token = secrets.token_urlsafe(24)
    boot = write_bootstrap(token)
    code = elevate(pythonw, boot)
    launcher_log("ShellExecuteW -> %s" % code)
    if code in (0, 5) or code <= 32:
        _box("没有拿到管理员权限（UAC 被取消或拒绝）。\n\n"
             "后端要改网卡地址、抓 DHCP 包，必须管理员权限。\n"
             "请重新双击，并在系统弹框里点「是」。")
        return 4

    url, how = wait_for_session(token, timeout=40)
    if not url:
        tail = log_tail(log_path()) or "（日志是空的：后端可能没起来）"
        _box("后端启动超时（%d 秒内没拿到地址）。\n\n"
             "日志：%s\n%s\n\n"
             "如果是杀软/防火墙拦了本机端口，或者 40 秒内 Python 还在解压/装包，"
             "可以再双击一次 —— 第二次会快很多。"
             % (40, log_path(), tail))
        return 5
    if how == "log":
        # 不弹框：会话文件这条路坏了也不影响用，别每次都拦一下。
        # 想查原因就看 backend.log 里以 BMCD_SESSION 开头的行。
        launcher_log("会话文件没读到，已改用 backend.log 里的地址 %s" % url)
    launcher_log("backend ready (via %s) %s" % (how, url))
    if not open_window(url):
        _box("后端已经在跑，但没找到能开窗口的浏览器。\n\n"
             "手动打开这个地址也可以：\n%s" % url, error=False)
    return 0


def _box(text: str, error: bool = True) -> None:
    # 用 pythonw 跑的时候 sys.stdout 是 None，print 会炸，所以先判一下
    if sys.stdout is not None:
        try:
            print(text)
        except Exception:         # noqa: BLE001
            pass
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, APPNAME, 0x10 if error else 0x40)
    except Exception:                 # noqa: BLE001
        pass


if __name__ == "__main__":
    # 用 pythonw 跑的时候没有任何控制台，万一启动器自己抛异常，
    # 用户看到的就是「双击没反应」。这里兜住，把 traceback 写进日志并弹框。
    try:
        _code = main()
    except SystemExit:
        raise
    except BaseException:                 # noqa: BLE001
        import traceback

        _tb = traceback.format_exc()
        launcher_log("启动器崩溃：\n" + _tb)
        _box("启动器自己出错了（已写到 %s）：\n\n%s"
             % (os.path.join(bmcd_dir(), "launcher.log"), _tb[-1200:]))
        _code = 9
    sys.exit(_code)
