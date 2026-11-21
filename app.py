#!/usr/bin/env python3
"""图形界面的启动器：确保后台服务在跑，然后开一个独立窗口。

流程：
  1. 读 ~/.bmcd/web.json / 探 127.0.0.1:8770，如果后台已经在跑 → 直接连上；
  2. 否则用 osascript 以管理员身份把它拉起来（会弹系统授权框）；
  3. 等 /api/ping 就绪；
  4. 用 Chrome/Edge/Brave 的 --app 模式开一个没有地址栏的窗口（没有就用默认浏览器）；
  5. 退出时（Ctrl-C / 关闭）通知后台停止并还原网卡。

参数：
  --port N          固定端口（默认 8770，被占用时自动换）
  --gui chrome|browser|none
  --no-elevate      不用管理员权限直接起（调试用，改网卡会失败）
  --print-url       只打印 URL 不打开窗口
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
if os.path.join(ROOT, "src") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "src"))
from bmcdhcp.stateio import atomic_write_json
DEFAULT_PORT = 8770
HOME_DIR = os.environ.get("BMCD_HOME") or os.path.expanduser("~")
SUPPORT_DIR = os.path.join(HOME_DIR, "Library/Application Support/BMC DHCP")
RUNTIME_DIR = os.path.join(SUPPORT_DIR, "runtime")

# macOS 的 TCC 会挡住 root 进程读这几个目录，提权后的后台必须从别处跑
TCC_DIRS = (
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Library/Mobile Documents"),
)
LOG_FILE = os.path.join(HOME_DIR, "Library/Logs/BMC DHCP.log")
SESSION_FILE = os.environ.get("BMCD_SESSION_FILE") or os.path.join(HOME_DIR, ".bmcd/web.json")

# 本地 API 必须直连：某些系统代理会连环回地址也代理，造成 502，甚至泄露令牌。
LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))

LAST_SPAWN_ERROR = ""

CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
]


# ----------------------------------------------------------------------
# 小工具
# ----------------------------------------------------------------------

def log(message: str) -> None:
    line = "[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
    print(line, file=sys.stderr, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def log_tail(lines: int = 6) -> str:
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as fh:
            tail = [l.rstrip() for l in fh.readlines() if l.strip()][-lines:]
        return "\n".join(tail)
    except OSError:
        return ""


def alert(title: str, text: str) -> None:
    """Finder 里双击启动时没有终端，用系统弹窗把话说清楚。"""
    if os.environ.get("BMCD_NATIVE") == "1":
        # 原生窗口负责展示错误；不能让另一个脚本弹窗阻塞就绪握手。
        log("%s：%s" % (title, text))
        return
    script = 'display alert %s message %s as critical' % (
        json.dumps(title, ensure_ascii=False), json.dumps(text, ensure_ascii=False)
    )
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pass


def needs_staging() -> bool:
    root = os.path.realpath(ROOT)
    return any(root == d or root.startswith(d + os.sep) for d in TCC_DIRS)


def ensure_runtime() -> str:
    """把运行时复制到 Application Support，root 才读得到。

    这次踩的坑：项目放在 ~/Documents 下，提权后的 root 进程读
    .venv/pyvenv.cfg 直接 EPERM（TCC），表现为"后台启动超时"。
    src 每次同步（很小），venv 只在缺失时复制一次（约 40MB）。
    """
    import shutil

    os.makedirs(RUNTIME_DIR, mode=0o700, exist_ok=True)
    if getattr(sys, "frozen", False):
        # 每次构建使用独立目录，不覆盖正在运行的旧后台；App 可从任意目录启动。
        with open(sys.executable, "rb") as fh:
            identity = hashlib.sha256(fh.read())
        build_id = os.path.join(os.path.dirname(sys.executable), "build-id.txt")
        if os.path.isfile(build_id):
            with open(build_id, "rb") as fh:
                identity.update(fh.read())
        digest = identity.hexdigest()[:20]
        dest = os.path.join(RUNTIME_DIR, "bundle-" + digest)
        if os.path.isfile(os.path.join(dest, os.path.basename(sys.executable))):
            return dest
        temp = tempfile.mkdtemp(prefix=".bundle-", dir=RUNTIME_DIR)
        try:
            shutil.copytree(os.path.dirname(sys.executable), temp, dirs_exist_ok=True,
                            symlinks=True)
            try:
                os.rename(temp, dest)
            except FileExistsError:
                if not os.path.isfile(os.path.join(dest, os.path.basename(sys.executable))):
                    raise
        finally:
            if os.path.isdir(temp):
                shutil.rmtree(temp)
        return dest

    dst_src = os.path.join(RUNTIME_DIR, "src")
    if os.path.isdir(dst_src):
        shutil.rmtree(dst_src)
    shutil.copytree(os.path.join(ROOT, "src"), dst_src)

    src_venv = os.path.join(ROOT, ".venv")
    dst_venv = os.path.join(RUNTIME_DIR, ".venv")
    if os.path.isdir(src_venv) and not os.path.exists(os.path.join(dst_venv, "bin", "python")):
        log("首次提权运行：复制 Python 环境到 %s（约 40MB）" % dst_venv)
        try:
            shutil.copytree(src_venv, dst_venv, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        except OSError as exc:
            log("复制 venv 失败: %s" % exc)
    return RUNTIME_DIR


def python_for_backend() -> str:
    venv = os.path.join(ROOT, ".venv", "bin", "python")
    if os.path.exists(venv):
        return venv
    return sys.executable


def backend_command(base: str, port: int) -> list[str]:
    """源码运行与随包运行共用同一启动协议，不从冻结程序执行 `-m`。"""
    if getattr(sys, "frozen", False):
        executable = (sys.executable if base == ROOT else
                      os.path.join(base, os.path.basename(sys.executable)))
        return [executable, "--backend", "web", "--port", str(port)]
    py = os.path.join(base, ".venv", "bin", "python")
    if not os.path.exists(py):
        py = python_for_backend()
    return [py, "-m", "bmcdhcp", "web", "--port", str(port)]


def port_free(port: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def pick_port(preferred: int) -> int:
    if preferred and port_free(preferred):
        return preferred
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def ping(port: int, timeout: float = 0.8):
    try:
        with LOCAL_HTTP.open("http://127.0.0.1:%d/api/ping" % port, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, dict) and data.get("ok") is True and data.get("version"):
                return data
    except (urllib.error.URLError, OSError, ValueError):
        return None


def token_valid(port: int, token: str) -> bool:
    req = urllib.request.Request("http://127.0.0.1:%d/api/state" % port,
                                 headers={"X-BMCD-Token": token})
    try:
        with LOCAL_HTTP.open(req, timeout=2) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        exc.close()
        return False
    except (urllib.error.URLError, OSError, ValueError):
        return False


def read_session():
    try:
        st = os.stat(SESSION_FILE)
        if st.st_uid != os.geteuid() or (st.st_mode & 0o077):
            return None          # 属主不对或者谁都可读：不认
        with open(SESSION_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("port") and data.get("token"):
            return data
    except (OSError, ValueError):
        pass
    return None


def write_session(port: int, token: str, pid: int = 0) -> None:
    """会话文件只有自己能读（里面是访问令牌）。"""
    try:
        os.makedirs(os.path.dirname(SESSION_FILE), mode=0o700, exist_ok=True)
        payload = {"url": "http://127.0.0.1:%d/?t=%s" % (port, token),
                   "port": port, "token": token, "pid": pid, "ts": time.time()}
        atomic_write_json(SESSION_FILE, payload)
    except OSError as exc:
        log("写会话文件失败: %s" % exc)


def clear_session() -> None:
    try:
        os.remove(SESSION_FILE)
    except OSError:
        pass


def post_quit(port: int, token: str) -> None:
    req = urllib.request.Request(
        "http://127.0.0.1:%d/api/quit" % port,
        data=b"{}",
        headers={"Content-Type": "application/json", "X-BMCD-Token": token},
        method="POST",
    )
    try:
        with LOCAL_HTTP.open(req, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, OSError):
        pass


# ----------------------------------------------------------------------
# 拉起后台
# ----------------------------------------------------------------------

def spawn_backend(port: int, token: str, elevate: bool) -> bool:
    global LAST_SPAWN_ERROR
    LAST_SPAWN_ERROR = ""
    base = ROOT
    if elevate and os.geteuid() != 0 and needs_staging():
        try:
            base = ensure_runtime()
        except OSError as exc:
            LAST_SPAWN_ERROR = str(exc)
            log("准备运行时失败: %s" % exc)
            return False
        log("项目在受 TCC 保护的目录里，改用运行时副本：%s" % base)
    for path in (os.path.dirname(LOG_FILE), os.path.dirname(SESSION_FILE)):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            pass
    try:
        fd = os.open(LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(LOG_FILE, 0o600)
    except OSError as exc:
        LAST_SPAWN_ERROR = str(exc)
        log("日志文件不可写: %s" % exc)
        return False

    script = "\n".join([
        "#!/bin/sh",
        "export PYTHONPATH=%s" % sh_quote(os.path.join(base, "src")),
        "export BMCD_TOKEN=%s" % sh_quote(token),        # 别走命令行，ps 看得见
        "export BMCD_HOME=%s" % sh_quote(HOME_DIR),  # root 的 ~ 是 /var/root
        "export BMCD_SESSION_FILE=%s" % sh_quote(SESSION_FILE),
        "export BMCD_DESKTOP=1",
        "export PYINSTALLER_RESET_ENVIRONMENT=1",
        'trap \'/bin/rm -f -- "$0"\' EXIT',
        "cd %s || exit 1" % sh_quote(base),
        '/bin/rm -f -- "$0"',
        "exec " + " ".join(sh_quote(arg) for arg in backend_command(base, port)),
        "",
    ])

    fd, path = tempfile.mkstemp(prefix="bmcd-", suffix=".sh")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(script)
    os.chmod(path, 0o700)
    child = None

    if elevate and os.geteuid() != 0:
        # 注意：这里不能用 nohup —— 在 do shell script 的无 TTY 环境里
        # macOS 的 nohup 会报 "can't detach from console" 然后什么都不做。
        inner = "/bin/sh %s >>%s 2>&1 < /dev/null &" % (sh_quote(path), sh_quote(LOG_FILE))
        apple = 'do shell script "%s" with administrator privileges' % (
            inner.replace("\\", "\\\\").replace('"', '\\"')
        )
        try:
            proc = subprocess.run(["osascript", "-e", apple], capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.SubprocessError) as exc:
            os.unlink(path) if os.path.exists(path) else None
            log("osascript 调用失败: %s" % exc)
            return False
        if proc.returncode != 0:
            os.unlink(path) if os.path.exists(path) else None
            LAST_SPAWN_ERROR = (proc.stderr.strip() or proc.stdout.strip())
            log("提权失败: %s" % LAST_SPAWN_ERROR)
            return False
    else:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as logfh:
                child = subprocess.Popen(
                    ["/bin/sh", path],
                    stdout=logfh,
                    stderr=logfh,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
        except OSError as exc:
            os.unlink(path) if os.path.exists(path) else None
            log("启动后台失败: %s" % exc)
            return False

    deadline = time.time() + 30
    while time.time() < deadline:
        info = ping(port)
        if info and token_valid(port, token):
            log("后台已就绪: 127.0.0.1:%d" % port)
            write_session(port, token, int(info.get("pid") or 0))
            return True
        if child is not None and child.poll() is not None:
            log("后台在就绪前退出，退出码 %d" % child.returncode)
            return False
        time.sleep(0.35)
    log("后台启动超时，日志见 %s" % LOG_FILE)
    return False


def sh_quote(text: str) -> str:
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


# ----------------------------------------------------------------------
# 开窗口
# ----------------------------------------------------------------------

def open_window(url: str, gui: str) -> bool:
    if gui in ("auto", "chrome"):
        for path in CHROME_PATHS:
            if os.path.exists(path):
                profile = os.path.join(SUPPORT_DIR, "chrome-profile")
                os.makedirs(profile, exist_ok=True)
                args = [
                    path,
                    "--app=" + url,
                    "--window-size=1240,880",
                    "--user-data-dir=" + profile,
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-features=Translate,MediaRouter",
                    "--disable-background-mode",
                ]
                try:
                    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
                    log("窗口已打开（%s）" % os.path.basename(path))
                    return True
                except OSError as exc:
                    log("打开 %s 失败: %s" % (path, exc))
        if gui == "chrome":
            return False
    try:
        subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("已用默认浏览器打开")
        return True
    except OSError as exc:
        log("打开浏览器失败: %s" % exc)
        return False


# ----------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="BMC DHCP 图形界面启动器")
    parser.add_argument("--version", action="version", version="BMC DHCP %s" % __import__("bmcdhcp").__version__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--gui", default="auto", choices=["auto", "chrome", "browser", "none"])
    parser.add_argument("--no-elevate", action="store_true", help="不用管理员权限（仅调试）")
    parser.add_argument("--print-url", action="store_true")
    parser.add_argument("--keep", action="store_true", help="启动后不等待，立刻退出")
    args = parser.parse_args()

    session = read_session()
    url = ""
    port = 0
    token = ""

    if session:
        port = int(session.get("port") or 0)
        token = str(session.get("token") or "")
        if port and ping(port) and token_valid(port, token):
            url = "http://127.0.0.1:%d/?t=%s" % (port, token)
            log("复用已在运行的后台：127.0.0.1:%d" % port)

    if not url:
        port = pick_port(args.port)
        token = session.get("token") if session and session.get("port") == port else ""
        if not token:
            import secrets

            token = secrets.token_urlsafe(24)

        write_session(port, token)          # 先落盘，App 重启时能复用
        elevated_ok = spawn_backend(port, token, elevate=not args.no_elevate)
        degraded = False
        if not elevated_ok:
            # 提权路径失败：再给 5 秒（root 进程可能只是慢），然后就降级到自己跑，
            # 至少让界面能打开、能看诊断，别把一个错误框怼在用户脸上。
            for _ in range(10):
                if ping(port) and token_valid(port, token):
                    elevated_ok = True
                    break
                time.sleep(0.5)
        if not elevated_ok and ("-128" in LAST_SPAWN_ERROR or "canceled" in LAST_SPAWN_ERROR.lower()):
            alert("BMC DHCP 需要管理员授权",
                  "你取消了授权，所以后台服务没法启动。\n\n"
                  "改网卡地址、抓 DHCP 包都必须管理员权限。\n"
                  "再双击一次 App，在系统弹框里输入密码即可。")
            clear_session()
            return 1
        if not elevated_ok:
            log("后台启动失败，换端口后用当前用户重试")
            port = pick_port(0)
            write_session(port, token)
            elevated_ok = spawn_backend(port, token, elevate=False)
            degraded = not args.no_elevate
        if not elevated_ok:
            tail = log_tail() or "（日志是空的）"
            alert("BMC DHCP 启动失败",
                  "后台服务没能启动。\n\n最近日志（%s）：\n%s\n\n"
                  "常见原因：授权框被取消了，或者端口被占用。"
                  % (LOG_FILE, tail[-600:]))
            clear_session()
            return 1
        if degraded:
            alert("BMC DHCP 已用普通权限启动",
                  "没能拿到管理员授权，界面可以正常用，但改网卡地址和抓包会失败。\n\n"
                  "要完整功能：退出后重新双击 App，并在系统弹框里输入密码。")
        url = "http://127.0.0.1:%d/?t=%s" % (port, token)

    print(url, flush=True)
    if args.gui == "none":
        print("后台在跑，用浏览器打开上面的地址即可。Ctrl-C 结束。", file=sys.stderr, flush=True)
    else:
        open_window(url, args.gui)

    if args.keep:
        return 0

    # 留在前台，Ctrl-C / Cmd-Q 时把后台也收掉
    import signal

    def _bye(*_: object) -> None:
        post_quit(port, token)
        clear_session()
        os._exit(0)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _bye)
        except (ValueError, OSError):
            pass

    try:
        while True:
            time.sleep(1)
            if not ping(port):
                log("后台已退出")
                break
    except KeyboardInterrupt:
        pass
    finally:
        post_quit(port, token)
        clear_session()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001  双击启动时没有终端，至少留下记录
        import traceback

        detail = traceback.format_exc()
        log("未捕获异常：\n%s" % detail)
        alert("BMC DHCP 出错了", detail.strip().splitlines()[-1][:300])
        raise
