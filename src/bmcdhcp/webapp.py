"""本地 HTTP 服务：给图形界面提供 API，并把单页前端发出去。

安全模型（这是一个以管理员权限运行的本地服务，必须当心）：
  * 只监听 127.0.0.1；
  * 校验 Host 头，挡 DNS rebinding；
  * 所有会改状态的操作必须带 X-BMCD-Token（随机令牌，App 通过 URL 传给页面）；
  * 校验 Origin，挡跨站请求；
  * 只服务内置的一个 HTML，不接受任何文件路径参数。
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

from . import __version__
from . import iface as I
from . import scan as S
from .session import Session, SessionConfig, SessionError, user_home
from .stateio import atomic_write_json

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
SESSION_FILE = os.path.join(user_home(), ".bmcd", "web.json")
MAX_BODY = 64 * 1024


def session_path() -> str:
    """会话文件位置。

    **由启动器说了算**：它通过 BMCD_SESSION_FILE 传一个绝对路径进来。
    这样「提权进程的 ~ 和普通用户的 ~ 不是同一个」这类差异就不可能咬人
    （Windows 上 UAC 换账号、Store 版 Python 的目录重定向都踩得到）。
    """
    override = os.environ.get("BMCD_SESSION_FILE")
    if override:
        return override
    return SESSION_FILE


def session_candidates() -> List[str]:
    r"""会话文件写哪 —— 按顺序试。

    1. 启动器指定的绝对路径（正常情况）；
    2. 启动器指定的**备用**路径（`%LOCALAPPDATA%\bmcd\web.json`，紧挨着
       backend.log）。这条很关键：后端既然能把 log 写进那个目录，就一定能
       写这里 —— 用户机器上真的出现过「主路径写不进去、日志却写得好好的」。
    """
    out: List[str] = []
    for key in ("BMCD_SESSION_FILE", "BMCD_SESSION_FALLBACK"):
        value = os.environ.get(key)
        if value and value not in out:
            out.append(value)
    default = SESSION_FILE
    if default not in out:
        out.append(default)
    return out


def _read_ui(name: str) -> bytes:
    path = os.path.join(UI_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


def ui_missing() -> List[str]:
    """界面资源缺了哪些（包没解压全 / 只拷了一部分文件时会这样）。"""
    need = ("index.html",)
    return [n for n in need if not os.path.isfile(os.path.join(UI_DIR, n))]


def _missing_ui_page() -> bytes:
    """界面文件丢了也**不能**给用户回一段 JSON。**

    以前 `_read_ui` 抛异常 → 前端拿到 `{"error": "服务端异常: [Errno 2] ..."}`
    整页白屏加一行原始报错，用户完全不知道该怎么办。
    """
    path = os.path.join(UI_DIR, "index.html")
    return ("""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>BMC DHCP · 包不完整</title></head>
<body style="margin:0;background:#0d1117;color:#c9d1d9;
 font:14px/1.7 -apple-system,'Segoe UI','Microsoft YaHei',sans-serif">
<div style="max-width:720px;margin:10vh auto;padding:0 24px">
<h2 style="color:#f85149;font-size:18px">界面文件不见了，包没解压完整</h2>
<p>后端已经在跑，但找不到这个文件：</p>
<pre style="background:#161b22;border:1px solid #30363d;border-radius:8px;
 padding:12px;overflow:auto;color:#ffa198">%s</pre>
<p>通常是把压缩包里的内容<b>只复制了一部分</b>，或者解压过程被杀软打断。</p>
<p>处理办法：把 zip <b>重新完整解压</b>到一个空目录（例如 <code>C:\\bmcd</code>），
再双击 <code>BMC DHCP.cmd</code>。命令行可以跑 <code>bmcd.cmd verify</code>
看缺了哪些文件。</p>
<p style="color:#8b949e">这个页面由后端直接生成，所以服务本身是正常的 —— 只是静态资源缺了。</p>
</div></body></html>""" % path).encode("utf-8")


class App:
    """把 Session + HTTP 服务绑在一起，方便测试时单独构造。"""

    def __init__(self, session: Session, token: str = "") -> None:
        self.session = session
        self.token = token or secrets.token_urlsafe(24)
        self.scanner = S.Scanner(log_fn=session.log)
        self.op_lock = threading.Lock()
        self._shutdown_lock = threading.Lock()
        self._stopped = False
        self.stop_event = threading.Event()
        self.last_heartbeat = 0.0
        self.auto_stop = True
        self._watchdog: Optional[threading.Thread] = None
        self.server: Optional[ThreadingHTTPServer] = None
        self.started_at = time.time()

    # ------------------------------------------------------------------

    def start(self, host: str = "127.0.0.1", port: int = 0) -> Tuple[str, int]:
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError("控制台只能监听本机环回地址 127.0.0.1")
        host = "127.0.0.1"
        app = self

        class Handler(_Handler):
            app_ref = app  # type: ignore[assignment]

        httpd = ThreadingHTTPServer((host, port), Handler)
        httpd.daemon_threads = True
        self.server = httpd
        thread = threading.Thread(target=httpd.serve_forever, name="webapp", daemon=True)
        thread.start()
        self._watchdog = threading.Thread(target=self._watch, name="heartbeat", daemon=True)
        self._watchdog.start()
        return host, httpd.server_address[1]

    def stop(self) -> None:
        # /api/quit 的工作线程与 main() 的 finally 都会调用；后者必须等
        # 前者真正还原完网口，不能看到 stop_event 就提前结束整个进程。
        with self._shutdown_lock:
            if self._stopped:
                return
            self._stop_locked()
            self._stopped = True

    def _stop_locked(self) -> None:
        self.stop_event.set()
        try:                      # 先收掉扫描：把它加的临时地址摘干净
            self.scanner.stop()
            removed = self.scanner.cleanup()
            if removed:
                self.session.log("info", "已摘掉临时地址：%s" % ", ".join(removed))
        except Exception:          # noqa: BLE001
            pass
        if self.server is not None:
            try:
                self.server.shutdown()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.server.server_close()
            except Exception:  # noqa: BLE001
                pass
            self.server = None
        try:
            with self.op_lock:      # 别和正在进行的 start/stop 抢
                self.session.shutdown()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------

    def _watch(self) -> None:
        """界面关掉忘停服务时，兜底停掉并还原网卡（防止留下一个 root 进程）。"""
        while not self.stop_event.wait(5.0):
            if not self.auto_stop or self.last_heartbeat <= 0:
                continue
            if time.time() - self.last_heartbeat > 120:
                self.session.log("warn", "界面已经 120 秒没响应，关闭后台并还原网卡")
                self.stop()
                return


class _Handler(BaseHTTPRequestHandler):
    server_version = "bmcdhcp/%s" % __version__
    protocol_version = "HTTP/1.1"
    app_ref: App = None  # type: ignore[assignment]

    # ---------------- 基础设施 ----------------

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10.0)

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _json(self, obj: object, status: int = 200) -> None:
        data = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        if not host:
            return False
        if host.startswith("["):                 # [::1]:8770
            name = host.split("]", 1)[0] + "]"
        elif host.count(":") == 1:               # 127.0.0.1:8770
            name = host.rsplit(":", 1)[0]
        else:
            name = host
        return name in ("127.0.0.1", "localhost", "[::1]", "::1")

    def _origin_ok(self) -> bool:
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(origin)
            port = parts.port
        except ValueError:
            return False
        if parts.scheme != "http":
            return False
        if (parts.hostname or "").lower() not in ("127.0.0.1", "localhost", "::1"):
            return False
        # 端口必须是我们自己监听的端口，别的本地端口也算跨站
        try:
            mine = self.server.server_address[1]
        except (AttributeError, IndexError, TypeError):
            mine = port
        return (port or 80) == mine

    def _token_ok(self) -> bool:
        app = self.app_ref
        if app is None:
            return False
        got = self.headers.get("X-BMCD-Token") or ""
        return secrets.compare_digest(got, app.token)

    def _body(self) -> Dict[str, object]:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("不支持分块传输，请带 Content-Length")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("Content-Length 不合法")
        if length < 0:
            raise ValueError("Content-Length 不合法")
        if length == 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("请求体太大")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("请求体不是合法 JSON")
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    def _guard(self) -> bool:
        if not self._host_ok():
            self._json({"error": "非法的 Host 头"}, 403)
            return False
        return True

    # ---------------- GET ----------------

    def do_GET(self) -> None:  # noqa: N802
        app = self.app_ref
        if app is None:
            self._json({"error": "内部状态异常"}, 500)
            return
        if not self._guard():
            return
        path, _, query = self.path.partition("?")
        try:
            if path in ("/", "/index.html"):
                if ui_missing():
                    self._html(_missing_ui_page())
                else:
                    try:
                        self._html(_read_ui("index.html"))
                    except OSError:
                        self._html(_missing_ui_page())
                return
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/api/ping":
                self._json({
                    "ok": True,
                    "version": __version__,
                    "pid": os.getpid(),
                    "root": I.is_root(),
                    "uptime": int(time.time() - app.started_at),
                })
                return
            if path in ("/api/state", "/api/ifaces", "/api/diag", "/api/scan") and not self._token_ok():
                self._json({"error": "缺少或错误的访问令牌，请从 App 打开界面"}, 403)
                return
            if path == "/api/state":
                since = 0
                for part in query.split("&"):
                    if part.startswith("since="):
                        try:
                            since = max(0, int(part[6:]))
                        except ValueError:
                            since = 0
                snap = app.session.snapshot(since)
                snap["scan"] = app.scanner.snapshot()
                self._json(snap)
                return
            if path == "/api/scan":
                self._json(app.scanner.snapshot())
                return
            if path == "/api/ifaces":
                force = ("refresh=1" in query) or ("force=1" in query)
                self._json(_iface_enum(force=force))
                return
            if path == "/api/diag":
                self._json(_diagnostics(app.session))
                return
            self._json({"error": "not found"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001
            self._json({"error": "服务端异常：%s" % exc}, 500)

    # ---------------- POST ----------------

    def do_POST(self) -> None:  # noqa: N802
        app = self.app_ref
        if app is None:
            self._json({"error": "内部状态异常"}, 500)
            return
        if not self._guard():
            return

        # 先把请求体读完再判断权限，否则 keep-alive 连接会被没读走的内容搞乱
        try:
            body = self._body()
        except ValueError as exc:
            self.close_connection = True
            self._json({"error": str(exc)}, 400)
            return

        if not self._origin_ok():
            self._json({"error": "跨站请求被拒绝"}, 403)
            return
        path = self.path.partition("?")[0]
        if not self._token_ok():
            self._json({"error": "缺少或错误的访问令牌，请从 App 打开界面"}, 403)
            return

        try:
            if path == "/api/heartbeat":
                app.last_heartbeat = time.time()
                if "auto_stop" in body:
                    app.auto_stop = bool(body["auto_stop"])
                self._json({"ok": True, "state": app.session.state})
                return
            if path == "/api/start":
                with app.op_lock:
                    # A console token controls networking, not arbitrary root
                    # filesystem output. Only the launcher/CLI chooses storage.
                    cfg = SessionConfig.from_dict({**body, "state_path": app.session.cfg.state_path})
                    app.session.cfg = cfg
                    app.session.start()
                self._json({"ok": True, "state": app.session.state})
                return
            if path == "/api/stop":
                with app.op_lock:
                    app.session.stop()
                self._json({"ok": True, "state": app.session.state})
                return
            if path == "/api/probe":
                ip = str(body.get("ip") or "").strip()
                if not ip:
                    self._json({"error": "缺少 ip"}, 400)
                    return
                # 以前给个乱七八糟的字符串也会回一个「空指纹」，看着像探测过了
                try:
                    addr = ipaddress.IPv4Address(ip)
                except ValueError:
                    self._json({"error": "ip 不是合法的 IPv4 地址：%s" % ip[:40]}, 400)
                    return
                if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
                    # 0.0.0.0 在本机等于连自己、255.255.255.255 是广播：
                    # 探它们只会得到一堆假的「端口开着」
                    self._json({"error": "这个地址不能探测：%s" % ip}, 400)
                    return
                self._json(app.session.probe(ip))
                return
            if path == "/api/scan/start":
                try:
                    result = app.scanner.start(body)
                except S.ScanError as exc:
                    self._json({"error": str(exc)}, 400)
                    return
                self._json(result)
                return
            if path == "/api/scan/stop":
                app.scanner.stop()
                self._json({"ok": True, "scan": app.scanner.snapshot()})
                return
            if path == "/api/scan/cleanup":
                removed = app.scanner.cleanup()
                self._json({"ok": True, "removed": removed})
                return
            if path == "/api/quit":
                self._json({"ok": True})
                threading.Thread(target=app.stop, name="quit", daemon=True).start()
                return
            self._json({"error": "not found"}, 404)
        except SessionError as exc:
            self._json({"error": str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001
            self._json({"error": "服务端异常：%s" % exc}, 500)


# ----------------------------------------------------------------------
# 辅助数据
# ----------------------------------------------------------------------

def _iface_rows(ifaces: List[I.Interface]) -> List[Dict[str, object]]:
    out = []
    for iface in ifaces:
        out.append({
            "name": iface.name,
            "service": iface.service,
            "mac": iface.mac,
            "ipv4": iface.ipv4,
            "netmask": iface.netmask,
            "link": iface.link,
            "has_link": iface.has_link,
            "wifi": iface.is_wifi,
            "default_route": iface.is_default_route,
            "loopback": iface.loopback,
            "virtual": iface.virtual,
            "tunnel": getattr(iface, "tunnel", False),
            "source": getattr(iface, "source", ""),
            "scan_cidrs": S.default_cidrs(iface),
        })
    return out


def _iface_list() -> List[Dict[str, object]]:
    return _iface_rows(I.enumerate_all())


def _iface_enum(force: bool = False) -> Dict[str, object]:
    """`/api/ifaces` 的返回体。

    契约（前端靠它区分「没网卡」和「读不到网卡」）：
      ok       —— 有没有拿到至少一张网卡
      ifaces   —— 列表（永远存在，哪怕是空数组）
      source   —— 这次数据来自哪个枚举源（ctypes / powershell / ipconfig）
      error    —— 枚举失败/降级的原因；ok=False 时**一定非空**
      enum     —— 本次枚举耗时与逐源报告

    枚举本身抛异常时也返回 200 + 上面这个结构（而不是 500）：500 会让前端
    在 `api()` 里抛错、`loadIfaces` 直接 return，用户看到的是一片空白，
    连「为什么」都没有。
    """
    started = time.time()
    ifaces: List[I.Interface] = []
    error = ""
    if force and I.IS_WINDOWS:
        try:
            I.winnet.adapter_records(force=True)
        except Exception as exc:          # noqa: BLE001  刷新失败也要给出结构
            # 以前这里是 pass：用户点「刷新」什么也没发生，界面上连「刷新失败」都看不到
            error = "刷新枚举失败：%s" % exc
    try:
        ifaces = I.enumerate_all()
    except Exception as exc:              # noqa: BLE001
        # 拼接：刷新失败的原因不能被后面的枚举异常顶掉
        error = (error + "；" if error else "") + "网卡枚举异常：%s" % exc
    rows = _iface_rows(ifaces)
    candidates: List[str] = []
    try:
        candidates = [i.name for i in I.ethernet_candidates(ifaces)] if ifaces else []
    except Exception as exc:              # noqa: BLE001
        error = (error + "；" if error else "") + "候选网卡计算失败：%s" % exc
    report: Dict[str, object] = {}
    if I.IS_WINDOWS:
        try:
            report = I.winnet.adapter_report()
        except Exception:                 # noqa: BLE001
            report = {}
    ok = bool(rows)
    if not ok:
        # 拼接而不是二选一：enumerate_all 抛的异常和三级枚举原因都要能看到，
        # 否则「读不到网卡」永远只剩一句话，用户不知道该查哪一级。
        parts = [p for p in (error, str(report.get("error") or "")) if p]
        error = "；".join(parts) or "没有读到任何网卡（原因未知）"
    return {
        "ok": ok,
        "platform": "windows" if I.IS_WINDOWS else "macos",
        "ifaces": rows,
        "candidates": candidates,
        "source": str(report.get("source") or ""),
        "error": error,
        "enum": {
            "ms": int((time.time() - started) * 1000),
            "sources": list(report.get("sources") or []),
            "cached": bool(report.get("cached")),
        },
    }


def _candidates() -> List[str]:
    return [i.name for i in I.ethernet_candidates()]


def _iface_enum_summary() -> Dict[str, object]:
    """`/api/diag` 里的网卡枚举摘要（没枚举过就先枚举一次，让诊断有内容）。

    非 Windows 显式回 skipped：macOS 不走多源枚举，如果照旧用
    `pending = not sources` 算，诊断弹窗会永远显示「枚举中」，比不显示更误导。
    """
    if not I.IS_WINDOWS:
        return {
            "platform": "macos",
            "source": "",
            "error": "",
            "sources": [],
            "pending": False,
            "skipped": "macOS 不用多源枚举（逐源报告只对 Windows 的 ctypes/powershell/ipconfig 有意义）",
        }
    report: Dict[str, object] = {}
    try:
        report = I.winnet.adapter_report()
        if not report.get("sources"):
            I.winnet.adapter_records()
            report = I.winnet.adapter_report()
    except Exception as exc:          # noqa: BLE001
        return {"platform": "windows", "error": "枚举诊断不可用：%s" % exc}
    return {
        "platform": "windows",
        "source": str(report.get("source") or ""),
        "error": str(report.get("error") or ""),
        "sources": list(report.get("sources") or []),
        "pending": not bool(report.get("sources")),
    }


def _diagnostics(session: Session) -> Dict[str, object]:
    caps = session.capabilities()
    owners = I.dhcp_port_owner(exclude_pid=os.getpid())
    running = session.state == "running"
    free_port = True
    note = ""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Windows 的 SO_REUSEADDR 是「抢端口」语义：设了之后哪怕别人占着
        # 67 也能绑上，探测就永远说「空闲」。所以只在 POSIX 上设。
        if not I.IS_WINDOWS:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 67))
    except OSError:
        free_port = False
        note = "本服务自己正在用" if running else "被别的进程占着（多半是「互联网共享」）"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return {
        "capabilities": caps,
        "port67_free": free_port,
        "port67_note": note,
        "port67_owners": owners,
        "engine": session.engine_kind,
        "state": session.state,
        "state_path": session.cfg.state_path,
        "python": "%s %s" % (os.sys.version.split()[0], _machine()),
        "session_file": session_path(),
        "session_candidates": session_candidates(),
        "ui_dir": UI_DIR,
        "ui_missing": ui_missing(),
        "iface_enum": _iface_enum_summary(),
    }


# ----------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------

def _owner_uid() -> int:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return -1                      # Windows 没有 uid 概念
    try:
        return int(geteuid())
    except OSError:
        return -1


def _machine() -> str:
    try:
        return os.uname().machine          # type: ignore[attr-defined]
    except AttributeError:
        import platform

        return platform.machine() or "unknown"


def write_session_file(port: int, token: str, url: str) -> bool:
    """只有属主能读：里面是访问令牌。管理员不覆盖普通用户写的文件。

    失败时**不能静默**：以前这里 except OSError: pass，结果是
    「后端起来了、日志里有 BMCD_LISTEN，但启动器读不到会话文件 → 报超时」，
    谁都看不出来是写文件失败。现在把路径和错误打进 stdout（= backend.log），
    并且启动器还会退一步直接解析日志。
    """
    payload = {"url": url, "port": port, "token": token, "pid": os.getpid(),
               "ts": time.time()}
    for path in session_candidates():
        if _write_session_to(path, payload):
            print("BMCD_SESSION %s" % path, flush=True)
            return True
    return False


def _write_session_to(path: str, payload: Dict[str, object]) -> bool:
    try:
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        if _owner_uid() == 0:
            try:
                if os.stat(path).st_uid != 0:
                    print("BMCD_SESSION_SKIP %s（用户自己写的，不覆盖）" % path, flush=True)
                    return False    # 这是用户（App）写的，别用管理员盖掉它
            except (OSError, AttributeError):
                pass
        atomic_write_json(path, payload)
        return True
    except OSError as exc:
        print("BMCD_SESSION_ERR %s: %s" % (path, exc), flush=True)
        return False


def read_session_file() -> Optional[Dict[str, object]]:
    for path in session_candidates():
        try:
            euid = _owner_uid()
            if euid >= 0 and os.stat(path).st_uid != euid:
                continue         # 不是我的文件，不读
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return None


def clear_session_file() -> None:
    for path in session_candidates():
        try:
            os.remove(path)
        except OSError:
            pass


def main(
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = False,
    print_url: bool = True,
    token: str = "",
) -> int:
    # 令牌走环境变量，别放进命令行（ps 看得见）
    token = token or os.environ.get("BMCD_TOKEN", "")
    session = Session(SessionConfig())
    app = App(session, token=token)
    if os.environ.get("BMCD_DESKTOP") == "1":
        app.last_heartbeat = time.time()  # 首次页面加载失败也不能留下闲置的 root 后台
    left = session.recover_backup()      # 上次被强杀/断电留下的静态地址
    if left:
        session.log("warn" if "失败" in left else "info", left)
    host, port = app.start(host, port)
    url = "http://%s:%d/?t=%s" % (host, port, app.token)
    if not write_session_file(port, app.token, url):
        print("BMCD_WARN 会话文件没写成，启动器可能读不到；URL 就在下面这一行", flush=True)
    if print_url:
        print("BMCD_LISTEN %s" % url, flush=True)
        print("BMCD_PORT %d" % port, flush=True)

    stop = threading.Event()
    import signal as _signal

    def _on_signal(*_: object) -> None:
        stop.set()

    signals = [getattr(_signal, name, None) for name in ("SIGINT", "SIGTERM", "SIGHUP")]
    for sig in [s for s in signals if s is not None]:
        try:
            _signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass

    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    try:
        while not stop.is_set() and not app.stop_event.is_set():
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        clear_session_file()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
