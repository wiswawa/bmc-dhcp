"""会话控制器：一次“启动 DHCP → 收租约 → 停止并还原”的完整生命周期。

CLI 和 GUI 共用同一个 Session，避免两套逻辑各自跑偏导致“命令行好使、界面不好使”。
线程模型：
  * 调用方线程：start() / stop() / snapshot()
  * engine 线程：收发包、触发事件回调
  * probe 守护线程：地址分配后去探测管理端口
所有对状态字段的写入都在 self._lock 里，读快照也在锁里做浅拷贝。
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Tuple

from . import discover, engines, vendors
from . import iface as I
from .core import ServerConfig, ServerCore
from .leases import LeaseManager
from .stateio import atomic_write_json

DEFAULT_SUBNET = "10.99.0.0/24"


def user_home() -> str:
    """真实用户的家目录。

    以 root 跑的时候（App 提权启动、sudo），expanduser("~") 会变成 /var/root，
    租约记录就会存到看不见的地方 —— 所以优先用启动器传进来的 BMCD_HOME，
    其次看 SUDO_USER。
    """
    home = os.environ.get("BMCD_HOME")
    if home:
        return home
    sudo_user = os.environ.get("SUDO_USER")
    geteuid = getattr(os, "geteuid", None)
    if sudo_user and geteuid is not None and geteuid() == 0:
        try:
            import pwd

            return pwd.getpwnam(sudo_user).pw_dir
        except (KeyError, ImportError):
            pass
    return os.path.expanduser("~")


DEFAULT_STATE = os.path.join(user_home(), ".bmcd", "state.json")

STATE_IDLE = "idle"
STATE_STARTING = "starting"
STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_ERROR = "error"

MAX_LOG_LINES = 1200


class SessionError(RuntimeError):
    """配置/启动阶段的错误，消息直接可以给用户看。"""


@dataclass
class SessionConfig:
    iface: str = ""
    # 网卡下拉里选的是「网络服务名」（扩展坞换了 en 号还是同一块网卡）：
    # iface 为空时按它反查设备名，iface 有值时以 iface 为准。
    iface_service: str = ""
    subnet: str = DEFAULT_SUBNET
    server_ip: str = ""
    pool: str = ""
    lease_seconds: int = 300
    dns: List[str] = field(default_factory=list)
    routers: List[str] = field(default_factory=list)
    auto_router: bool = True
    domain: str = "bmc.local"
    hostname_prefix: str = "bmc"
    engine: str = "auto"
    echo: bool = True
    configure: bool = True
    restore: bool = True
    state_path: str = DEFAULT_STATE
    probe_retry: float = 7.0

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "SessionConfig":
        cfg = cls()
        for key in list(cls.__dataclass_fields__):
            if key not in data:
                continue
            value = data[key]
            if value is None:
                continue
            if key in ("dns", "routers"):
                if isinstance(value, str):
                    value = [x.strip() for x in value.split(",") if x.strip()]
                elif isinstance(value, (list, tuple)):
                    value = [str(x).strip() for x in value if str(x).strip()]
                else:
                    value = []
                setattr(cfg, key, list(value))
            elif key == "lease_seconds":
                try:
                    setattr(cfg, key, max(30, min(86400, int(float(value)))))
                except (TypeError, ValueError):
                    pass
            elif key == "probe_retry":
                try:
                    setattr(cfg, key, max(0.0, min(60.0, float(value))))
                except (TypeError, ValueError):
                    pass
            elif key in ("auto_router", "echo", "configure", "restore"):
                # 接口是 JSON 传进来的，正常是 true/false；但字符串 "false"
                # 用 bool() 会变成 True（改网卡开关被误解的最坏情况），所以显式判一次
                if isinstance(value, str):
                    setattr(cfg, key, value.strip().lower() not in ("", "0", "false", "no", "off"))
                else:
                    setattr(cfg, key, bool(value))
            else:
                setattr(cfg, key, str(value).strip())
        if cfg.engine not in ("auto", "raw", "udp", "dnsmasq"):
            cfg.engine = "auto"
        if not cfg.subnet:
            cfg.subnet = DEFAULT_SUBNET
        return cfg


class DaemonPool:
    """小线程池：全是 daemon 线程，退出时不会卡在后台探测上。"""

    def __init__(self, workers: int = 4, name: str = "probe") -> None:
        self._queue: "queue.Queue" = queue.Queue()
        self._threads: List[threading.Thread] = []
        self._closed = False
        for i in range(max(1, workers)):
            thread = threading.Thread(target=self._work, name="%s-%d" % (name, i), daemon=True)
            thread.start()
            self._threads.append(thread)

    def submit(self, fn: Callable, *args: object) -> None:
        if self._closed:
            return
        self._queue.put((fn, args))

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            fn, args = item
            try:
                fn(*args)
            except Exception:  # noqa: BLE001  后台线程绝不外抛
                pass

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for _ in self._threads:
            self._queue.put(None)


class Session:
    def __init__(
        self,
        cfg: SessionConfig,
        log: Optional[Callable[[str, str], None]] = None,
        engine_factory: Optional[Callable] = None,
        probe_fn: Optional[Callable] = None,
        on_found: Optional[Callable[[str], None]] = None,
        iface_lookup: Optional[Callable[[str], Optional[I.Interface]]] = None,
    ) -> None:
        self.cfg = cfg
        self._on_found = on_found
        self._log_cb = log
        self._engine_factory = engine_factory or engines.make_engine
        self._probe_fn = probe_fn or discover.probe
        self._iface_lookup = iface_lookup
        self._lock = threading.RLock()

        self.state = STATE_IDLE
        self.error = ""
        self.started_at = 0.0
        self.stopped_at = 0.0

        self.iface: Optional[I.Interface] = None
        self.saved_iface: Optional[I.SavedConfig] = None
        self.server_cfg: Optional[ServerConfig] = None
        self.leases: Optional[LeaseManager] = None
        self.core: Optional[ServerCore] = None
        self.engine: Optional[engines.Engine] = None
        self.engine_kind = ""
        self.engine_note = ""

        self._life = threading.RLock()      # start/stop 互斥，避免状态机被写坏
        self._ifconfig_added: Optional[str] = None   # 用 ifconfig 兜底加的地址
        self._engine_thread: Optional[threading.Thread] = None
        self._engine_ready = threading.Event()
        self._pool = DaemonPool(workers=4)
        self._probed: set = set()

        self._logs: List[Dict[str, object]] = []
        self._log_seq = 0
        self._last_ack = 0.0
        self._ack_count = 0

    # ------------------------------------------------------------------
    # 日志
    # ------------------------------------------------------------------

    def log(self, level: str, text: str) -> None:
        with self._lock:
            entry = {
                "i": self._log_seq,
                "ts": time.time(),
                "level": level,
                "text": str(text)[:600],
            }
            self._log_seq += 1
            self._logs.append(entry)
            if len(self._logs) > MAX_LOG_LINES:
                del self._logs[:-MAX_LOG_LINES]
        if self._log_cb:
            try:
                self._log_cb(level, entry["text"])
            except Exception:  # noqa: BLE001
                pass

    def logs_since(self, since: int) -> Tuple[List[Dict[str, object]], int]:
        with self._lock:
            if since < 0 or since > self._log_seq:
                since = 0          # 服务重启过，游标越界就从头给
            items = [e for e in self._logs if int(e["i"]) >= int(since)]
            return items, int(self._log_seq)

    # ------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._life:                    # 整个启动过程串行，stop 会等它跑完
            self._start_locked()

    def _start_locked(self) -> None:
        with self._lock:
            if self.state in (STATE_STARTING, STATE_RUNNING, STATE_STOPPING):
                raise SessionError("服务正在运行或正在切换状态")
            self.state = STATE_STARTING
            self.error = ""

        try:
            self._do_start()
        except Exception as exc:  # noqa: BLE001
            message = str(exc) or exc.__class__.__name__
            self._teardown()
            with self._lock:
                self.state = STATE_ERROR
                self.error = message
            self.log("err", "启动失败：%s" % message)
            raise SessionError(message) from exc
        except BaseException:
            # Ctrl-C / SystemExit：也要把网卡还原回去
            self._teardown()
            with self._lock:
                self.state = STATE_ERROR
                self.error = "启动被中断"
            raise

        with self._lock:
            self.state = STATE_RUNNING
            self.started_at = time.time()
        self.log("ok", "服务已启动，等待 BMC 请求地址")

    def _resolve_service(self, service: str) -> "I.Interface":
        """按网络服务名反查网卡，失败时给一句能看懂的话。"""
        device = I.service_device(service)
        if device:
            iface = I.find_by_name(device)
            if iface is None:
                raise SessionError(
                    "服务「%s」对应的网卡 %s 现在不存在 —— 扩展坞/网卡插上了吗？"
                    % (service, device)
                )
            self.log("info", "服务「%s」对应网卡 %s" % (service, iface.name))
            return iface
        names = [i.name for i in I.enumerate_all() if i.mac]
        raise SessionError(
            "找不到网络服务「%s」（也可以直接写网卡名如 en7）。当前网卡：%s"
            % (service, "，".join(names[:8]) or "无")
        )

    def _do_start(self) -> None:
        cfg = self.cfg
        with self._lock:
            self._probed.clear()
            self.engine_kind = ""
            self.engine_note = ""
        try:
            net = ipaddress.IPv4Network(cfg.subnet, strict=False)
        except ValueError:
            raise SessionError("子网格式不对：%r（例：10.99.0.0/24）" % cfg.subnet)
        server_ip = cfg.server_ip or str(net.network_address + 1)
        try:
            server_addr = ipaddress.IPv4Address(server_ip)
        except ValueError:
            raise SessionError("本机地址不合法：%s" % server_ip)
        if server_addr not in net:
            raise SessionError("本机地址 %s 不在子网 %s 内" % (server_ip, cfg.subnet))
        if net.prefixlen > 30:
            raise SessionError("子网太小（/%d），至少 /30" % net.prefixlen)
        if server_addr in (net.network_address, net.broadcast_address):
            raise SessionError("本机地址不能使用网络地址或广播地址：%s" % server_ip)

        pool_spec = cfg.pool or "%s-%s" % (
            str(net.network_address + 100),
            str(net.network_address + 200),
        )
        start, end = self.parse_pool(pool_spec, net)

        routers: List[str] = []
        if cfg.routers:
            for r in cfg.routers:
                try:
                    routers.append(str(ipaddress.IPv4Address(r)))
                except ValueError:
                    raise SessionError("网关地址不合法：%s" % r)
        elif cfg.auto_router:
            routers = [server_ip]
        for r in routers:
            if ipaddress.IPv4Address(r) not in net:
                raise SessionError("网关 %s 不在子网 %s 内" % (r, cfg.subnet))

        for d in cfg.dns:
            try:
                ipaddress.IPv4Address(d)
            except ValueError:
                raise SessionError("DNS 地址不合法：%s" % d)

        server_cfg = ServerConfig(
            server_ip=server_ip,
            network=str(net),
            pool_start=start,
            pool_end=end,
            lease_seconds=cfg.lease_seconds,
            routers=routers,
            dns=list(cfg.dns),
            domain=cfg.domain,
            hostname_prefix=cfg.hostname_prefix,
            vendor_echo=cfg.echo,
            client_id_echo=cfg.echo,
        )
        leases = LeaseManager(
            server_ip=server_ip,
            network=str(net),
            pool_start=start,
            pool_end=end,
            lease_seconds=cfg.lease_seconds,
            state_path=cfg.state_path,
        )

        # 本机地址落在池子里时，那个地址不会分给设备，先说清楚
        lo, hi = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
        if lo <= int(server_addr) <= hi:
            if lo == hi:
                raise SessionError("地址池里只有本机地址 %s，换一个地址池" % server_ip)
            self.log(
                "warn",
                "地址池包含了本机地址 %s，这个地址会留给本机，实际可用 %d 个"
                % (server_ip, hi - lo),
            )

        # 先恢复遗留配置，再枚举接口。否则同一个临时 IP 会被误认为原配置。
        if cfg.configure:
            left = self.recover_backup()
            if left:
                self.log("warn" if "失败" in left else "info", left)
            if os.path.exists(self._backup_path()):
                raise SessionError("上次的网络配置备份尚未恢复，拒绝覆盖原记录")

        # 每次启动都重新读一遍：上一次 stop 已经把配置还原了，缓存的对象会骗人
        iface = None
        lookup = self._iface_lookup or I.find_by_name
        if cfg.iface:
            iface = lookup(cfg.iface)
            if iface is None:      # 允许写服务名，比如 --iface AX88179A
                device = I.service_device(cfg.iface)
                if device:
                    iface = lookup(device)
                    if iface is None:
                        raise SessionError(
                            "服务「%s」对应的网卡 %s 现在不存在 —— 扩展坞/网卡插上了吗？"
                            % (cfg.iface, device)
                        )
                    self.log("info", "服务「%s」对应网卡 %s" % (cfg.iface, iface.name))
            if iface is not None and cfg.iface_service and cfg.iface_service != cfg.iface:
                self.log("info", "同时收到网卡 %s 和网络服务「%s」，以网卡为准"
                         % (iface.name, cfg.iface_service))
        elif cfg.iface_service:
            # 界面上选的是网络服务名：以前这个字段被直接丢掉，所以「选了下拉里的网卡
            # 但启动还是用自动挑的第一块」—— 用户看到的就是「选了没用」。
            iface = self._resolve_service(cfg.iface_service)
        if iface is None and not cfg.iface and not cfg.iface_service:
            cands = I.ethernet_candidates()
            if not cands:
                raise SessionError("没有检测到有链路的以太网口（网线插了吗？）")
            iface = cands[0]
        if iface is None:
            names = [i.name for i in I.enumerate_all() if i.mac]
            raise SessionError(
                "找不到网卡 %s（可以写 en7，或写网络服务名如 AX88179A）。当前有：%s"
                % (cfg.iface, "，".join(names[:8]) or "无")
            )
        self.iface = iface

        self.server_cfg = server_cfg
        self.leases = leases
        self.core = ServerCore(server_cfg, leases, on_event=self._on_event)

        self.log(
            "info",
            "网卡 %s（%s） 本机 %s/%s 地址池 %s-%s 租期 %ds"
            % (iface.name, iface.service or "-", server_ip, server_cfg.netmask, start, end,
               cfg.lease_seconds),
        )

        self._prepare_iface(iface, server_cfg)

        conflicts = I.dhcp_port_owner(exclude_pid=os.getpid())
        if conflicts:
            self.log("warn", "注意：UDP/67 还被这些进程占着：%s" % "，".join(conflicts[:2]))

        self._start_engine()

        if not leases.sticky:
            self.log("info", "首次运行，租约状态会存到 %s" % cfg.state_path)

    # ---------- 网卡配置 ----------

    def _prepare_iface(self, iface: I.Interface, server_cfg: ServerConfig) -> None:
        cfg = self.cfg
        want, mask = server_cfg.server_ip, server_cfg.netmask

        same_subnet = False
        if iface.ipv4 and not iface.is_link_local:
            try:
                same_subnet = ipaddress.IPv4Address(iface.ipv4) in ipaddress.IPv4Network(
                    server_cfg.network, strict=False
                )
            except ValueError:
                same_subnet = False

        if want == iface.ipv4:
            self.log("info", "%s 已经是 %s，不再改动它（停止时也不会动）" % (iface.name, want))
            return

        if not cfg.configure:
            if not same_subnet:
                self.log(
                    "warn",
                    "已关闭自动配置：%s 现在的地址 %s 不在 %s 内，BMC 可能连不回来"
                    % (iface.name, iface.ipv4 or "无", server_cfg.network),
                )
            return

        self.saved_iface = I.describe_config(iface.service)
        self.saved_iface.iface = iface.name
        try:
            self._save_backup(want)
        except (OSError, ValueError) as exc:
            self.saved_iface = None  # 没有改过网口，失败收尾也不应动它
            raise SessionError("无法保存原网络配置，未修改网口：%s" % exc) from exc
        if self.saved_iface.mode in ("unknown", "none"):
            # 这个口没有「网络服务」可改，set_static 会走 ifconfig，退出时自己摘
            self._ifconfig_added = want
        self.log(
            "info",
            "把 %s 设为 %s/%s（原来是 %s %s，停止时会还原）"
            % (iface.name, want, mask, self.saved_iface.mode, self.saved_iface.ip or ""),
        )
        if not I.set_static(iface, want, mask):
            if I.is_root():
                raise SessionError("设置网卡地址失败（%s）" % iface.name)
            if I.IS_WINDOWS:
                raise SessionError(
                    "没有权限修改网卡地址，请右键「以管理员身份运行」；"
                    r'或手动执行：netsh interface ipv4 set address name="%s" source=static '
                    "address=%s mask=%s" % (iface.name, want, mask))
            raise SessionError(
                "没有权限修改网卡地址，请用管理员身份运行（App 会提示授权；"
                "或手动执行：sudo ifconfig %s inet %s %s）" % (iface.name, want, mask)
            )

        for _ in range(12):
            time.sleep(0.35)
            updated = I.find_by_name(iface.name)
            if updated and updated.ipv4 == want:
                self.iface = updated
                return
        updated = I.find_by_name(iface.name)
        if updated:
            self.iface = updated
        self.log("warn", "%s 上的地址还没生效（当前 %s），继续尝试启动"
                 % (iface.name, (updated.ipv4 if updated else "") or "空"))

    # ---------- 引擎 ----------

    def _start_engine(self) -> None:
        # 用显式判断而不是 assert：python -O 会把 assert 全部删掉，
        # 那时候这里就会拿 None 继续往下走，报一个看不懂的 AttributeError
        if self.iface is None or self.core is None:
            raise SessionError("内部状态不对：网卡/核心还没准备好就启动引擎了")
        note = ""
        try:
            engine = self._make_engine()
        except engines.EngineUnavailable as exc:
            if self.cfg.engine not in ("auto",):
                raise SessionError("引擎不可用：%s" % exc)
            self.log("warn", "raw 引擎不可用（%s），改用 udp 引擎" % exc)
            engine = engines.UdpEngine(self.iface, self.core, self.log)
            note = "udp"

        self.engine = engine
        self.engine_kind = engine.kind
        self.engine_note = note
        self._engine_ready.clear()
        thread = threading.Thread(target=self._engine_main, name="bmcd-engine", daemon=True)
        self._engine_thread = thread
        thread.start()

        if not self._engine_ready.wait(6.0):
            raise SessionError("引擎启动超时（%s）" % engine.kind)
        if self.state == STATE_ERROR:  # 引擎线程已经判定失败
            raise SessionError(self.error or "引擎启动失败")
        self.log("info", "发包引擎：%s" % (self.engine_kind or engine.kind))

    def _make_engine(self):
        """工厂可能不接受 on_lease（测试替身只有 4 个参数），按签名适配。"""
        import inspect

        factory = self._engine_factory
        try:
            params = inspect.signature(factory).parameters
            takes_on_lease = "on_lease" in params
        except (TypeError, ValueError):
            takes_on_lease = False
        if takes_on_lease:
            return factory(
                self.cfg.engine, self.iface, self.core, self.log,
                on_lease=self._on_dnsmasq_lease,
            )
        return factory(self.cfg.engine, self.iface, self.core, self.log)

    def _on_dnsmasq_lease(self, mac: str, ip: str, hostname: str) -> None:
        if not self.leases:
            return
        self.leases.bind(ip, mac, hostname=hostname, now=time.time())
        self._on_event({"type": "ack", "mac": mac, "ip": ip, "hostname": hostname})

    def _engine_main(self) -> None:
        if self.engine is None:
            return
        try:
            self.engine.start(on_ready=self._engine_ready.set)
        except (PermissionError, OSError) as exc:
            if self.cfg.engine == "auto" and self.engine.kind == "raw":
                self.log("warn", "raw 引擎起不来（%s），自动退到 udp 引擎" % exc)
                try:
                    if self.iface is None or self.core is None:
                        raise SessionError("内部状态不对：退化到 udp 引擎时网卡信息丢了")
                    self.engine = engines.UdpEngine(self.iface, self.core, self.log)
                    self.engine_kind = "udp"
                    self.engine.start(on_ready=self._engine_ready.set)
                    return
                except Exception as exc2:  # noqa: BLE001
                    self.log("err", "udp 引擎也起不来：%s" % exc2)
                    self._fail_engine("引擎启动失败：%s" % exc2)
                    return
            self._fail_engine("权限不足或发包失败：%s" % exc)
        except engines.EngineUnavailable as exc:
            self._fail_engine("引擎不可用：%s" % exc)
        except Exception as exc:  # noqa: BLE001
            self._fail_engine("引擎异常退出：%s" % exc)

    def _fail_engine(self, message: str) -> None:
        with self._lock:
            self.error = message
            if self.state == STATE_STARTING:
                self.state = STATE_ERROR
        self.log("err", message)
        self._engine_ready.set()

    # ------------------------------------------------------------------
    # 停止
    # ------------------------------------------------------------------

    def stop(self) -> None:
        with self._life:
            with self._lock:
                if self.state == STATE_IDLE and not self.saved_iface and not self._ifconfig_added:
                    return
                if self.state == STATE_STOPPING:
                    return
                self.state = STATE_STOPPING
            self.log("info", "正在停止…")
            self._teardown()
            with self._lock:
                self.state = STATE_IDLE
                self.stopped_at = time.time()
                self.error = ""
            self.log("ok", "已停止")

    # ------------------------------------------------------------------
    # 网卡配置备份：进程被强杀 / 断电时，下次启动要把地址改回去
    # ------------------------------------------------------------------

    def _backup_path(self) -> str:
        base = ""
        if self.cfg.state_path:
            base = os.path.dirname(str(self.cfg.state_path))
        if not base:
            base = os.path.join(user_home(), ".bmcd")
        return os.path.join(base, "iface-backup.json")

    def _save_backup(self, applied_ip: str) -> None:
        """改网卡之前先把原配置落盘。

        只存在内存里的话，一旦进程被 SIGKILL / 机器断电，静态地址就永远留在
        那块网卡上了 —— 下次启动 describe_config 读到的「原来」已经是改过的
        样子，还原也回不去。
        """
        if not self.saved_iface:
            return
        payload = asdict(self.saved_iface)
        payload["applied_ip"] = applied_ip
        payload["ts"] = time.time()
        path = self._backup_path()
        atomic_write_json(path, payload)

    def _drop_backup(self) -> None:
        try:
            os.remove(self._backup_path())
        except OSError:
            pass

    def recover_backup(self) -> str:
        """上次没收尾的网卡配置，现在补一次还原。返回给用户看的一句话。"""
        path = self._backup_path()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return ""
        if not isinstance(data, dict):
            self._drop_backup()
            return ""
        fields = I.SavedConfig.__dataclass_fields__
        raw = {k: v for k, v in data.items() if k in fields and isinstance(v, str)}
        if "iface" not in raw:
            self._drop_backup()
            return ""
        saved = I.SavedConfig(**raw)
        applied = str(data.get("applied_ip") or "")
        cur = I.find_by_name(saved.iface)
        if cur is None:
            self._drop_backup()
            return "上次改过 %s，但这个网卡已经不在，忽略残留记录" % saved.iface
        if not applied or cur.ipv4 != applied:
            # 现在的地址不是我们设的：说明用户自己改过，别再动它
            self._drop_backup()
            return ("上次改过 %s，但它现在是 %s（我们设的是 %s），"
                    "不是我们留下的，不动它" % (saved.iface, cur.ipv4 or "无地址", applied or "?"))
        if saved.mode in ("unknown", "none"):
            # 这个口没有「网络服务」，地址是 ifconfig/netsh 硬加上去的，直接摘
            if I.IS_WINDOWS:
                ok = I.remove_alias(saved.iface, applied)
            else:
                ok = I.run([I.IFCONFIG, saved.iface, "inet", applied, "delete"])[0] == 0
        else:
            ok = I.restore_config(saved)
        if ok:
            self._drop_backup()
            return "补还原了上次残留的配置：%s 回到 %s %s" % (
                saved.iface, saved.mode, saved.ip or "")
        return "上次残留的 %s 配置还原失败，请到「系统设置 → 网络」手动改回" % saved.iface

    def _teardown(self) -> None:
        engine = self.engine
        if engine is not None:
            try:
                engine.stop()
            except Exception:  # noqa: BLE001
                pass
        thread = self._engine_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        self.engine = None
        self._engine_thread = None

        if self._ifconfig_added:
            # 没有网络服务可改，用 ifconfig 加的地址要自己摘掉
            try:
                ok = bool(self.iface and I.run(
                    [I.IFCONFIG, self.iface.name, "inet", self._ifconfig_added, "delete"])[0] == 0)
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                self.log("warn", "临时地址 %s 摘除失败，保留恢复记录" % self._ifconfig_added)
                return
            self.log("info", "已摘掉临时地址 %s" % self._ifconfig_added)
            self._ifconfig_added = None

        if self.saved_iface and self.saved_iface.mode in ("unknown", "none"):
            # 这个口本来就没有「网络服务」可还原：地址上面已经用 ifconfig 摘掉了。
            # 之前这里还会去调 restore_config，必然失败，然后弹一句假的
            # 「还原失败，请到系统设置检查」—— 属于自己吓自己。
            self.saved_iface = None
            self._drop_backup()
        elif self.saved_iface and self.cfg.restore:
            try:
                ok = I.restore_config(self.saved_iface)
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                self.log("info", "已还原 %s 的原网络配置" % self.saved_iface.iface)
                self.saved_iface = None
                self._drop_backup()
            else:
                self.log("warn", "还原 %s 的原配置失败，请到「系统设置 → 网络」检查"
                         % self.saved_iface.iface)
                # 保留记录：下次 stop 还会再试一次
        elif self.saved_iface:
            self.log("warn", "%s 保持静态地址未还原" % self.saved_iface.iface)
            self.saved_iface = None
            self._drop_backup()

    def shutdown(self) -> None:
        """进程退出前调用：停服务 + 停探测线程池。"""
        try:
            self.stop()
        finally:
            self._pool.shutdown()

    # ------------------------------------------------------------------
    # 事件 / 探测
    # ------------------------------------------------------------------

    def _on_event(self, ev: Dict[str, object]) -> None:
        kind = str(ev.get("type", ""))
        mac = str(ev.get("mac", ""))
        ip = str(ev.get("ip", ""))
        if kind == "discover":
            extra = []
            if ev.get("hostname"):
                extra.append("host=%s" % ev["hostname"])
            if ev.get("vendor"):
                extra.append("class=%s" % str(ev["vendor"])[:32])
            if ev.get("ip_hint"):
                extra.append("want=%s" % ev["ip_hint"])
            self.log("info", "DISCOVER %s %s" % (mac, " ".join(extra)))
        elif kind == "offer":
            self.log("info", "OFFER    %s → %s" % (mac, ip))
        elif kind == "ack":
            with self._lock:
                self._last_ack = time.time()
                self._ack_count += 1
            self.log("ok", "ACK      %s → %s（租期 %ds）" % (mac, ip, self.cfg.lease_seconds))
            self._schedule_probe(ip, mac)
        elif kind == "nak":
            self.log("warn", "NAK      %s %s" % (mac, ev.get("detail", "")))
        elif kind == "decline":
            self.log("warn", "DECLINE  %s %s" % (ip, ev.get("detail", "")))
        elif kind == "release":
            self.log("info", "RELEASE  %s %s" % (mac, ip))
        elif kind == "request_other":
            self.log("info", "忽略     %s %s" % (mac, ev.get("detail", "")))
        elif kind == "pool_exhausted":
            self.log("err", "地址池已满，没有地址可分配了")

    def _schedule_probe(self, ip: str, mac: str) -> None:
        with self._lock:
            if ip in self._probed:
                return
            self._probed.add(ip)
        self._pool.submit(self._probe_worker, ip, mac)

    def _probe_worker(self, ip: str, mac: str) -> None:
        fp = self._probe_fn(ip, timeout=0.8)
        if not fp.alive and self.cfg.probe_retry:
            time.sleep(self.cfg.probe_retry)
            fp = self._probe_fn(ip, timeout=1.0)
        self.apply_fingerprint(ip, mac, fp)
        if fp.alive:
            self.log("ok", "FOUND    %s %s" % (ip, fp.summary()))
            if fp.url:
                self.log("info", "         管理地址 %s" % fp.url)
                if self._on_found:
                    try:
                        self._on_found(fp.url)
                    except Exception:  # noqa: BLE001
                        pass
        else:
            self.log("warn", "%s 已分配但管理端口还没响应（可能还在启动）" % ip)

    def apply_fingerprint(self, ip: str, mac: str, fp: discover.Fingerprint) -> None:
        if not self.leases:
            return
        lease = self.leases.get(ip)
        if lease is None:
            return
        lease.open_ports = ",".join(str(p) for p in fp.ports)
        if fp.identity.known:
            lease.vendor_guess = fp.identity.vendor
            lease.confidence = fp.identity.confidence
        elif vendors.oui_vendor(mac):
            lease.vendor_guess = vendors.oui_vendor(mac)
            lease.confidence = "低"
        if fp.url:
            lease.url = fp.url
        if fp.http and fp.http.title and not lease.hostname:
            lease.hostname = fp.http.title
        self.leases.save_state()

    def probe(self, ip: str) -> Dict[str, object]:
        fp = self._probe_fn(ip, timeout=1.0)
        mac = fp.mac or ""
        if self.leases and self.leases.get(ip):
            self.apply_fingerprint(ip, mac, fp)
        return {
            "ip": fp.ip,
            "alive": fp.alive,
            "mac": fp.mac,
            "ports": fp.ports,
            "tls_cn": fp.tls_cn,
            "title": fp.http.title if fp.http else "",
            "server": fp.http.server if fp.http else "",
            "location": fp.http.location if fp.http else "",
            "rmcp": fp.rmcp,
            "url": fp.url,
            "vendor": fp.identity.vendor,
            "confidence": fp.identity.confidence,
            "evidence": fp.identity.evidence,
            "creds": fp.identity.creds,
            "summary": fp.summary(),
            # ARP 查询本身的失败原因（跟「表里没有这个 MAC」区分开）：界面单独显示成告警
            "arp_error": str(getattr(fp, "arp_error", "") or ""),
            "elapsed": round(fp.elapsed, 2),
        }

    # ------------------------------------------------------------------
    # 快照
    # ------------------------------------------------------------------

    def capabilities(self) -> Dict[str, object]:
        can_open_bpf = False
        if I.IS_WINDOWS:
            can_open_bpf = bool(I.winnet.has_npcap())
        else:
            try:
                if I.is_root():
                    can_open_bpf = True
                else:
                    fd = os.open("/dev/bpf0", os.O_RDONLY)
                    os.close(fd)
                    can_open_bpf = True
            except OSError:
                can_open_bpf = False
        return {
            "root": I.is_root(),
            "bpf": can_open_bpf,
            "npcap": bool(I.winnet.has_npcap()) if I.IS_WINDOWS else False,
            "netconfig": I.is_root(),
            "scapy": engines.has_scapy(),
            "dnsmasq": engines.has_dnsmasq(),
            "platform": "windows" if I.IS_WINDOWS else "macos",
        }

    def snapshot(self, since: int = 0) -> Dict[str, object]:
        with self._lock:
            state = self.state
            error = self.error
            started_at = self.started_at
            engine_kind = self.engine_kind
            ack_count = self._ack_count
            iface = self.iface
            server_cfg = self.server_cfg
            leases = self.leases
            saved = self.saved_iface

        logs, cursor = self.logs_since(since)
        stats = dict(leases.stats()) if leases else {
            "pool": 0, "bound": 0, "offered": 0, "bad": 0, "free": 0,
        }
        rows = leases.rows() if leases else []
        if state != STATE_RUNNING:
            # 停了以后这些只是历史记录，别让界面显示成“正在生效”
            for row in rows:
                row["bound"] = False
                row["remaining"] = 0
                row["state"] = "历史"
            stats["bound"] = 0
            stats["free"] = max(0, stats["pool"] - stats["offered"])

        return {
            "state": state,
            "error": error,
            "running": state == STATE_RUNNING,
            "uptime": int(time.time() - started_at) if started_at and state == STATE_RUNNING else 0,
            "engine": engine_kind,
            "acks": ack_count,
            "iface": (
                {
                    "name": iface.name,
                    "service": iface.service,
                    "mac": iface.mac,
                    "ipv4": iface.ipv4,
                    "netmask": iface.netmask,
                    "link": iface.link,
                }
                if iface
                else None
            ),
            "config": (
                {
                    "server_ip": server_cfg.server_ip,
                    "network": server_cfg.network,
                    "netmask": server_cfg.netmask,
                    "pool_start": server_cfg.pool_start,
                    "pool_end": server_cfg.pool_end,
                    "lease": server_cfg.lease_seconds,
                    "routers": server_cfg.routers,
                    "dns": server_cfg.dns,
                    "domain": server_cfg.domain,
                }
                if server_cfg
                else None
            ),
            "saved_iface": bool(saved),
            "stats": stats,
            "leases": rows,
            "logs": logs,
            "cursor": cursor,
            "capabilities": self.capabilities(),
            "server_time": time.time(),
        }

    # ------------------------------------------------------------------

    @staticmethod
    def parse_pool(spec: str, network: ipaddress.IPv4Network) -> Tuple[str, str]:
        base = str(network.network_address).rsplit(".", 1)[0]

        def expand(token: str) -> str:
            token = (token or "").strip()
            if token.count(".") == 3:
                return token
            if token.startswith(".") and token.count(".") == 1:
                return base + token
            if token.isdigit():
                return base + "." + token
            raise SessionError("看不懂的地址池写法：%r（例：.100-.200）" % token)

        if "-" in spec:
            left, right = spec.split("-", 1)
            start, end = expand(left), expand(right)
        else:
            start = expand(spec)
            end = start
        for ip in (start, end):
            try:
                addr = ipaddress.IPv4Address(ip)
            except ValueError:
                raise SessionError("地址不合法：%r" % ip)
            if addr not in network:
                raise SessionError("地址池 %s 不在子网 %s 内" % (ip, network))
            if addr == network.network_address or addr == network.broadcast_address:
                raise SessionError("%s 是网络地址/广播地址，不能分给设备" % ip)
        if int(ipaddress.IPv4Address(end)) < int(ipaddress.IPv4Address(start)):
            raise SessionError("地址池起点比终点大：%s" % spec)
        if int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)) > 4094:
            raise SessionError("地址池太大（最多 4094 个）")
        return start, end


def as_public_dict(session: Session) -> Dict[str, object]:
    """给 API 用的简化状态。"""
    snap = session.snapshot(0)
    snap.pop("logs", None)
    return snap


__all__ = [
    "Session",
    "SessionConfig",
    "SessionError",
    "DaemonPool",
    "DEFAULT_SUBNET",
    "DEFAULT_STATE",
    "asdict",
]
