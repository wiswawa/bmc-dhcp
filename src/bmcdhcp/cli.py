"""命令行入口：`bmcd run / ifaces / probe / find-static / leases / selftest / web`。

真正干活的是 session.Session，CLI 只负责：解析参数、挑网卡、打印。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from . import __version__
from . import dhcp as D
from . import discover, engines, scan, simulate, ui, webapp
from . import iface as I
from .session import DEFAULT_STATE, DEFAULT_SUBNET, Session, SessionConfig, SessionError

VERSION = __version__

# 出厂常见静态网段：BMC 拿不到 DHCP 时经常退回这些地址
STATIC_CANDIDATES = [
    "192.168.0.0/24",
    "192.168.1.0/24",
    "10.0.0.0/24",
    "192.168.100.0/24",
    "172.16.0.0/24",
]


# ----------------------------------------------------------------------
# 小工具
# ----------------------------------------------------------------------

def parse_pool(spec: str, network: ipaddress.IPv4Network) -> Tuple[str, str]:
    """保留这个函数名给外部脚本/测试用，实现搬到 Session.parse_pool。"""
    return Session.parse_pool(spec, network)


def human_time(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return "%ds" % seconds
    if seconds < 5400:
        return "%dm" % (seconds // 60)
    return "%.1fh" % (seconds / 3600)


def confirm(prompt: str, default: bool = True) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input("%s %s " % (prompt, suffix)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not answer:
        return default
    return answer in ("y", "yes", "是")


def print_hint(console: ui.Console) -> None:
    console.raw()
    console.raw(console.c("  还没收到任何 DHCP 请求，按顺序排查：", ui.YELLOW))
    if I.IS_WINDOWS:
        console.raw("   1. 网线真的插在这个口上吗：  Get-NetAdapter 看 Status 是不是 Up")
    else:
        console.raw("   1. 网线真的插在这个口上吗：  ifconfig <接口> | grep status   （要看到 active）")
    console.raw("   2. BMC 是不是被设成静态 IP 了：出厂常见 192.168.0.120 / 192.168.1.100")
    console.raw("      → 另开一个终端跑：  bmcd scan   （界面里是「IP 探测」标签）")
    console.raw("   3. BMC 的 DHCP 开关是不是关着（iDRAC/iLO 里 Network → IPv4 → Enable DHCP）")
    console.raw("   4. 有的机器 BMC 口和网卡口是共享的（shared LOM），要插对口号，或换 dedicated 口")
    console.raw("   5. 交换机/VLAN：BMC 口如果要 802.1Q tag，直连也得配")
    console.raw()


# ----------------------------------------------------------------------
# run
# ----------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    console = ui.Console(color=not args.no_color, quiet=args.quiet)
    cfg = SessionConfig(
        iface=args.iface,
        subnet=args.subnet,
        server_ip=args.server_ip,
        pool=args.pool,
        lease_seconds=args.lease,
        dns=list(args.dns or []),
        routers=list(args.router or []),
        auto_router=not args.no_router,
        domain=args.domain,
        hostname_prefix=args.hostname_prefix,
        engine=args.engine,
        echo=not args.no_echo,
        configure=not args.no_configure,
        restore=not args.no_restore,
        state_path=os.path.expanduser(args.state),
        probe_retry=args.probe_retry,
    )

    # --- 选网卡 ---
    if not cfg.iface:
        candidates = I.ethernet_candidates()
        if not candidates:
            ports = [
                i for i in I.enumerate_all()
                if not i.name.startswith(("lo", "gif", "stf", "utun", "awdl", "llw", "ap1", "anpi", "bridge"))
                and not i.is_wifi
            ]
            listing = "，".join("%s(%s)" % (i.name, i.link or "无状态") for i in ports) or "无"
            console.err("没有『有链路』的以太网口。当前候选：%s" % listing)
            console.raw("  ① 网线插好没有（ifconfig <口> | grep status 要看到 active）")
            console.raw("  ② USB 网卡识别了没有（./bmcd ifaces）")
            console.raw("  ③ 也可以强指：./bmcd --iface en7")
            return 2
        if len(candidates) > 1 and not args.yes and sys.stdin.isatty():
            console.raw("检测到多个以太网口，选一个接 BMC 的口：")
            for idx, iface in enumerate(candidates, 1):
                console.raw("  %d) %s%s" % (idx, iface.label(), " *默认" if idx == 1 else ""))
            try:
                raw = input("请输入编号 [1]: ").strip()
            except (EOFError, KeyboardInterrupt):
                raw = ""
            try:
                choice = int(raw or "1")
            except ValueError:
                choice = 1
            chosen = candidates[choice - 1] if 1 <= choice <= len(candidates) else candidates[0]
        else:
            chosen = candidates[0]
        if chosen.is_default_route and not args.yes:
            console.warn("%s 是你上网用的默认路由口，改它的地址会断网！" % chosen.name)
            if not confirm("确定还要用它吗？", default=False):
                console.raw("已取消。换个口试试：./bmcd ifaces")
                return 2
        cfg.iface = chosen.name

    # --- 端口冲突 ---
    owners = I.dhcp_port_owner()
    if owners:
        console.warn("UDP/67 已被占用：%s" % "，".join(owners[:2]))
        console.warn("系统「互联网共享」开着会抢同一个端口，建议先关掉。")
        if args.kill_conflict:
            for owner in owners:
                if "bootpd" in owner:
                    subprocess.run(["killall", "bootpd"], capture_output=True)
                    console.info("已停掉 bootpd（系统需要时会自己重启）")
                    break

    # --- 日志 ---
    jsonl = None
    if args.json_log:
        try:
            jsonl = open(os.path.expanduser(args.json_log), "a", encoding="utf-8")
        except OSError as exc:
            console.err("打不开 --json-log：%s" % exc)

    def log(level: str, text: str) -> None:
        if jsonl:
            try:
                jsonl.write(json.dumps({"ts": time.time(), "level": level, "text": text},
                                       ensure_ascii=False) + "\n")
                jsonl.flush()
            except OSError:
                pass
        if args.quiet and level not in ("warn", "err", "ok"):
            return
        if level == "err":
            console.err(text)
        elif level == "warn":
            console.warn(text)
        elif level == "ok":
            console.ok(text)
        else:
            console.info(text)

    opened = {"done": False}

    def on_found(url: str) -> None:
        if args.open and not opened["done"]:
            opened["done"] = True
            subprocess.run(["open", url], capture_output=True)

    session = Session(cfg, log=log, on_found=on_found)
    left = session.recover_backup()          # 上次被强杀留下的网卡配置
    if left:
        log("warn" if "失败" in left else "info", left)

    console.raw()
    console.raw(console.c("  BMC 临时 DHCP  v%s" % VERSION, ui.BOLD))
    console.raw("  网卡   %s" % (cfg.iface or "自动"))
    console.raw("  子网   %s   地址池 %s" % (cfg.subnet, cfg.pool or "默认 .100-.200"))
    console.raw("  租期   %s   引擎 %s" % (human_time(cfg.lease_seconds), cfg.engine))
    console.raw()

    try:
        session.start()
    except SessionError:
        # Session 内部已经把原因打进日志了，这里不重复
        if jsonl:
            jsonl.close()
        return 2

    snap = session.snapshot(0)
    conf = snap.get("config") or {}
    console.ok(
        "已就绪：%s 服务 %s，地址池 %s-%s"
        % (snap["iface"]["name"], conf.get("server_ip"), conf.get("pool_start"), conf.get("pool_end"))
    )
    console.raw()

    stop_signal = threading.Event()

    def _on_signal(*_: object) -> None:
        stop_signal.set()

    import signal as _signal

    for sig in [x for x in (getattr(_signal, "SIGTERM", None),
                            getattr(_signal, "SIGHUP", None)) if x is not None]:
        try:
            _signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass

    hint_at = time.time() + (args.hint_after or 18)
    warned = False
    next_status = time.time() + (args.status_interval or 0)
    try:
        while not stop_signal.is_set():
            time.sleep(0.4)
            snap = session.snapshot(0)
            now = time.time()
            if args.duration and now - session.started_at >= args.duration:
                console.info("已到 --duration，收工")
                break
            if not warned and snap["acks"] == 0 and now >= hint_at:
                print_hint(console)
                warned = True
            if args.status_interval and now >= next_status:
                next_status = now + args.status_interval
                stats = snap["stats"]
                console.info(
                    "状态：绑定 %d，OFFER %d，空闲 %d / 共 %d"
                    % (stats["bound"], stats["offered"], stats["free"], stats["pool"])
                )
                console.raw(ui.lease_table(console, snap["leases"]))
    except KeyboardInterrupt:
        console.raw()
        console.info("收到 Ctrl-C，正在收尾…")
    finally:
        session.shutdown()
        if jsonl:
            try:
                jsonl.close()
            except OSError:
                pass

    snap = session.snapshot(0)
    console.raw()
    console.raw(console.c("  本次拿到的地址", ui.BOLD))
    console.raw(ui.lease_table(console, snap["leases"]))
    console.raw()
    stats = snap["stats"]
    console.raw("  共绑定 %d 个，状态文件 %s" % (stats["bound"], cfg.state_path))
    console.raw()
    return 0


# ----------------------------------------------------------------------
# 其他子命令
# ----------------------------------------------------------------------

def cmd_ifaces(args: argparse.Namespace) -> int:
    console = ui.Console(color=not args.no_color)
    ifaces = I.enumerate_all()
    report = I.winnet.adapter_report() if I.IS_WINDOWS else {}
    if getattr(args, "json", False):
        payload = {
            "platform": "windows" if I.IS_WINDOWS else "macos",
            "source": report.get("source", ""),
            "error": report.get("error", ""),
            "sources": report.get("sources", []),
            "ifaces": [
                {
                    "name": i.name, "service": i.service, "mac": i.mac,
                    "ipv4": i.ipv4, "netmask": i.netmask, "link": i.link,
                    "has_link": i.has_link, "wifi": i.is_wifi,
                    "virtual": i.virtual, "tunnel": i.tunnel,
                    "loopback": i.loopback, "source": i.source,
                }
                for i in ifaces
            ],
            "candidates": [i.name for i in I.ethernet_candidates(ifaces)],
        }
        console.raw(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if payload["ifaces"] else 1

    rows = []
    for iface in ifaces:
        rows.append([
            iface.name,
            iface.service or "-",
            iface.mac or "-",
            iface.ipv4 or "-",
            iface.link or ("active" if iface.has_link else "无链路"),
            "是" if iface.is_default_route else "",
        ])
    console.raw(console.table(["接口", "网络服务", "MAC", "IPv4", "链路", "默认路由"], rows))
    console.raw()
    # 枚举源：读不到网卡时这几行就是唯一线索（Windows 有三级回退）
    if report:
        sources = report.get("sources") or []
        if sources:
            for item in sources:
                mark = "OK " if item.get("ok") else ("跳过" if item.get("skipped") else "失败")
                console.raw("  [%s] %-10s %3d 条 %5dms  %s" % (
                    mark, item.get("source", "?"), int(item.get("count") or 0),
                    int(item.get("ms") or 0), item.get("error") or ""))
        if report.get("error"):
            console.raw(console.c("  枚举问题：" + str(report["error"]), ui.YELLOW))
    cands = I.ethernet_candidates(ifaces)
    if cands:
        console.raw("可能接 BMC 的口：" + "，".join(i.name for i in cands))
    elif ifaces:
        console.raw(console.c("有网卡，但没有「有链路 + 非虚拟 + 非 Wi-Fi」的口"
                              "（虚拟网卡就勾「显示所有网卡」，或直接写网卡名）", ui.YELLOW))
    else:
        console.raw(console.c("一张网卡都没读到 —— 看上面每级枚举源的原因", ui.YELLOW))
        return 1
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    console = ui.Console(color=not args.no_color)
    ips = list(args.ips)
    if args.cidr:
        ips.extend([str(h) for h in ipaddress.IPv4Network(args.cidr, strict=False).hosts()])
    if not ips:
        console.err("给个 IP 或 --cidr")
        return 2
    console.info("探测 %d 个地址…" % len(ips))
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(ips)))) as pool:
        results = list(pool.map(lambda ip: discover.probe(ip, timeout=0.9), ips))
    # ARP 查询失败时，「没有 MAC」并不等于「没有设备」—— 结果整体不可信，
    # 必须先把这条原因说出来，别让用户对着网线折腾。
    arp_errors = sorted({str(getattr(r, "arp_error", "") or "") for r in results} - {""})
    if arp_errors:
        console.warn("ARP 查询失败（%s）：结果可能不全，先确认 arp 命令可用"
                     % "；".join(arp_errors[:2]))
    alive = [r for r in results if r.alive]
    if not alive:
        if arp_errors:
            console.warn("都没响应，但 ARP 查询本身也失败了（见上一行）—— "
                         "先修好 arp 命令再判断网线/网段/防火墙。")
        else:
            console.warn("都没响应。确认网线/网段/防火墙。")
        return 1
    for fp in alive:
        console.raw()
        console.raw(console.c("%s  %s" % (fp.ip, fp.summary()), ui.BOLD))
        if fp.mac:
            console.raw("   MAC   %s" % fp.mac)
        if fp.tls_cn:
            console.raw("   TLS   CN=%s" % fp.tls_cn)
        if fp.http:
            console.raw("   HTTP  %s %s" % (fp.http.status, fp.http.server))
            if fp.http.title:
                console.raw("   标题  %s" % fp.http.title)
            if fp.http.location:
                console.raw("   跳转  %s" % fp.http.location)
        if fp.rmcp_detail:
            console.raw("   IPMI  %s" % fp.rmcp_detail)
        if fp.url:
            console.raw("   管理  %s" % console.c(fp.url, ui.CYAN))
        if fp.identity.creds:
            console.raw("   账号  %s" % " 或 ".join(fp.identity.creds))
    return 0


def cmd_find_static(args: argparse.Namespace) -> int:
    console = ui.Console(color=not args.no_color)
    if not I.is_root():
        console.err("要临时给网卡加地址别名，需要管理员权限："
                    "%s" % ("右键以管理员身份运行" if I.IS_WINDOWS else "sudo ./bmcd find-static"))
        return 2
    iface = I.find_by_name(args.iface) if args.iface else None
    if iface is None:
        cands = I.ethernet_candidates()
        if not cands:
            console.err("没有可用以太网口（先 ./bmcd ifaces 看一眼）")
            return 2
        iface = cands[0]
    console.info("在 %s 上扫描出厂静态网段：%s" % (iface.name, ", ".join(args.subnets)))

    found: List[Tuple[str, str]] = []
    added: List[Tuple[str, str, bool]] = []
    try:
        for cidr in args.subnets:
            net = ipaddress.IPv4Network(cidr, strict=False)
            host = str(net.network_address + 1)
            added_alias = False
            if not (iface.ipv4 and ipaddress.IPv4Address(iface.ipv4) in net):
                I.add_alias(iface.name, host, str(net.netmask))
                added_alias = True
                time.sleep(0.3)
            hits = [
                (ip, mac) for ip, mac in discover.sweep(str(net), iface=iface.name, timeout=args.timeout)
                if ip != (iface.ipv4 or "")
            ]
            if added_alias:
                added.append((host, cidr, bool(hits)))
            found.extend(hits)
            if hits:
                console.ok("%s 发现 %d 台：%s" % (cidr, len(hits), ", ".join(h[0] for h in hits)))
            else:
                console.info("%s 没有设备" % cidr)
                table_error = str(getattr(discover, "LAST_ARP_TABLE_ERROR", "") or "")
                if table_error:
                    # 「一台都没有」和「连 ARP 表都读不出来」完全是两回事，必须说清楚
                    console.warn("  ARP 表读不出来（%s）：这一轮的结果不作数" % table_error)
    finally:
        for host, _cidr, has_hits in added:
            if not has_hits:
                I.remove_alias(iface.name, host)

    kept = [host for host, _cidr, has_hits in added if has_hits]
    if kept:
        console.raw()
        console.info("为了让下面这些地址现在就能连，临时地址保留了：%s" % ", ".join(kept))
        console.info("用完后摘掉：sudo ifconfig %s %s"
                     % (iface.name, " ".join("-alias " + h for h in kept)))

    if not found:
        console.warn("没扫到。BMC 可能：① 已在别的网段 ② 管理口没启用 ③ 需要交换机/斜线")
        return 1

    console.raw()
    with ThreadPoolExecutor(max_workers=8) as pool:
        prints = list(pool.map(lambda t: discover.probe(t[0], timeout=0.9), found))
    for fp in prints:
        console.raw(console.c("%-15s %s  %s" % (fp.ip, fp.mac or "-", fp.summary()), ui.BOLD))
        if fp.url:
            console.raw("                管理 %s" % console.c(fp.url, ui.CYAN))
        if fp.identity.creds:
            console.raw("                账号 %s" % " 或 ".join(fp.identity.creds))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """找「已经配好地址」的机器：被动侦听 + 扫网段 + 识别。"""
    console = ui.Console(color=not args.no_color)
    if not I.is_root():
        console.err("IP 探测要管理员权限（抓 ARP 包、临时给网卡加地址）：%s"
                    % ("右键以管理员身份运行 bmcd.cmd" if I.IS_WINDOWS else "sudo ./bmcd scan"))
        return 2
    iface = None
    if args.iface:
        iface = I.find_by_name(args.iface) or I.find_by_service(args.iface)
        if iface is None:
            console.err("找不到网卡 %s（./bmcd ifaces 看一眼）" % args.iface)
            return 2
    else:
        cands = I.ethernet_candidates()
        if not cands:
            console.err("没有『有链路』的以太网口：先把网线插好")
            return 2
        iface = cands[0]

    passive = args.listen > 0
    guess = not args.no_guess
    neighbors = not args.no_neighbors
    cidrs = list(args.cidr) or scan.default_cidrs(iface)
    scanner = scan.Scanner()
    console.raw(console.c("  在 %s 上找已经配好 IP 的机器" % iface.name, ui.BOLD))
    console.raw("  网段   %s" % (", ".join(cidrs) if not args.no_active else "（不扫网段）"))
    console.raw("  侦听   %s" % ("%g 秒" % args.listen if passive else "关闭"))
    console.raw("  猜地址 %s（%d 个常见出厂地址）" % ("开" if guess else "关", len(scan.GUESS_TARGETS)))
    console.raw("  邻居   %s（IPv6 all-nodes + 广播 ICMP）" % ("开" if neighbors else "关"))
    console.raw()
    try:
        scanner.start({
            "iface": iface.name,
            "cidrs": cidrs,
            "passive": passive,
            "guess": guess,
            "neighbors": neighbors,
            "active": not args.no_active,
            "probe": not args.no_probe,
            "duration": args.listen if passive else 1,
        })
    except scan.ScanError as exc:
        console.err(str(exc))
        return 2

    last = ""
    try:
        while True:
            snap = scanner.snapshot()
            msg = str(snap.get("message") or "")
            if msg and msg != last:
                last = msg
                console.info(msg)
            if snap.get("state") != "running":
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        console.warn("停止扫描…")
        scanner.stop()
        for _ in range(30):
            if scanner.snapshot().get("state") != "running":
                break
            time.sleep(0.1)
    snap = scanner.snapshot()

    for err in snap.get("errors") or []:
        console.warn(str(err))

    hits = snap.get("hits") or []
    if not hits:
        console.warn("没扫到任何设备。常见原因：")
        console.raw("   ① 网线没插在 %s 上（ifconfig %s | grep status 要是 active）" % (iface.name, iface.name))
        console.raw("   ② 地址可能是任何值：--cidr 192.168.0.0/16（约 1～2 分钟），"
                    "或断电重启 BMC 让它自己喊一遍（-l 30 只侦听）")
        console.raw("   ③ 交换机/AP 做了客户端隔离，广播不通：直连一根线最稳")
        console.raw("   ④ BMC 网口没启用 / 机器还没上电")
        if args.cleanup:
            scanner.cleanup()
        return 1

    console.raw()
    rows = []
    for hit in hits:
        rows.append([
            str(hit.get("ip", "")),
            str(hit.get("mac") or "-"),
            str(hit.get("vendor") or "-") + (
                "(%s)" % hit.get("confidence") if hit.get("confidence") else ""),
            str(hit.get("hostname") or "-"),
            ",".join(str(s) for s in (hit.get("sources") or [])),
        ])
    console.raw(console.table(["IP", "MAC", "厂商", "主机名", "发现方式"], rows))
    console.raw()
    for hit in hits:
        console.raw(console.c("%-15s %s" % (hit.get("ip"), hit.get("summary") or ""), ui.BOLD))
        if hit.get("url"):
            console.raw("                管理 %s" % console.c(str(hit["url"]), ui.CYAN))
        if hit.get("creds"):
            console.raw("                账号 %s" % " 或 ".join(str(c) for c in hit["creds"]))
        for ev in (hit.get("evidence") or [])[:4]:
            console.raw("                · %s" % ev)

    v6 = snap.get("v6") or []
    if v6:
        console.raw()
        console.info("IPv6 邻居（跟它 IPv4 配成什么无关，能直连）：")
        for item in v6:
            console.raw("   %-42s %s" % (console.c(str(item.get("addr")), ui.CYAN),
                                         item.get("link") or ""))

    aliases = snap.get("aliases") or []
    if aliases:
        console.raw()
        console.info("为了让上面这些地址现在就能连，临时加了：%s"
                     % "，".join("%s %s" % (a["iface"], a["ip"]) for a in aliases))
        if args.cleanup:
            removed = scanner.cleanup()
            console.info("已摘掉：%s" % ("，".join(removed) or "无"))
        else:
            console.info("用完摘掉：sudo ifconfig %s %s"
                         % (iface.name, " ".join("-alias " + a["ip"] for a in aliases)))
    return 0


def cmd_leases(args: argparse.Namespace) -> int:
    console = ui.Console(color=not args.no_color)
    path = os.path.expanduser(args.state)
    if not os.path.exists(path):
        console.warn("还没有状态文件：%s" % path)
        return 1
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        console.err("读取失败：%s" % exc)
        return 1
    rows = []
    for row in data.get("leases") or []:
        rows.append([
            str(row.get("ip", "")),
            str(row.get("mac", "")),
            str(row.get("hostname", "")),
            str(row.get("vendor_guess", "")),
            str(row.get("url", "")),
        ])
    console.raw(console.table(["IP", "MAC", "主机名", "厂商", "管理地址"], rows))
    return 0


def _loopback_session_check() -> Tuple[bool, str]:
    """用真实的 Session + 高端口 UDP 引擎，跑一遍 start → DORA → stop。"""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.5)
    cfg = SessionConfig(
        iface="lo0",
        subnet="127.0.0.0/8",
        server_ip="127.0.0.2",
        pool="127.0.0.1-127.0.0.1",
        lease_seconds=120,
        configure=False,
        state_path="",
        engine="udp",
        probe_retry=0,
    )

    def factory(kind: str, iface: object, core: object, log: object) -> engines.UdpEngine:
        return engines.UdpEngine(
            iface, core, log,                     # type: ignore[arg-type]
            bind_ip="127.0.0.1", bind_port=0,
            reply_targets=[client.getsockname()],
        )

    session = Session(cfg, engine_factory=factory, probe_fn=lambda *a, **k: _NullFP(),
                      iface_lookup=lambda name: I.Interface(name=name, ipv4="127.0.0.1",
                                                             netmask="255.0.0.0", loopback=True))
    try:
        session.start()
    except SessionError as exc:
        client.close()
        session.shutdown()
        return False, "Session 启动失败：%s" % exc
    server_address = session.engine._recv.getsockname()

    def recv(kind: int, tries: int = 6) -> Optional[D.DHCPMessage]:
        for _ in range(tries):
            try:
                data, _ = client.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                msg = D.DHCPMessage.parse(data)
            except ValueError:
                continue
            if msg.msg_type == kind:
                return msg
        return None

    try:
        disc = D.build_client_packet(D.DISCOVER, "02:00:00:00:00:42", 0x99)
        client.sendto(disc.pack(), server_address)
        offer = recv(D.OFFER)
        if not offer:
            return False, "Session 收不到 OFFER"
        req = D.build_client_packet(
            D.REQUEST, "02:00:00:00:00:42", 0x99,
            requested_ip=offer.yiaddr, server_id=offer.get_ip(D.O_SERVER_ID),
        )
        client.sendto(req.pack(), server_address)
        ack = recv(D.ACK)
        if not ack:
            return False, "Session 收不到 ACK"
        snap = session.snapshot(0)
        if not any(l["state"] == "已绑定" for l in snap["leases"]):
            return False, "Session 快照里没有已绑定租约"
        return True, "租约 %s，状态 %s" % (ack.yiaddr, snap["state"])
    finally:
        client.close()
        session.shutdown()


class _NullFP:
    alive = False
    ports: List[int] = []
    mac = ""
    url = ""
    summary = lambda self: "skip"  # noqa: E731

    def __init__(self) -> None:
        from .vendors import Identity

        self.identity = Identity()
        self.tls_cn = ""
        self.rmcp = False
        self.rmcp_detail = ""
        self.http = None
        self.elapsed = 0.0
        self.ip = ""


def cmd_selftest(args: argparse.Namespace) -> int:
    """不碰真网卡、不需要 root 的自检：编解码 + 状态机 + 本机 UDP DORA + Session 生命周期。"""
    console = ui.Console(color=not args.no_color)
    failures = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        mark = console.c("PASS", ui.GREEN) if ok else console.c("FAIL", ui.RED)
        console.raw("[%s] %s%s" % (mark, name, ("  " + detail) if detail else ""))
        if not ok:
            failures += 1

    pkt = D.build_client_packet(
        D.DISCOVER, "aa:bb:cc:11:22:33", 0xDEADBEEF,
        vendor_class="iDRAC", hostname="idrac-test", requested_ip="10.99.0.105",
    )
    blob = pkt.pack()
    back = D.DHCPMessage.parse(blob)
    check("报文 round-trip", back.xid == 0xDEADBEEF and back.mac == "aa:bb:cc:11:22:33",
          "%d bytes" % len(blob))
    check("option 60 解析", back.get_str(D.O_VENDOR_CLASS) == "iDRAC")
    check("option 50 解析", back.get_ip(D.O_REQUESTED_IP) == "10.99.0.105")

    from .core import ServerConfig, ServerCore
    from .leases import LeaseManager

    cfg = ServerConfig(
        server_ip="10.99.0.1", network="10.99.0.0/24",
        pool_start="10.99.0.100", pool_end="10.99.0.110", lease_seconds=120,
    )
    leases = LeaseManager(
        server_ip=cfg.server_ip, network=cfg.network,
        pool_start=cfg.pool_start, pool_end=cfg.pool_end, lease_seconds=120, state_path=None,
    )
    events: List[Dict[str, object]] = []
    core = ServerCore(cfg, leases, on_event=events.append)
    replies = core.handle(D.DHCPMessage.parse(blob), "aa:bb:cc:11:22:33")
    ok_offer = bool(replies) and replies[0].msg.msg_type == D.OFFER
    ip = replies[0].msg.yiaddr if replies else ""
    check("DISCOVER → OFFER", ok_offer, "分配 %s" % ip)
    check("OFFER 里有子网掩码/租期",
          bool(replies and replies[0].msg.get_ip(D.O_SUBNET_MASK)
               and replies[0].msg.get_u32(D.O_LEASE_TIME)))

    req = D.build_client_packet(
        D.REQUEST, "aa:bb:cc:11:22:33", 0xDEADBEEF,
        requested_ip=ip, server_id=cfg.server_ip, vendor_class="iDRAC",
    )
    replies2 = core.handle(D.DHCPMessage.parse(req.pack()), "aa:bb:cc:11:22:33")
    check("REQUEST → ACK", bool(replies2) and replies2[0].msg.msg_type == D.ACK,
          "地址 %s" % (replies2[0].msg.yiaddr if replies2 else "-"))
    check("租约已绑定", leases.get(ip) is not None and leases.get(ip).bound)

    replies3 = core.handle(D.DHCPMessage.parse(blob), "aa:bb:cc:11:22:33")
    check("同一 MAC 拿到同一 IP", bool(replies3) and replies3[0].msg.yiaddr == ip,
          replies3[0].msg.yiaddr if replies3 else "-")

    try:
        ok_udp, detail = _loopback_dora()
    except Exception as exc:                  # noqa: BLE001
        ok_udp, detail = False, "异常：%s" % exc
    check("本机 UDP 端到端 DORA", ok_udp, detail)

    try:
        ok_sess, detail2 = _loopback_session_check()
    except Exception as exc:                  # noqa: BLE001
        ok_sess, detail2 = False, "异常：%s" % exc
    check("Session 生命周期（启动→租约→停止）", ok_sess, detail2)

    try:
        ok_enum, detail_enum = _adapter_enum_check()
    except Exception as exc:                  # noqa: BLE001
        ok_enum, detail_enum = False, "异常：%s" % exc
    check("网卡枚举（Windows 是 ctypes→PowerShell→ipconfig 三级）", ok_enum, detail_enum)

    console.raw()
    if failures:
        console.err("%d 项失败" % failures)
        return 1
    console.ok("全部通过")
    return 0


def _adapter_enum_check() -> Tuple[bool, str]:
    """自检里的网卡枚举：Windows 上把三级源每级结果都打出来。

    读不到网卡时以前只有一句「没有检测到有链路的以太网口（网线插了吗？）」，
    把「命中了 20 秒超时/策略拦截」误判成「没插网线」。这里要求每级都留痕。
    """
    if I.IS_WINDOWS:
        records = I.winnet.adapter_records(force=True)
        report = I.winnet.adapter_report()
        bits = []
        for item in report.get("sources") or []:
            bits.append("%s=%s(%d 条,%sms)" % (
                item.get("source"),
                "ok" if item.get("ok") else ("skip" if item.get("skipped") else "fail"),
                int(item.get("count") or 0), int(item.get("ms") or 0)))
        return bool(records), "%d 张卡；%s" % (
            len(records), "，".join(bits) or "无逐源报告")
    ifaces = I.enumerate_all()
    return bool(ifaces), "%d 个接口（%s）" % (
        len(ifaces), "，".join(i.name for i in ifaces[:6]))


def _loopback_dora() -> Tuple[bool, str]:
    from .core import ServerConfig, ServerCore
    from .leases import LeaseManager

    cfg = ServerConfig(
        server_ip="10.99.0.1", network="10.99.0.0/24",
        pool_start="10.99.0.100", pool_end="10.99.0.110", lease_seconds=120,
        routers=["10.99.0.1"],
    )
    leases = LeaseManager(
        server_ip=cfg.server_ip, network=cfg.network,
        pool_start=cfg.pool_start, pool_end=cfg.pool_end, lease_seconds=120, state_path=None,
    )
    core = ServerCore(cfg, leases)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(0.6)
    fake = I.Interface(name="lo0", ipv4="127.0.0.1", netmask="255.0.0.0")
    engine = engines.UdpEngine(
        fake, core, lambda level, msg: None,
        bind_ip="127.0.0.1", bind_port=0,
        reply_targets=[client.getsockname()],
    )
    ready = threading.Event()
    thread = threading.Thread(target=engine.start, args=(ready.set,), daemon=True)
    thread.start()

    def recv_expect(expected: int) -> Optional[D.DHCPMessage]:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                data, _ = client.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                msg = D.DHCPMessage.parse(data)
            except ValueError:
                continue
            if msg.msg_type == expected:
                return msg
        return None

    try:
        if not ready.wait(3):
            return False, "UDP 自检引擎未能就绪"
        server_address = engine._recv.getsockname()
        disc = D.build_client_packet(D.DISCOVER, "02:00:00:00:00:99", 0x12345678)
        offered: Optional[D.DHCPMessage] = None
        for _ in range(5):
            client.sendto(disc.pack(), server_address)
            offered = recv_expect(D.OFFER)
            if offered:
                break
        if not offered:
            return False, "没收到 OFFER（engine 没起来？）"
        req = D.build_client_packet(
            D.REQUEST, "02:00:00:00:00:99", 0x12345678,
            requested_ip=offered.yiaddr, server_id=cfg.server_ip,
        )
        acked: Optional[D.DHCPMessage] = None
        for _ in range(3):
            client.sendto(req.pack(), server_address)
            acked = recv_expect(D.ACK)
            if acked:
                break
        if not acked:
            return False, "没收到 ACK"
        if acked.yiaddr != offered.yiaddr:
            return False, "ACK 的地址和 OFFER 不一致"
        return True, "OFFER/ACK = %s，租期 %ss" % (
            acked.yiaddr, acked.get_u32(D.O_LEASE_TIME))
    finally:
        client.close()
        engine.stop()
        thread.join(timeout=2)


def cmd_simulate(args: argparse.Namespace) -> int:
    return simulate.run(
        iface_name=args.iface,
        client_iface=args.client_iface,
        subnet=args.subnet,
        with_web=not args.no_web,
        keep=args.keep,
        color=not args.no_color,
    )


def cmd_web(args: argparse.Namespace) -> int:
    """在前台跑 Web 服务（App 会用它；也可以手动 `bmcd web` 再用浏览器开）。"""
    return webapp.main(
        host=args.host,
        port=args.port,
        open_browser=args.open,
        print_url=True,
        token=args.token,
    )


# ----------------------------------------------------------------------
# argparse
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bmcd",
        description="给新机器 BMC / IPMI 口发临时 DHCP 地址，在 Mac 上直接连上管理页面。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""例子:
  ./bmcd                          自动挑口，10.99.0.0/24，池 .100-.200
  ./bmcd --iface en7 --open       指定网卡，识别到 BMC 就打开浏览器
  ./bmcd --subnet 192.168.50.0/24 --pool .20-.60 --lease 600
  ./bmcd find-static              扫 BMC 出厂静态网段（192.168.0.x 之类）
  ./bmcd scan                     找「已经配好静态 IP」的机器（侦听 + 扫网段 + 识别）
  ./bmcd probe 192.168.0.120      已知 IP 时直接识别厂商
  ./bmcd selftest                 不需要 root 的自检
  ./bmcd simulate                 没有 BMC 也能跑一遍完整链路（假 BMC）
  ./bmcd web --open               只用网页界面（GUI 后端的入口）
""",
    )
    parser.add_argument("--version", action="version", version="bmcd %s" % VERSION)
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--no-color", action="store_true", help="关闭彩色输出")
        p.add_argument("--json-log", default="", help="把事件写成 JSONL 追加到这个文件")
        p.add_argument("--state", default=DEFAULT_STATE, help="租约状态文件（默认 ~/.bmcd/state.json）")

    run = sub.add_parser("run", help="启动 DHCP 服务（默认子命令）")
    add_common(run)
    run.add_argument("--iface", default="", help="网卡名，如 en7（默认自动挑）")
    run.add_argument("--subnet", default=DEFAULT_SUBNET, help="子网 CIDR（默认 %s）" % DEFAULT_SUBNET)
    run.add_argument("--server-ip", default="", help="本机在这个子网里的地址（默认网关位 .1）")
    run.add_argument("--pool", default="", help="地址池，如 .100-.200")
    run.add_argument("--lease", type=int, default=300, help="租期秒数（默认 300）")
    run.add_argument("--dns", action="append", default=[], help="下发的 DNS，可多次给；默认不发")
    run.add_argument("--router", action="append", default=[], help="下发的网关，可多次给")
    run.add_argument("--no-router", action="store_true", help="完全不下发 option 3")
    run.add_argument("--domain", default="bmc.local", help="option 15 域名")
    run.add_argument("--hostname-prefix", default="bmc", help="给 BMC 起名用前缀")
    run.add_argument("--engine", default="auto", choices=["auto", "raw", "udp", "dnsmasq"],
                     help="发包引擎，默认 auto")
    run.add_argument("--no-echo", action="store_true", help="不回显 option 60/61（默认回显）")
    run.add_argument("--no-configure", action="store_true", help="不去改网卡地址，自己配好")
    run.add_argument("--no-restore", action="store_true", help="退出时不还原网卡配置")
    run.add_argument("--open", action="store_true", help="识别到 BMC 就自动用浏览器打开")
    run.add_argument("--duration", type=int, default=0, help="跑多少秒后自动退出")
    run.add_argument("--hint-after", type=int, default=18, help="多少秒没租约就打印排查提示")
    run.add_argument("--probe-retry", type=float, default=7.0, help="分配后多久再探测一次")
    run.add_argument("--status-interval", type=int, default=0, help="每隔多少秒打印一次租约表")
    run.add_argument("--kill-conflict", action="store_true", help="发现 bootpd 占用 67 时尝试 kill")
    run.add_argument("--yes", "-y", action="store_true", help="不问，直接用第一个候选网卡")
    run.add_argument("--quiet", action="store_true", help="少讲话")

    ifaces = sub.add_parser("ifaces", help="列出网卡和网络服务")
    ifaces.add_argument("--no-color", action="store_true")
    ifaces.add_argument("--json", action="store_true", help="机器可读输出（含逐源枚举报告）")

    probe = sub.add_parser("probe", help="识别已知 IP 的 BMC")
    probe.add_argument("ips", nargs="*", help="要探测的 IP")
    probe.add_argument("--cidr", default="", help="也可以整段扫，如 192.168.0.0/24")
    probe.add_argument("--no-color", action="store_true")

    fs = sub.add_parser("find-static", help="扫 BMC 出厂静态网段")
    fs.add_argument("--iface", default="", help="网卡名")
    fs.add_argument("--subnets", nargs="*", default=STATIC_CANDIDATES, help="候选网段")
    fs.add_argument("--timeout", type=float, default=1.5)
    fs.add_argument("--no-color", action="store_true")

    sc = sub.add_parser("scan", help="找已经配好静态 IP 的机器（被动侦听 + 扫网段 + 识别）")
    sc.add_argument("--iface", default="", help="网卡名（默认自动挑有链路的口）")
    sc.add_argument("--cidr", action="append", default=[],
                    help="要扫的网段，可多次给；默认出厂常见网段")
    sc.add_argument("--listen", type=float, default=scan.PASSIVE_DEFAULT,
                    help="被动侦听多少秒（0 = 不侦听），默认 %g" % scan.PASSIVE_DEFAULT)
    sc.add_argument("--no-guess", action="store_true",
                    help="不试「常见 BMC 出厂地址」那一批（默认会试，几十个包）")
    sc.add_argument("--no-neighbors", action="store_true",
                    help="不做 IPv6 邻居 / 广播探测（默认会做）")
    sc.add_argument("--no-active", action="store_true", help="只被动侦听/猜地址，不扫网段")
    sc.add_argument("--no-probe", action="store_true", help="扫到后不识别厂商/端口")
    sc.add_argument("--cleanup", action="store_true", help="跑完把临时地址摘掉")
    sc.add_argument("--no-color", action="store_true")

    ls = sub.add_parser("leases", help="看上次保存的租约")
    ls.add_argument("--state", default=DEFAULT_STATE)
    ls.add_argument("--no-color", action="store_true")

    st = sub.add_parser("selftest", help="自检（不需要 root）")
    st.add_argument("--no-color", action="store_true")

    sim = sub.add_parser("simulate", help="没有 BMC 也能跑一遍完整链路（假 BMC）")
    sim.add_argument("--iface", default="", help="服务端网卡（默认自动挑）")
    sim.add_argument("--client-iface", default="",
                     help="用哪块网卡发客户端报文（两块网卡对插时用，最真实）")
    sim.add_argument("--subnet", default="10.99.0.0/24")
    sim.add_argument("--no-web", action="store_true", help="跳过假管理页/厂商识别")
    sim.add_argument("--keep", action="store_true", help="跑完保留服务（方便同时开界面看）")
    sim.add_argument("--no-color", action="store_true")

    web = sub.add_parser("web", help="跑网页/图形后端的 HTTP 服务")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=0, help="0 表示自动挑空闲端口")
    web.add_argument("--token", default="", help="访问令牌（App 会传）")
    web.add_argument("--open", action="store_true", help="启动后打开浏览器")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    commands = {"run", "ifaces", "probe", "find-static", "scan", "leases",
                "selftest", "web", "simulate"}
    if not argv:
        argv = ["run"]
    elif argv[0] not in commands and argv[0] not in ("-h", "--help", "--version"):
        argv = ["run"] + argv
    args = parser.parse_args(argv)

    handler = {
        "run": cmd_run,
        "ifaces": cmd_ifaces,
        "probe": cmd_probe,
        "find-static": cmd_find_static,
        "scan": cmd_scan,
        "leases": cmd_leases,
        "selftest": cmd_selftest,
        "web": cmd_web,
        "simulate": cmd_simulate,
    }.get(args.command or "run", cmd_run)
    try:
        return handler(args)
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except BrokenPipeError:
        return 0
