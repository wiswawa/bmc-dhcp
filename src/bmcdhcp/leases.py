"""租约池：分配、粘性映射（同一台 BMC 每次拿同一个 IP）、持久化。

BMC 场景特殊点：
  * 一台机器只服务一个口，池子很小（20~100 个地址）就够；
  * 必须「粘性」：断电、重启、重插线后还能拿到上次那个地址，
    否则每次都要重新找 IP，工具就失去意义；
  * 租约要短（默认 300s），但粘性映射长期保留，两者分离。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from .stateio import atomic_write_json


@dataclass
class Lease:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""
    client_id: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    expiry: float = 0.0
    bound: bool = False
    offers: int = 0
    vendor_guess: str = ""
    confidence: str = ""
    open_ports: str = ""
    url: str = ""

    @property
    def remaining(self) -> int:
        return max(0, int(self.expiry - time.time()))

    def to_row(self) -> Dict[str, object]:
        d = asdict(self)
        d["remaining"] = self.remaining
        d["state"] = "已绑定" if self.bound else ("已 OFFER" if self.offers else "空闲")
        return d


class LeaseManager:
    def __init__(
        self,
        server_ip: str,
        network: str,
        pool_start: str,
        pool_end: str,
        lease_seconds: int = 300,
        state_path: Optional[str] = None,
    ) -> None:
        self.net = ipaddress.IPv4Network(network, strict=False)
        self.server_ip = server_ip
        self.lease_seconds = int(lease_seconds)
        self.state_path = state_path

        start = ipaddress.IPv4Address(pool_start)
        end = ipaddress.IPv4Address(pool_end)
        if start not in self.net or end not in self.net:
            raise ValueError("地址池 %s-%s 不在子网 %s 内" % (pool_start, pool_end, network))
        if int(end) < int(start):
            raise ValueError("地址池起点大于终点")
        if int(end) - int(start) > 4094:
            raise ValueError("地址池过大，最多 4094 个地址")

        self.pool: List[str] = [
            str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)
        ]
        self.leases: Dict[str, Lease] = {}      # ip -> Lease
        self.sticky: Dict[str, str] = {}        # mac -> ip（长期粘性）
        self.bad: Dict[str, float] = {}         # ip -> 解封时间（收到 DECLINE）
        self.leased_at: Dict[str, float] = {}   # ip -> OFFER 时间（防重复 offer 抢占）
        self._load_state()

    # ---------------- 查询 ----------------

    def get(self, ip: str) -> Optional[Lease]:
        return self.leases.get(ip)

    def by_mac(self, mac: str) -> Optional[Lease]:
        ip = self.sticky.get(mac)
        if ip and ip in self.leases:
            return self.leases[ip]
        for lease in self.leases.values():
            if lease.mac == mac:
                return lease
        return None

    def in_pool(self, ip: str) -> bool:
        return (ip in self.pool and ip != self.server_ip
                and ip not in (str(self.net.network_address), str(self.net.broadcast_address)))

    def is_bad(self, ip: str, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        until = self.bad.get(ip)
        if until is None:
            return False
        if until <= now:
            self.bad.pop(ip, None)
            return False
        return True

    def _free(self, ip: str, now: float) -> bool:
        if not self.in_pool(ip):
            return False
        if self.is_bad(ip, now):
            return False
        lease = self.leases.get(ip)
        if lease is None:
            return True
        # 还没过期（无论只是 OFFER 中的占位，还是已绑定）都不让别人抢
        return lease.expiry <= now

    def is_free_for(self, ip: str, mac: str, now: Optional[float] = None) -> bool:
        """地址能否交给这个 MAC：没人用、已过期、或本来就是它的。"""
        now = time.time() if now is None else now
        if not self.in_pool(ip) or self.is_bad(ip, now):
            return False
        lease = self.leases.get(ip)
        if lease is None:
            return True
        if lease.mac == mac.lower():
            return True
        # 未过期（含刚 OFFER 出去的占位）都不许别人抢
        return lease.expiry <= now

    # ---------------- 分配 ----------------

    def offer(
        self,
        mac: str,
        *,
        hint: Optional[str] = None,
        hostname: str = "",
        vendor: str = "",
        client_id: str = "",
        now: Optional[float] = None,
    ) -> Optional[str]:
        """返回一个待 OFFER 的地址。优先粘性映射，其次客户端 hint，最后顺序分配。"""
        now = time.time() if now is None else now
        mac = mac.lower()
        self._reap(now)

        # 1) 粘性映射
        ip = self.sticky.get(mac)
        if ip and (self.leases.get(ip) is None or self.leases[ip].mac == mac):
            if self.in_pool(ip) and not self.is_bad(ip, now):
                return self._touch(ip, mac, hostname, vendor, client_id, now, bind=False)

        # 2) 客户端自己想要的地址（DHCP option 50 / INIT-REBOOT）
        if hint and self.in_pool(hint) and self._free(hint, now):
            return self._touch(hint, mac, hostname, vendor, client_id, now, bind=False)

        # 3) 本机已有的租约（续租 / 重新要地址）
        existing = self.by_mac(mac)
        if existing and self.in_pool(existing.ip) and not self.is_bad(existing.ip, now):
            return self._touch(existing.ip, mac, hostname, vendor, client_id, now, bind=False)

        # 4) 顺序找空位
        for candidate in self.pool:
            if candidate == self.server_ip:
                continue
            if self._free(candidate, now):
                return self._touch(candidate, mac, hostname, vendor, client_id, now, bind=False)
        return None

    def _touch(
        self,
        ip: str,
        mac: str,
        hostname: str,
        vendor: str,
        client_id: str,
        now: float,
        *,
        bind: bool,
    ) -> str:
        lease = self.leases.get(ip)
        if lease is None:
            lease = Lease(ip=ip, mac=mac, first_seen=now)
            self.leases[ip] = lease
        lease.mac = mac
        lease.last_seen = now
        lease.offers += 1
        if hostname:
            lease.hostname = hostname
        if vendor:
            lease.vendor = vendor
        if client_id:
            lease.client_id = client_id
        if bind:
            lease.bound = True
            lease.expiry = now + self.lease_seconds
            self.sticky[mac] = ip
            self.leased_at[ip] = now
        else:
            # OFFER 阶段给一个短期占位，避免并发 offer 撞车
            if not lease.bound or lease.expiry <= now:
                lease.expiry = now + max(60, self.lease_seconds // 2)
            self.leased_at[ip] = now
        return ip

    def bind(
        self,
        ip: str,
        mac: str,
        *,
        hostname: str = "",
        vendor: str = "",
        client_id: str = "",
        now: Optional[float] = None,
    ) -> Lease:
        if not self.in_pool(ip):
            raise ValueError("不能分配本机地址、网络地址、广播地址或地址池外的地址：%s" % ip)
        now = time.time() if now is None else now
        self._touch(ip, mac.lower(), hostname, vendor, client_id, now, bind=True)
        self.save_state()
        return self.leases[ip]

    def owns(self, ip: str, mac: str) -> bool:
        lease = self.leases.get(ip)
        if lease is None:
            return self.sticky.get(mac.lower()) == ip
        return lease.mac == mac.lower()

    def release(self, ip: str) -> None:
        lease = self.leases.get(ip)
        if lease:
            lease.bound = False
            lease.expiry = time.time()
        self.save_state()

    def decline(self, ip: str, seconds: int = 300) -> None:
        """客户端说这地址被别人占了（典型：BMC 上已经有静态 IP 冲突）。"""
        self.bad[ip] = time.time() + seconds
        lease = self.leases.pop(ip, None)
        if lease:
            for mac, sticky in list(self.sticky.items()):
                if sticky == ip:
                    self.sticky.pop(mac, None)
        self.save_state()

    def _reap(self, now: float) -> None:
        for ip, lease in list(self.leases.items()):
            if lease.bound and lease.expiry <= now:
                lease.bound = False
        for ip, until in list(self.bad.items()):
            if until <= now:
                self.bad.pop(ip, None)

    # ---------------- 展示 / 持久化 ----------------

    def rows(self) -> List[Dict[str, object]]:
        items = sorted(self.leases.values(), key=lambda l: ipaddress.IPv4Address(l.ip))
        return [l.to_row() for l in items]

    def stats(self) -> Dict[str, int]:
        now = time.time()
        self._reap(now)
        used = sum(1 for l in self.leases.values() if l.bound)
        offered = sum(1 for l in self.leases.values() if not l.bound and l.expiry > now)
        capacity = sum(1 for ip in self.pool if self.in_pool(ip))
        return {
            "pool": capacity,
            "bound": used,
            "offered": offered,
            "bad": len(self.bad),
            "free": max(0, capacity - used - offered - sum(1 for ip in self.bad if self.in_pool(ip))),
        }

    def _load_state(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return                      # 文件被写坏了就当没有，不要让服务起不来
        sticky = data.get("sticky")
        if isinstance(sticky, dict):
            for mac, ip in sticky.items():
                if isinstance(mac, str) and isinstance(ip, str) and self.in_pool(ip):
                    self.sticky[mac.lower()] = ip
        rows = data.get("leases")
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                lease = Lease(**{k: v for k, v in row.items() if k in Lease.__dataclass_fields__})
                if not isinstance(lease.ip, str) or not isinstance(lease.mac, str):
                    continue
            except (TypeError, ValueError):
                continue
            if self.in_pool(lease.ip):
                # 冷启动时旧租约一律视为已过期，等客户端重新来要
                lease.bound = False
                self.leases[lease.ip] = lease

    def save_state(self) -> None:
        if not self.state_path:
            return
        payload = {
            "updated": time.time(),
            "sticky": self.sticky,
            "leases": [asdict(l) for l in self.leases.values()],
        }
        try:
            atomic_write_json(self.state_path, payload)
        except (OSError, ValueError) as exc:
            logging.getLogger(__name__).warning("租约未能持久化：%s", exc)
