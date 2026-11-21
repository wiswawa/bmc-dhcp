"""BMC 厂商识别：把各种零散线索（MAC 前缀 / option 60 / TLS CN / HTTP 标题）拼成判断。

原则：**只把强证据标成「高」**。MAC 前缀只算提示，因为 BMC 的 MAC 可能跟主机网卡、
交换机、甚至你手上的 USB 网卡前缀混在一起；厂商识别错了会让人去试错默认口令，
所以这里用「置信度 + 证据链」表达，而不是给一个武断结论。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# MAC OUI 前缀 —— 只是线索，标注为「低」
OUI_HINTS = {
    "b0:83:fe": "Dell",
    "18:66:da": "Dell",
    "18:db:f2": "Dell",
    "d0:67:e5": "Dell",
    "f8:bc:12": "Dell",
    "5c:f9:dd": "Dell",
    "24:b6:fd": "Dell",
    "f4:8e:38": "Dell",
    "00:25:90": "Supermicro",
    "0c:c4:7a": "Supermicro",
    "3c:ec:ef": "Supermicro",
    "ac:1f:6b": "Supermicro",
    "00:30:48": "Supermicro",
    "00:24:81": "HPE",
    "00:1b:78": "HPE",
    "3c:d9:2b": "HPE",
    "9c:b6:54": "HPE",
    "00:e0:fc": "Huawei",
    "28:6e:d4": "Huawei",
    "00:0f:fe": "Huawei",
}

# 文本特征：出现在 HTTP 标题 / TLS CN / 页面内容 / option 60 里
TEXT_SIGNATURES = [
    ("iDRAC", "Dell iDRAC"),
    ("idrac", "Dell iDRAC"),
    ("dell", "Dell iDRAC"),
    ("ilo", "HPE iLO"),
    ("integrated lights-out", "HPE iLO"),
    ("supermicro", "Supermicro IPMI"),
    ("xclarity", "Lenovo XClarity"),
    ("lenovo", "Lenovo XClarity"),
    ("imm", "Lenovo IMM"),
    ("ibmc", "Huawei iBMC"),
    ("huawei", "Huawei iBMC"),
    ("xcc", "Lenovo XClarity"),
    ("megarac", "AMI MegaRAC"),
    ("ami", "AMI MegaRAC"),
    ("irmc", "Fujitsu iRMC"),
    ("fujitsu", "Fujitsu iRMC"),
    ("cimc", "Cisco CIMC"),
    ("cisco", "Cisco CIMC"),
    ("asmb", "ASUS ASMB"),
    ("asrock", "ASRock Rack"),
    ("gigabyte", "Gigabyte BMC"),
    ("inspur", "Inspur BMC"),
    ("quanta", "Quanta BMC"),
    ("ipmi", "通用 IPMI/BMC"),
]

# 各厂商常见默认账号（新固件多半强制用机身标签上的唯一密码，这里只是让你少试几次）
DEFAULT_CREDS = {
    "Dell iDRAC": ["root / calvin"],
    "HPE iLO": ["Administrator / 机身标签密码", "Administrator / (空)", "admin / admin"],
    "Supermicro IPMI": ["ADMIN / ADMIN", "ADMIN / 机身标签密码"],
    "Lenovo XClarity": ["USERID / PASSW0RD", "USERID / 机身标签密码"],
    "Lenovo IMM": ["USERID / PASSW0RD"],
    "Huawei iBMC": ["root / Huawei12#$", "Administrator / Admin@9000"],
    "AMI MegaRAC": ["admin / admin", "root / superuser"],
    "Fujitsu iRMC": ["admin / admin"],
    "Cisco CIMC": ["admin / password"],
    "ASUS ASMB": ["admin / admin"],
    "ASRock Rack": ["admin / admin"],
    "Gigabyte BMC": ["admin / admin"],
    "Inspur BMC": ["admin / admin", "superuser / superuser"],
    "Quanta BMC": ["root / 0penBmc"],
    "通用 IPMI/BMC": ["admin / admin", "root / calvin", "ADMIN / ADMIN"],
}

# 一次性问一圈，BMC 管理界面常用端口
BMC_PORTS = [443, 80, 8443, 623, 22, 5900]


@dataclass
class Hit:
    vendor: str
    confidence: str      # 高 / 中 / 低
    evidence: str


@dataclass
class Identity:
    vendor: str = ""
    confidence: str = ""
    evidence: List[str] = field(default_factory=list)
    creds: List[str] = field(default_factory=list)
    url: str = ""

    @property
    def known(self) -> bool:
        return bool(self.vendor)


def oui_vendor(mac: str) -> str:
    if not mac:
        return ""
    return OUI_HINTS.get(mac.lower().replace("-", ":")[:8], "")


def _match_text(text: str) -> Optional[str]:
    if not text:
        return None
    low = text.lower()
    best: Optional[str] = None
    for needle, vendor in TEXT_SIGNATURES:
        if needle in low:
            # 越具体的特征优先（后出现的更具体）
            best = vendor
    return best


def identify(
    *,
    mac: str = "",
    hostname: str = "",
    option60: str = "",
    tls_cn: str = "",
    http_title: str = "",
    http_server: str = "",
    http_body_hint: str = "",
) -> Identity:
    """按证据强弱合成一个身份判断。"""
    hits: List[Hit] = []

    strong_fields = [
        ("HTTP 标题", http_title),
        ("TLS 证书 CN", tls_cn),
        ("页面特征", http_body_hint),
    ]
    for label, value in strong_fields:
        vendor = _match_text(value)
        if vendor:
            hits.append(Hit(vendor, "高", "%s=%s" % (label, value[:48])))

    if option60:
        vendor = _match_text(option60)
        if vendor:
            hits.append(Hit(vendor, "中", "DHCP option 60=%s" % option60[:48]))

    if hostname:
        vendor = _match_text(hostname)
        if vendor:
            hits.append(Hit(vendor, "中", "DHCP hostname=%s" % hostname[:48]))

    oui = oui_vendor(mac)
    if oui:
        hits.append(Hit(oui, "低", "MAC 前缀 %s" % mac[:8]))

    ident = Identity()
    if not hits:
        return ident

    order = {"高": 0, "中": 1, "低": 2}
    hits.sort(key=lambda h: order.get(h.confidence, 3))
    best = hits[0]
    ident.vendor = best.vendor
    ident.confidence = best.confidence
    ident.evidence = ["%s（%s）" % (h.vendor, h.evidence) for h in hits[:4]]
    ident.creds = DEFAULT_CREDS.get(best.vendor, [])
    return ident


def guess_from_dhcp(mac: str, hostname: str, option60: str) -> Identity:
    return identify(mac=mac, hostname=hostname, option60=option60)
