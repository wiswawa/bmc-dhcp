"""终端输出：彩色日志 + 等宽表格（按东亚字符宽度对齐）。"""

from __future__ import annotations

import sys
import time
import unicodedata
from typing import Dict, List, Sequence

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREY = "\033[90m"


def _wide(ch: str) -> int:
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def dw(text: str) -> int:
    return sum(_wide(ch) for ch in text)


def pad(text: str, width: int, align: str = "<") -> str:
    diff = width - dw(text)
    if diff <= 0:
        return text
    if align == ">":
        return " " * diff + text
    if align == "^":
        left = diff // 2
        return " " * left + text + " " * (diff - left)
    return text + " " * diff


class Console:
    def __init__(self, color: bool = True, quiet: bool = False) -> None:
        self.color = color and sys.stdout.isatty()
        self.quiet = quiet

    def c(self, text: str, code: str) -> str:
        return "%s%s%s" % (code, text, RESET) if self.color else text

    def _ts(self) -> str:
        return time.strftime("%H:%M:%S")

    def raw(self, text: str = "") -> None:
        print(text, flush=True)

    def info(self, text: str) -> None:
        if self.quiet:
            return
        print("%s %s" % (self.c(self._ts(), GREY), text), flush=True)

    def ok(self, text: str) -> None:
        print("%s %s" % (self.c(self._ts(), GREY), self.c(text, GREEN)), flush=True)

    def warn(self, text: str) -> None:
        print("%s %s" % (self.c(self._ts(), GREY), self.c(text, YELLOW)), flush=True)

    def err(self, text: str) -> None:
        print("%s %s" % (self.c(self._ts(), GREY), self.c(text, RED)), file=sys.stderr, flush=True)

    def event(self, label: str, text: str, color: str = CYAN) -> None:
        print(
            "%s %s %s" % (self.c(self._ts(), GREY), self.c("[%s]" % label, color), text),
            flush=True,
        )

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]], aligns: str = "") -> str:
        cols = len(headers)
        widths = [dw(h) for h in headers]
        for row in rows:
            for i in range(min(cols, len(row))):
                widths[i] = max(widths[i], dw(str(row[i])))
        aligns = (aligns + "<" * cols)[:cols]
        out: List[str] = []
        head = "  ".join(pad(h, widths[i], aligns[i]) for i, h in enumerate(headers))
        out.append(self.c(head, BOLD))
        out.append(self.c("  ".join("-" * w for w in widths), GREY))
        for row in rows:
            out.append(
                "  ".join(
                    pad(str(row[i]) if i < len(row) else "", widths[i], aligns[i])
                    for i in range(cols)
                )
            )
        return "\n".join(out)


LEASE_HEADERS = ["IP", "MAC", "状态", "剩余", "主机名", "厂商", "端口", "管理地址"]
LEASE_ALIGNS = "<<" + "<<" + ">"


def lease_table(console: Console, rows: List[Dict[str, object]]) -> str:
    if not rows:
        return console.c("（还没有设备来要地址）", GREY)
    body = []
    for r in rows:
        body.append(
            [
                str(r.get("ip", "")),
                str(r.get("mac", "")),
                str(r.get("state", "")),
                "%ds" % int(r.get("remaining", 0) or 0),
                str(r.get("hostname", ""))[:18],
                str(r.get("vendor_guess", ""))[:16],
                str(r.get("open_ports", ""))[:16],
                str(r.get("url", "")),
            ]
        )
    return console.table(LEASE_HEADERS, body, LEASE_ALIGNS)


def banner(console: Console, lines: List[str]) -> None:
    for line in lines:
        print(line, flush=True)
