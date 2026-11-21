"""测试用端口分配器：**不要**在用例里写死端口。

为什么需要这个模块
------------------
以前 `test_second_udp_engine_on_same_port_fails` 写死 `bind_port=6771/6772`：

* 两套全套 unittest 并行跑时会撞在一起（先起的那个把端口占了，后起的先绑失败，
  于是要么卡住、要么整个进程被 SIGTERM —— 实测有成员拿到 rc=143）；
* 用户机器上只要有别的程序（真实 bmcd、系统「互联网共享」等）占着那个端口，
  用例就会假失败，而且报错信息跟被测逻辑完全无关。

这里的做法
----------
1. `free_udp_port()` / `free_tcp_port()`：绑 `('127.0.0.1', 0)` 让系统分配，
   拿 `getsockname()[1]`，立刻关闭 —— 后续场景用这个端口。
2. `acquire_udp_port()`：在上一步基础上再确认「刚关掉就能重新绑上」，
   失败就换一个端口重试（自愈）。系统分配的端口理论上可能被别人抢走，
   所以调用方仍然要允许失败重来。
3. `wait_udp_bound()`：等被测代码真的把端口占上（轮询「我绑不上了」），
   避免「sleep 0.2 秒」这种靠时间猜的写法。
4. `occupy_udp()`：自己先占住一个端口，用来做「端口被占用」场景 ——
   这种场景必须自带占用者，不能依赖外部环境恰好占着某个固定端口。
"""

from __future__ import annotations

import contextlib
import socket
import time
from typing import Iterator, Optional, Tuple

HOST = "127.0.0.1"


def _probe(family: int, kind: int) -> Optional[int]:
    sock = socket.socket(family, kind)
    try:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])
    except OSError:
        return None
    finally:
        sock.close()


def free_udp_port(attempts: int = 8) -> int:
    """向系统要一个当前空闲的 UDP 端口；要不到就抛 RuntimeError（不去猜固定值）。"""
    for _ in range(attempts):
        port = _probe(socket.AF_INET, socket.SOCK_DGRAM)
        if port:
            return port
    raise RuntimeError("连着 %d 次都拿不到空闲 UDP 端口（系统端口耗尽？）" % attempts)


def free_tcp_port(attempts: int = 8) -> int:
    for _ in range(attempts):
        port = _probe(socket.AF_INET, socket.SOCK_STREAM)
        if port:
            return port
    raise RuntimeError("连着 %d 次都拿不到空闲 TCP 端口（系统端口耗尽？）" % attempts)


def is_udp_port_free(port: int, host: str = HOST) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def acquire_udp_port(attempts: int = 12) -> int:
    """拿一个「刚放开、马上还能绑上」的 UDP 端口（自愈：被别人抢走就换一个）。"""
    last = ""
    for _ in range(attempts):
        port = free_udp_port(attempts=1)
        if is_udp_port_free(port):
            return port
        last = str(port)
    raise RuntimeError("连着 %d 次拿到的端口都立刻被别人占走了（最后一次 %s）"
                       % (attempts, last or "?"))


def wait_udp_bound(port: int, timeout: float = 3.0, host: str = HOST,
                   interval: float = 0.01) -> bool:
    """等「别人把这个端口占上」：绑不上就说明占上了。超时返回 False。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((host, port))
        except OSError:
            return True                      # 端口被占了 = 被测引擎起来了
        else:
            time.sleep(interval)
        finally:
            sock.close()
    return False


@contextlib.contextmanager
def occupy_udp(port: int = 0, host: str = HOST) -> Iterator[Tuple[socket.socket, int]]:
    """自己占住一个 UDP 端口（默认让系统分配），退出时释放。

    「端口被占用」这种场景必须自带占用者 —— 不能指望外部环境恰好占着 6771。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        actual = int(sock.getsockname()[1])
        yield sock, actual
    finally:
        sock.close()
