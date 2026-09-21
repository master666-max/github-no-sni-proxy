#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gh-proxy.py — 本机 GitHub 专用 HTTPS 反代（v2）

做什么
------
只服务 GitHub。在本机 127.0.0.1:443 做 TLS 中间人，把浏览器 / git 对 GitHub
的请求转出去。连上游时按需「不发 SNI」，用来绕过按 SNI 匹配的封锁。

    浏览器 --TLS(SNI=github.com)--> 本反代 --TLS(正常SNI 或 无SNI)--> GitHub

为什么不用内核驱动
------------------
WinDivert 那类驱动会被 360 主动防御拦死（Win32Exception 1243）。本程序纯用户态，
只用 socket + ssl，不碰内核。

设计要点（对齐 RFC 9110 与 Go httputil.ReverseProxy 的成熟做法）
--------------------------------------------------------------
1. 流式搬运，绝不整包缓冲 —— 大仓库 zip、git push 的 packfile 都不会撑爆内存。
   小响应（≤ FLUSH_THRESHOLD）先攒够再一次性发出，因此截断时「一个字节都还没发」，
   可以换条通道重试；超过阈值就边收边发。
2. 上游 TLS 连接池（keep-alive 复用）—— 打开一个 GitHub 页面要发几十个请求，
   复用连接能省掉几十次 TLS 握手。
3. 严格剥 hop-by-hop 头（RFC 9110 §7.6.1）：Connection 里列出的字段先删，
   再删 Connection 本身；Keep-Alive / TE / Transfer-Encoding / Upgrade 不转发。
4. 上游连接是概率性的：多 IP 并发竞速、先正常 SNI 再退回无 SNI、
   剔除已知 DNS 污染地址、记住上次可用的 (IP, 模式)。
5. 域名白名单 —— 只放行 GitHub，防止本机其它程序把 443 当开放代理用。

用法
----
  python gh-proxy.py                 # 监听 443
  python gh-proxy.py --port 8443     # 换端口（测试用）
  python gh-proxy.py -q              # 安静模式，只报错（后台运行建议加）
"""

import argparse
import hashlib
import os
import queue
import random
import secrets
import socket
import ssl
import struct
import sys
import threading
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certs")
KEY_FILE = os.path.join(CERT_DIR, "server.key")
# 优先用「叶子证书 + CA」的完整链，兼容 Windows schannel 这类挑剔的客户端
CERT_FILE = os.path.join(CERT_DIR, "server-chain.crt")
if not os.path.exists(CERT_FILE):
    CERT_FILE = os.path.join(CERT_DIR, "server.crt")
PID_FILE = os.path.join(BASE_DIR, "gh-proxy.pid")

# ---- CRL 分发（解决 schannel 的 CRYPT_E_NO_REVOCATION_CHECK）----
#
# Windows 上 curl / git 走 schannel，它**强制**做证书吊销检查。我们出示的是
# 自家私有 CA 签发的证书 —— 若那张证书没声明任何吊销源，schannel 就报
#     CRYPT_E_NO_REVOCATION_CHECK (0x80092012)
# 并掐断握手。症状极难归因：「curl 打不开，但浏览器和 git 有时又没事」。
#
# 解法：证书里声明 crlDistributionPoints = http://127.0.0.1:<CRL_PORT>/ca.crl，
# 这里起一个只服务该 CRL 的极小 HTTP 监听 —— 检查能真正取到 CRL，于是
# curl / git / 任何 schannel 工具**都不需要任何开关**。
#
# ⚠️ 实测（2026-09-21）：`file://` 形式的 CDP Windows 链引擎**不读**，
#    只有 `http://` 才真正被取回。别改成 file://。
CRL_FILE = os.path.join(CERT_DIR, "ca.crl")
CRL_PORT_FILE = os.path.join(CERT_DIR, "crl-port.txt")
DEFAULT_CRL_PORT = 18444


def _crl_port():
    """CRL 监听端口。以 certs/crl-port.txt 为准（gen_certs.py 写入、
    证书 CDP 也按它生成），缺失或非法则退回默认值。"""
    try:
        with open(CRL_PORT_FILE) as f:
            p = int(f.read().strip())
        if 1024 <= p <= 65535:
            return p
    except Exception:
        pass
    return DEFAULT_CRL_PORT


def start_crl_server():
    """起一个只服务 /ca.crl 的极小 HTTP 监听（仅 127.0.0.1）。

    失败**不致命**：TLS 反代照常工作，只是 schannel 工具会报
    CRYPT_E_NO_REVOCATION_CHECK。所以这里只记日志、返回 None。

    返回监听 socket 或 None。
    """
    port = _crl_port()
    if not os.path.exists(CRL_FILE):
        log("  [!] 缺 %s —— 证书已声明 CDP 却取不到 CRL，"
            "curl 会报 CRYPT_E_NO_REVOCATION_CHECK。请跑 gen_certs.py。"
            % os.path.basename(CRL_FILE), warn=True)
        return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    except (AttributeError, OSError):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError as e:
        log("  [!] CRL 监听绑定 127.0.0.1:%d 失败: %s" % (port, str(e)[:60]),
            warn=True)
        log("      影响：schannel 工具（curl）会报 CRYPT_E_NO_REVOCATION_CHECK。",
            warn=True)
        return None
    s.listen(16)

    def loop():
        while True:
            try:
                conn, _addr = s.accept()
            except Exception:
                return                       # socket 被关 = 正常退出
            try:
                conn.settimeout(3)
                req = b""
                while b"\r\n" not in req and len(req) < 4096:
                    c = conn.recv(1024)
                    if not c:
                        break
                    req += c
                path = "/"
                try:
                    path = req.split(b" ")[1].decode("latin-1")
                except Exception:
                    pass
                if path.split("?", 1)[0].rstrip("/") in ("/ca.crl", ""):
                    data = open(CRL_FILE, "rb").read()
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/pkix-crl\r\n"
                        b"Content-Length: " + str(len(data)).encode() + b"\r\n"
                        b"Cache-Control: no-store\r\n"
                        b"Connection: close\r\n\r\n" + data)
                else:
                    conn.sendall(b"HTTP/1.1 404 Not Found\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
            finally:
                close_quietly(conn)

    threading.Thread(target=loop, daemon=True).start()
    return s


# ================================================================ 配置

UPSTREAM_PORT = 443

# --- 并发与流控 ---
MAX_CLIENT_CONNS = 128          # 同时处理的客户端连接上限
CHUNK = 64 << 10                # 一次 recv 的大小
FLUSH_THRESHOLD = 1 << 20       # 先攒这么多；超了就开始边收边发（放弃重试）

# --- 上游拨号 ---
TCP_TIMEOUT = 3                 # TCP 建连超时（黑洞 IP 要迅速放弃）
HANDSHAKE_TIMEOUT = 6           # TLS 握手超时
DATA_TIMEOUT = 60               # socket 基础超时（发请求体等兜底用）。
                                # 「等待」各有专用预算，见下面三条 —— 全部实测标定过。
HEADER_TIMEOUT = 20             # 等响应头（刚建立的连接）。
                                # GFW 的典型手法是「放行 TLS 握手，然后把请求整条吞掉」——
                                # 一个字节都不回。这里若等满 60s，重试预算当场耗光，
                                # 浏览器只能拿到 502，哪怕换条通道 2s 就能通。
                                # 实测 GitHub 响应头 0.07~0.57s，20s 已是 35 倍余量。
FIRST_BYTE_TIMEOUT = 15         # 响应头到了之后，再等体首字节（刚建立的连接）。
                                # 实测所有端点（含 linux 全量打包）体首字节 0.07~0.65s → 15s 是 23 倍余量。
                                # ⚠️ 这个值曾被设成 60s（理由是「服务端要现算」），结果单次尝试
                                # 就把 45s 重试预算整个吃掉，重试在结构上不可能发生 ——
                                # 实测表现为首页硬等 60s 后 502，而另一条通道明明 1s 就能通。
BODY_STALL_TIMEOUT = 12         # 体传到一半「卡住」多久就判死。
                                # 实测 github.com 首页会出现「握手成功、体传一半再也不动」，
                                # 靠它 12s 就换通道重试，而不是死等满 60s。
                                # 静态内容不会真有 >12s 的停顿，调小能显著缩短最坏耗时。
HEADER_TIMEOUT_GET = 10         # 无体幂等请求（GET/HEAD）专用的「等响应头」预算。
                                # 为什么要单独一套：这类请求**重试是安全且几乎免费的**，
                                # 而 GFW 的常见手法是「握手成功、请求石沉大海」——
                                # 用 20s 等它等于让用户白等 20s，然后才换通道；两次就是 40s。
                                # 实测（2026-09-15）github.com 正是如此：连拨两次、每次等满
                                # 20s，40s 才通，监控和浏览器都先放弃了。
                                # 实测头 TTFB 只要 0.07~0.57s（含 linux 全量打包），
                                # 10s 已是 17 倍余量；且 10+10+10=30s 仍远小于 45s 重试预算。
                                # ⚠️ 带请求体的请求（POST/git push）不能这么干：上游真的可能
                                # 在收完大 body 后算上十几秒才回头，那时误杀比等更糟。
FIRST_BYTE_TIMEOUT_GET = 10     # 同上，无体幂等请求的「体首字节」预算。
                                # 实测 0.07~0.65s（4MB 流式下载也只要 0.35s）→ 10s 是 15 倍余量。
MODE_PENALTY_TTL = 180          # 某模式刚在体传输上栽过，这段时间内排到最后
RACE_SIZE = 6                   # 同时竞速的 IP 数
RACE_ROUNDS = 3                 # 竞速跑几轮（RST 是概率性的）

# 竞速切片的轮转游标。见 race_slice()。
# 必须是进程内单调递增的，让**连续请求**也用不同的切片。
_race_rotate = 0


RACE_HEAD = 2                   # 环形切片里**固定保留**的最快的几个 IP（不参与轮转）
                                # 理由见 race_slice 的 docstring。


def race_slice(ips, size, step, head=RACE_HEAD):
    """环形切片：**头部固定**（最快的几个），**尾部轮转**。

    `step` 是**调用序号**（0,1,2,…），不是字节偏移 ——
    内部按「尾段长度 / 每次需要的格数」自增，保证连续几次调用**恰好把尾段铺满一遍**。

    为什么需要（2026-09-21 实测换来的）：
        旧写法是 `ips = ips[:RACE_SIZE]` —— 每轮都竞速**同一批前 N 个**，
        池尾的 IP **从上线起就从未被试过**。
        当日日志里 github.com 的 101 次失败恰好全落在被竞速的那 4 个上，
        而同期逐 IP 实测发现池外还有 10 个可用 —— 也就是说，
        **失败有一大半不是「没通道」，而是「有通道但从没去试」。**

    为什么不整段轮转（踩过）：
        第一版实现是**整段**环形轮转，A/B 实测 p50 从 2.89s **劣化到 4.76s**。
        原因是轮转会把「实测最快的那几个 IP」挤出切片 ——
        竞速的赢家是「谁先成功」，切片里若只剩 4~5s 的慢 IP，
        哪怕池里有 0.3s 的 IP 也赢不了。
        ⇒ 改成「**头 head 个固定 + 其余位置轮转**」：快路不动，尾部照样轮得到。

    不变量（selftest A22 守着）：在单次建连能跑的那几次竞速调用里，
    池子里**每个 IP 都要被排到至少一次** —— 否则「有通道却从没去试」会重演。
    """
    n = len(ips)
    if n <= size:
        return list(ips)
    head_n = max(0, min(head, size))
    fixed = list(ips[:head_n])
    tail = ips[head_n:]
    need = size - head_n
    if not tail:
        return list(ips[:size])
    off = (step * need) % len(tail)
    return fixed + [tail[(off + i) % len(tail)] for i in range(need)]
PHASE_BUDGET = 6                # 单轮竞速最多花多少秒
                                # 这个数 × 「单次建连能跑几轮」决定能试几段 IP 切片：
                                #     REQUEST_BUDGET / PHASE_BUDGET = 竞速调用次数
                                #     次数 / 2 = 走过的**不同切片**数（每轮两个模式各一次调用）
                                # 原值 10 ⇒ 20/10 = 2 次 ⇒ **只有 1 段切片**（两个模式），
                                # 于是 RACE_ROUNDS 设多大都轮不到第二段（2026-09-21 发现）。
                                # 取 6 的另一个理由：实测最慢的可用 IP 约 5.2s，
                                # 低于它会把这几个「慢但活着」的通道直接掐掉。
REQUEST_BUDGET = 24             # 建上游连接的总预算
                                # 20 → 24：为的是凑出「2 段切片 × 2 个模式」= 4 次竞速调用。
                                # 代价：全部失败的极端情况下，用户多等 4 秒（反正要手动刷新）。
MAX_ATTEMPTS = 3                # 单次请求最多试几遍
ATTEMPT_BUDGET = 45             # 从收到请求算起，重试循环的总预算。
                                # 3 遍 × (建连 20s + 停滞 12s) 理论上能到 90s，
                                # 浏览器就一直转圈了 —— 到点就回 502，让它自己重试。
IDEMPOTENT = {"GET", "HEAD", "OPTIONS", "TRACE"}   # 只有这些方法能安全重试

# --- 连接池 ---
POOL_IDLE_TIMEOUT = 45          # 空闲连接最多留 45s（超过上游空闲超时必被对端关）
POOL_MAX_IDLE = 4               # 每个 (host, ip, 模式) 最多缓存几条
POOL_MAX_REQ = 200              # 单条连接最多复用多少次
POOL_FIRST_BYTE_TIMEOUT = 15    # 池里捞出的连接，15s 还不给首字节就当它早被关了。
                                # 死连接通常表现为「发得出去、回不来」，而 GFW 常把对端的
                                # FIN 吃掉，本端察觉不到 —— 不给个短预算就得干等满 60s。

# --- 客户端 ---
CLIENT_IDLE_TIMEOUT = 120
TLS_HANDSHAKE_CLIENT_TIMEOUT = 20   # 客户端侧 TLS 握手独立预算（审计 S2：并发槽在
                                    # 握手「之前」占用、首设超时在握手「之后」才生效，
                                    # 慢/挂起握手可永久耗尽 128 槽。宽值 20s：劣化链路的
                                    # 合法握手也可能 >10s）
HEADER_READ_TOTAL = 120             # 单个请求头的总读取预算（审计 V6：空闲超时是每
                                    # recv 重置的，一字节一滴灌可无限拖住一条连接；
                                    # 头必须在该总预算内读完。只影响「读头」，不碰
                                    # 响应体流式搬运，大下载不受影响）

# --- DNS ---
DNS_TTL = 300                   # 解析结果缓存 5 分钟

VERBOSE = True
_lock = threading.Lock()


def log(msg, warn=False):
    """warn=True 的消息在 -q 模式下也会打印。"""
    if not VERBOSE and not warn:
        return
    try:
        with _lock:
            print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)
    except Exception:
        pass


# ================================================================ 专一：域名白名单

ALLOW_EXACT = {
    "github.com", "github.io", "githubassets.com", "githubapp.com",
    "github.dev", "githubusercontent.com",
}
ALLOW_SUFFIX = (
    ".github.com", ".github.io", ".githubassets.com",
    ".githubapp.com", ".github.dev", ".githubusercontent.com",
)


def host_allowed(host):
    host = host.lower().rstrip(".")
    return host in ALLOW_EXACT or host.endswith(ALLOW_SUFFIX)


# ================================================================ 上游：解析与拨号

# ⚠️⚠️ 本文件最容易踩、后果最严重的一条：**绝不能把本机地址当上游**。
#
# hosts 把我们服务的 36 个域名全指向 127.0.0.1，而系统解析器
# （getaddrinfo / gethostbyname）**会读 hosts** —— 于是「解析上游」的结果就是我们
# 自己的监听地址。反代会连上自己、把自己当上游，然后那一层再解析、再连自己……
# 一路递归下去，每层吃掉一个并发槽（MAX_CLIENT_CONNS=128），最后「并发已满」，
# 外层拿到 502。实测症状（2026-09-14）：
#   · raw / avatars / gist 必挂；github.com 等少数域名因为另有硬编码兜底 IP 才侥幸能通
#   · 日志被 "[WinError 10053/10054] … 所有通道失败(4): 127.0.0.1: …" 刷屏
#   · **更坑的是：没部署时（hosts 干净）一切正常** —— 自测全绿，一部署就现原形
#
# 所以这里两道防线：
#   ① 解析层：直查公共 DNS（绕开 hosts），并把本机地址过滤掉（见 SELF_IPS / resolve）；
#   ② 拨号层：dial() 见到本机地址直接拒绝（兜底，防未来新增路径又漏掉）。
SELF_IPS = {"127.0.0.1", "0.0.0.0", "::1", "::"}

# 公共 DNS：只有直查它们才拿得到真地址（系统解析器已被自己的 hosts 带偏）。
# 实测（2026-09-14）：223.5.5.5 最准；119.29.29.29 偶尔回污染地址（有 POISON_IPS 兜着）；
# 1.1.1.1 在境内经常超时，不采用。
PUBLIC_DNS = ("223.5.5.5", "119.29.29.29")
DNS_TIMEOUT = 3

# 已知 GitHub 官方 IP 池：DNS 不可用 / 被污染 / 被自己的 hosts 骗时的兜底
#
# ⚠️ 这里每个域名的 IP **必须只放真属于它的**。实测（2026-09-12）：
# 20.205.243.166 是 github.com 的边缘，**不认 api.github.com 这个虚拟主机** ——
# 无论发不发 SNI，它都会回 `301 Location: https://github.com/<原路径>`。
# 早先把 .166 也放进 api/codeload 的兜底池，等于主动往竞速里塞一条错通道，
# 结果是「首页正常、API 拿回一堆 301」，而且静默无报错，极难定位。
#
# Fastly 段（2026-09-14 用 223.5.5.5 直查实测得来）：
#   .133 → raw / objects / media / release-assets / avatars* / camo / cloud / user-images
#           / private-user-images / resources.github.com
#   .215 → github.githubassets.com          .153 → github.io / pages.github.com
#   .154 → github-cloud / support-assets
_FASTLY_133 = ["185.199.108.133", "185.199.109.133",
               "185.199.110.133", "185.199.111.133"]
_FASTLY_153 = ["185.199.108.153", "185.199.109.153",
               "185.199.110.153", "185.199.111.153"]
_FASTLY_154 = ["185.199.108.154", "185.199.109.154",
               "185.199.110.154", "185.199.111.154"]
_FASTLY_215 = ["185.199.108.215", "185.199.109.215",
               "185.199.110.215", "185.199.111.215"]

FALLBACK_IPS = {
    # github.com —— 2026-09-21 逐 IP 实测（发 SNI / 不发 SNI 各一次，只看 HTTP 200）
    # 22 个候选里 16 个可用。**同一时段 github.com 的失败恰好集中在旧池那 4 个上，
    # 而池外 10 个是好的** —— 所以把它们全收进来（顺序≈实测耗时升序）。
    "github.com": ["20.205.243.166", "20.207.73.82", "20.233.83.145",
                   "4.208.26.197", "20.26.156.215", "20.27.177.113",
                   "20.200.245.247", "4.237.22.38", "20.201.28.151",
                   "140.82.112.3", "140.82.112.4", "140.82.113.3",
                   "140.82.114.3", "140.82.114.4", "140.82.116.3",
                   "140.82.121.3"],
    # www 与 github.com 同池即可（同一边缘），但保留前几个快的
    "www.github.com": ["20.205.243.166", "20.207.73.82", "4.208.26.197",
                       "140.82.112.3", "140.82.113.3", "140.82.114.3",
                       "140.82.116.3"],
    "uploads.github.com": ["20.205.243.161"],
    # api —— 实测 8 个候选里 3 个可用；140.82.113.6 / 140.82.114.6 当前
    # ConnectionReset（可能只是当前窗口），**保留**以免窗口过去后又缺通道；
    # 新补的 140.82.116.6 实测 200。
    "api.github.com": ["20.205.243.168", "140.82.112.6", "140.82.116.6",
                       "140.82.113.6", "140.82.114.6"],
    # codeload —— 新补 140.82.116.9（实测 200）；20.201.28.151 / 20.233.83.145 /
    # 4.208.26.197 **不认 codeload 这个虚拟主机**（回 301），绝不能放进来。
    "codeload.github.com": ["140.82.112.9", "140.82.113.9", "140.82.114.9",
                            "140.82.116.9", "20.205.243.165"],
    # gist 最顽固：会被 DNS 污染（实测 223.5.5.5 回 159.24.3.173、
    # 119.29.29.29 回 243.185.187.39，都是假地址）→ 兜底池才是它的主力。
    # 2026-09-21 实测：**此刻 gist 只有「不发 SNI」能通**（发 SNI 一律 ConnectionReset），
    # 且可用 IP 是 140.82.112.4 / 20.205.243.166 / 20.207.73.82 —— 后两个是新增。
    "gist.github.com": ["140.82.112.4", "20.205.243.166", "20.207.73.82",
                        "140.82.113.4", "140.82.114.4"],
    "collector.github.com": ["140.82.114.22"],
    "alive.github.com": ["140.82.114.25"],
    "objects-origin.githubusercontent.com": ["140.82.114.22"],
    "githubapp.com": ["140.82.112.29", "140.82.113.29", "140.82.114.29"],
    "github.dev": ["20.43.185.14"],
    "github.githubassets.com": list(_FASTLY_215),
    "githubassets.com": list(_FASTLY_215),
    "archiveprogram.github.com": list(_FASTLY_153),
    "github-cloud.githubusercontent.com": list(_FASTLY_154),
    "support-assets.githubassets.com": list(_FASTLY_154),
}
for _d in ("raw.githubusercontent.com", "objects.githubusercontent.com",
           "release-assets.githubusercontent.com", "media.githubusercontent.com",
           "avatars.githubusercontent.com", "avatars0.githubusercontent.com",
           "avatars1.githubusercontent.com", "avatars2.githubusercontent.com",
           "avatars3.githubusercontent.com", "avatars4.githubusercontent.com",
           "avatars5.githubusercontent.com", "camo.githubusercontent.com",
           "cloud.githubusercontent.com", "user-images.githubusercontent.com",
           "private-user-images.githubusercontent.com",
           "resources.github.com"):
    FALLBACK_IPS[_d] = list(_FASTLY_133)
for _d in ("github.io", "www.github.io", "pages.github.com"):
    FALLBACK_IPS[_d] = list(_FASTLY_153)
del _d

# 臭名昭著的 GFW DNS 污染地址：解析结果里出现这些，直接丢掉，连了也白连
POISON_IPS = {
    "46.82.174.68", "59.24.3.173", "78.16.49.15", "93.46.8.89", "8.7.198.45",
    "37.61.54.158", "159.106.121.75", "203.98.7.65", "243.185.187.39",
    "243.185.187.30", "4.36.66.178", "54.76.135.1", "3.4.175.183", "49.2.123.56",
    # 159.24.3.173 是 59.24.3.173 的同族变体，实测由 223.5.5.5 回给 gist.github.com
    "159.24.3.173",
}

_dns_cache = {}
_dns_lock = threading.Lock()


def _dns_skip_name(data, i):
    """跳过 DNS 报文中的一个名字字段，返回新下标。越界一律报错（不做任何猜测）。"""
    while True:
        if i >= len(data):
            raise ValueError("报文截断(name)")
        b = data[i]
        if b == 0:
            return i + 1
        if b & 0xC0:                      # 压缩指针：两字节即结束
            if i + 2 > len(data):
                raise ValueError("报文截断(ptr)")
            return i + 2
        i += b + 1


def dns_query_a(host, server, timeout=DNS_TIMEOUT):
    """最小 DNS over UDP 客户端：只查 A 记录。

    存在的唯一理由：**getaddrinfo 会读 hosts，而 hosts 正是我们自己写的**
    （36 个域名 → 127.0.0.1），用它解析等于把自己当上游（见 SELF_IPS 的注释）。
    直查公共 DNS 就绕开了这一层。
    """
    tid = secrets.randbits(16)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in host.rstrip(".").split("."):
        if not 0 < len(part) < 64:
            raise ValueError("域名不合法")
        q += bytes([len(part)]) + part.encode("ascii")
    q += b"\x00" + struct.pack(">HH", 1, 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # connect 绑定四元组：内核只把「来自所查服务器 53 端口」的报文交给我们，
        # 任意源端口的伪造应答直接被丢（审计 S6.3；离路防线另见下方来源校验与 TID）。
        # TID 用 secrets 而非 random（MT19937 可预测）。
        s.connect((server, 53))
        s.send(q)
        data, addr = s.recvfrom(4096)
    finally:
        try:
            s.close()
        except Exception:
            pass

    # 响应必须来自我们查询的那台服务器：不校验来源的话，任何主机发来的伪造
    # 报文只要蒙对 16 位 tid 就能污染解析（离路注入）。
    if addr[0] != server:
        raise ValueError("响应来源不是查询的服务器(%s)" % addr[0])

    if len(data) < 12:
        raise ValueError("响应过短(%d)" % len(data))
    if struct.unpack(">H", data[:2])[0] != tid:
        raise ValueError("响应 ID 不匹配")
    flags, qdcount, ancount = struct.unpack(">HHH", data[2:8])
    if not (flags & 0x8000):
        raise ValueError("不是响应报文")
    if flags & 0x000F:
        raise ValueError("rcode=%d" % (flags & 0x000F))

    i = 12
    for _ in range(qdcount):
        i = _dns_skip_name(data, i) + 4
    ips = []
    for _ in range(ancount):
        i = _dns_skip_name(data, i)
        if i + 10 > len(data):
            raise ValueError("报文截断(rr)")
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if i + rdlen > len(data):
            raise ValueError("报文截断(rdata)")
        if rtype == 1 and rdlen == 4:
            ips.append("%d.%d.%d.%d" % tuple(data[i:i + 4]))
        i += rdlen
    return ips


def resolve(host):
    """解析候选 IP：**先直查公共 DNS**（绕开被自己 hosts 带偏的系统解析器），
    再并上系统解析器的结果（剔除指向本机的地址），最后并入兜底 IP 池。

    最后统一过一遍 POISON_IPS + SELF_IPS 黑名单 —— 尤其是 SELF_IPS：
    一旦漏出去，反代就会连自己（见文件顶部那段注释）。
    """
    now = time.time()
    with _dns_lock:
        hit = _dns_cache.get(host)
        if hit and now - hit[1] < DNS_TTL:
            return hit[0]

    # 字面 IPv4 不必查 DNS（省一次往返，本机自测也用得上）
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        return [] if (host in SELF_IPS or host in POISON_IPS) else [host]

    ips = []
    for server in PUBLIC_DNS:                 # ① 公共 DNS：hosts 影响不到
        try:
            for ip in dns_query_a(host, server):
                if ip not in ips:
                    ips.append(ip)
            if ips:
                break
        except Exception as e:
            log("  DNS %s 查 %s 失败: %s" % (server, host, str(e)[:36]))

    if not ips:                               # ② 系统解析器（hosts 生效，故剔本机地址）
        try:
            for info in socket.getaddrinfo(host, UPSTREAM_PORT, socket.AF_INET,
                                           socket.SOCK_STREAM):
                ip = info[4][0]
                if ip not in ips and ip not in SELF_IPS:
                    ips.append(ip)
        except Exception:
            pass

    for ip in FALLBACK_IPS.get(host, []):     # ③ 兜底池
        if ip not in ips:
            ips.append(ip)

    result = [ip for ip in ips if ip not in POISON_IPS and ip not in SELF_IPS]
    with _dns_lock:
        _dns_cache[host] = (result, now)
    return result


def build_client_ctx(check_hostname, verify_chain=True):
    """上游客户端上下文。

    安全审计 F1（2026-09-18）：原先两种 SNI 模式一律 CERT_NONE —— 在路攻击者
    出示任意证书都被接受，可以改写 release/raw/zipball 等任意响应内容。
    现在证书链一律验（系统根集合；本机私有 gh-proxy CA 不在系统默认根中，
    不会形成自签环）：「正常 SNI」模式连主机名一起核，「无 SNI」模式没有
    可核对的名字、只验链（GitHub 回的是默认虚拟主机的真链，照样能验过）。
    verify_chain=False 仅限 --no-verify-upstream 排障开关与自测的本地端到端用例。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = check_hostname and verify_chain
    ctx.verify_mode = ssl.CERT_REQUIRED if verify_chain else ssl.CERT_NONE
    if verify_chain:
        try:
            ctx.load_default_certs()
        except Exception:
            pass
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


CLIENT_CTX_SNI = build_client_ctx(True)
CLIENT_CTX_NOSNI = build_client_ctx(False)
CLIENT_CTX = CLIENT_CTX_SNI      # 旧名保留：selftest 的本地端到端用例整体替换上下文用

# ---- 无 SNI 模式的根 CA 钉扎（审计 S1，WO-SEC-GHACCEL-001 批次2）----
#
# 无 SNI 模式没有可核对的主机名，只验链意味着「任何合法公共 CA 签发的证书」都能
# 通过——在路攻击者用自己域名的免费证书即可伪造响应。这里把可信根证书的
# SHA-256(DER) 钉成白名单：链的根不在集合内 → 拒绝该连接（竞速转投其它 IP/模式，
# 不产生内容侧影响）。
# ⚠️ 刻意不钉叶子 SPKI、不在无 SNI 下强校 SAN——GitHub 轮换证书/默认虚拟主机
# 证书不含目标域时会把回退路整个废掉（面板 L3 裁定的修复暗坑）。
# 底账采集：2026-09-19 用生产 SNI 上下文对各域名 get_verified_chain() 实测。
# 动态集合：SNI 模式验证通过的链根会话内累积——GitHub 换根时 SNI 先看见，NOSNI 跟进；
# 若 GitHub 换根且 SNI 全被掐，NOSNI 会被钉扎挡住 → 把 NOSNI_PIN_MODE 改 "log-only" 应急。
NOSNI_ROOT_PINS = {
    "4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a",  # github.com/api/codeload/gist 系根
    "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",  # Fastly 边缘系根（raw/avatars/objects/github.io）
}
NOSNI_DYNAMIC_ROOTS = set()      # SNI 模式见过的根（会话内）
NOSNI_PIN_MODE = "enforce"       # "enforce"=不在集合内即拒绝；"log-only"=仅告警（应急）


def _chain_root_hash(tls):
    """已验证链的根证书 SHA-256(DER)；拿不到链返回 None（无法判定）。"""
    try:
        chain = tls.get_verified_chain() or []
    except Exception:
        return None
    if not chain:
        return None
    return hashlib.sha256(bytes(chain[-1])).hexdigest()


def _nosni_root_ok(tls, ip):
    if NOSNI_PIN_MODE != "enforce":
        return True
    h = _chain_root_hash(tls)
    if h is None:
        # 平台不支持链枚举 / CERT_NONE 上下文（自测与排障开关）：退化为仅验链
        return True
    if h in NOSNI_ROOT_PINS or h in NOSNI_DYNAMIC_ROOTS:
        return True
    log("  ⚠ 无SNI模式链根不在钉扎集合(%s…)，拒绝 %s" % (h[:16], ip), warn=True)
    return False


# host -> {ip: 解禁时间}。有些 IP 在 DNS 里确实挂在这个域名下，实际却只认别的
# 虚拟主机（GFW 污染、边缘节点错配都会这样）。表现很隐蔽：**TLS 握手完全正常，
# 只是回一个指向 github.com 的 301**（CDN 的「默认虚拟主机」兜底）。
# 一旦识别出来就短期拉黑，竞速时跳过它 —— 否则会一直有 1/N 的概率命中错内容。
BAD_IP = {}
BAD_IP_TTL = 600


def mark_ip_bad(host, ip):
    if not ip:
        return
    BAD_IP.setdefault(host, {})[ip] = time.time() + BAD_IP_TTL


def ip_ok(host, ip):
    """这个 IP 现在还能不能用来连该 host（被拉黑且未过期 → 不能）。"""
    bad = BAD_IP.get(host)
    if not bad:
        return True
    until = bad.get(ip)
    if until is None:
        return True
    if until <= time.time():
        bad.pop(ip, None)
        return True
    return False


def dial(ip, sni_host):
    """连到一个 IP 并完成 TLS 握手；sni_host=None 表示不发送 SNI。"""
    # 兜底红线：解析层已经滤过 SELF_IPS，但这条路径以后可能被新代码绕过。
    # 连自己 = 自杀式递归（每层吃一个并发槽，最后 502 + 日志刷屏），
    # 所以宁可当场硬失败，也不允许它发生。
    if ip in SELF_IPS:
        raise RuntimeError("拒绝把本机地址当上游(%s)" % ip)
    raw = socket.create_connection((ip, UPSTREAM_PORT), timeout=TCP_TIMEOUT)
    try:
        raw.settimeout(HANDSHAKE_TIMEOUT)
        ctx = CLIENT_CTX_NOSNI if sni_host is None else CLIENT_CTX_SNI
        tls = ctx.wrap_socket(raw, server_hostname=sni_host)
        if sni_host is None:
            # 无 SNI 模式的根钉扎（审计 S1）：只验链不核名的残余风险在此收口
            if not _nosni_root_ok(tls, ip):
                close_quietly(tls)
                raise RuntimeError("无SNI模式链根不在钉扎集合: %s" % ip)
        else:
            h = _chain_root_hash(tls)
            if h is not None:
                NOSNI_DYNAMIC_ROOTS.add(h)   # SNI 看见的新根，NOSNI 会话内跟进
        tls.settimeout(DATA_TIMEOUT)
        tls.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return tls
    except Exception:
        close_quietly(raw)
        raise


def race(ips, mode, budget):
    """并发拨号同一批 IP，谁先握手成功用谁，其余立刻关掉。

    返回 (sock, ip, errs)；全失败返回 (None, None, errs)。

    「晚到的成功连接」也必须收掉：每轮竞速开 len(ips) 条 TLS 连接，只有 1 条能用。
    若收摊后某个 worker 才握手成功而其 socket 没人管，就是**永久 fd 泄漏** ——
    网络抽风会疯狂重试，很快把句柄耗光。所以：
      · worker 的「入队」放在 guard 内 → 入队与收摊不会交错；
      · 主线程收摊时置 closed 并清空队列，晚到的 worker 会在 guard 内看到 closed 自行关闭。
    """
    q = queue.Queue()
    guard = threading.Lock()
    taken = threading.Event()        # 已有赢家
    closed = threading.Event()       # 本轮已收摊

    def worker(ip):
        try:
            tls = dial(ip, mode)
        except Exception as e:
            q.put((None, ip, str(e)[:60]))
            return
        with guard:
            if taken.is_set() or closed.is_set():
                close_quietly(tls)               # 已有赢家 / 本轮收摊 → 关掉，别泄漏
                q.put((None, ip, ""))
                return
            taken.set()
            q.put((tls, ip, ""))                 # 入队必须在 guard 内

    for ip in ips:
        threading.Thread(target=worker, args=(ip,), daemon=True).start()

    deadline = time.time() + budget
    errs = []
    winner = None
    for _ in range(len(ips)):
        remain = deadline - time.time()
        if remain <= 0:
            break
        try:
            sock, ip, err = q.get(timeout=min(remain, 6))
        except queue.Empty:
            break
        if sock is not None:
            winner = (sock, ip)
            break
        if err:
            errs.append("%s: %s" % (ip, err))

    # 收摊：清掉队列里可能残留的连接；晚到的 worker 会自行关闭
    with guard:
        closed.set()
        while True:
            try:
                sock, _ip, _e = q.get_nowait()
            except queue.Empty:
                break
            if sock is not None:                 # 赢家已被 q.get 取走，这里只可能是输家
                close_quietly(sock)

    if winner is not None:
        return winner[0], winner[1], errs
    return None, None, errs


# 上次成功的 (ip, 模式)。失败即作废，不做时间过期。
GOOD_PEER = {}

# host -> (模式, 解禁时间)。某模式刚在「体传输」上栽过 → 这段时间内排到最后试。
# 关键：握手成功 ≠ 通道可用。实测 github.com 首页就是「握手好好的，体传一半卡死」，
# 如果只按握手成败挑模式，会一直选中这条坏通道。加"体传输"这一维才治得住。
MODE_PENALTY = {}

# host -> 模式：**真的把一次请求完整跑通过**的模式（不是「握手成功」就算）。
#
# 为什么还要这个：竞速挑模式用的判据是「握手成功」，而 GFW 恰好让握手永远成功、
# 之后把请求吞掉 —— 于是「惩罚坏模式」只压得住一次：惩罚完 A，下次竞速又按握手
# 选中 A（或选中同样握手成功的 B），又要等满一次头超时。
# 实测（2026-09-15）github.com 每次新建连接都稳定交 10s「学费」。
# 记下「上次真的跑通请求的模式」并优先用它，才能把这一课补全。
MODE_GOOD = {}


def mode_order(host):
    """返回该 host 的上游模式尝试顺序。

    规则：① 优先「上次真的跑通过请求」的模式（MODE_GOOD）；
          ② 默认仍是「正常 SNI」优先（最正宗，GitHub 认这个）；
          ③ 刚被罚过的模式排到最后。
    """
    order = [host, None]
    # ⚠️ 必须用 `in` 判断「有没有记录」：无 SNI 这个模式的值**就是 None**，
    # 拿 MODE_GOOD.get() 的返回值当哨兵会把「没记录」和「记录的是无 SNI」弄混 ——
    # 结果是没记录时也去提升一把，默认顺序被永久翻成「无 SNI 优先」（踩过，被 A10/A11 抓住）。
    if host in MODE_GOOD and MODE_GOOD[host] in order:
        good = MODE_GOOD[host]
        order.remove(good)
        order.insert(0, good)

    pen = MODE_PENALTY.get(host)
    if not pen:
        return order
    bad_mode, until = pen
    if until <= time.time():
        MODE_PENALTY.pop(host, None)     # 过期即清，别让表格无限长
        return order
    if bad_mode in order:                # ②③ 惩罚优先于提升：被罚的挪到队尾
        order.remove(bad_mode)
        order.append(bad_mode)
    return order


def connect_upstream(host, budget=None):
    """建立到 host 的 TLS 连接。

    先试「正常 SNI」（最正宗，GitHub 认这个），全挂了再试「不发 SNI」绕过封锁。
    反过来先发无 SNI 会被 CDN 当成错误虚拟主机，api.github.com 会回 301。
    """
    ips = resolve(host)
    if not ips:
        # 解析结果全被过滤（污染本机地址 / 公共 DNS 不通且无兜底）→ 说清原因，
        # 否则只报「无法解析」会让人以为是网络坏了。
        raise RuntimeError("没有可用上游 IP：%s（查 DNS 与 FALLBACK_IPS 是否覆盖该域名）"
                           % host)
    # 拉黑过的 IP 直接排除；万一全被拉黑（说明判断错怪了人），还是照原样试。
    ips = [ip for ip in ips if ip_ok(host, ip)] or ips

    deadline = time.time() + (REQUEST_BUDGET if budget is None else budget)

    # 1) 上次成功的通道，直达（但别用已经确认「答错虚拟主机」的 IP）
    peer = GOOD_PEER.get(host)
    if peer and peer[0] in ips and ip_ok(host, peer[0]):
        try:
            sock = dial(peer[0], peer[1])
            sock._ghp_peer = peer      # 连接自带身份（审计 S5.6）：下游不再二次查表
            return sock
        except Exception:
            GOOD_PEER.pop(host, None)

    # 2) 竞速：按当前最优顺序，正常 SNI / 无 SNI 各跑几轮。
    #    每轮换一段**环形切片**（见 race_slice）—— 旧写法 ips[:RACE_SIZE] 会让
    #    池尾 IP 永远没机会；这是 2026-09-21 那次「有通道却从没去试」的直接修法。
    global _race_rotate
    errs = []
    dead_modes = []          # 整段一个 IP 都没握手成功的模式
    for _round in range(RACE_ROUNDS):
        batch = race_slice(ips, RACE_SIZE, _race_rotate)
        _race_rotate += 1        # 步进 1：race_slice 内部按「尾段/格数」自增，保证铺满
        for mode in mode_order(host):
            remain = deadline - time.time()
            if remain < 2:
                errs.append("预算耗尽")
                break
            sock, ip, e = race(batch, mode, min(PHASE_BUDGET, remain))
            errs.extend(e)
            if sock is not None:
                # 前面整段失败的模式 = 此刻它正被针对，记一笔惩罚挪到队尾。
                # 实测（2026-09-14）：github.com 的「正常 SNI」会出现 4 个 IP 全部
                # 握不上手（TCP 通、TLS 无响应），而「无 SNI」1s 就通 —— 不记这笔，
                # 下次遇到 GOOD_PEER 失效时又要先白等一轮 6s×N。实测首页因此 23s。
                for m in dead_modes:
                    MODE_PENALTY[host] = (m, time.time() + MODE_PENALTY_TTL)
                if dead_modes:
                    log("  通道 %s 整段失败，已记惩罚（下次先试另一条）"
                        % "、".join("无SNI" if m is None else "正常SNI"
                                   for m in dead_modes))
                sock._ghp_peer = (ip, mode)    # 连接自带身份（审计 S5.6）
                GOOD_PEER[host] = (ip, mode)
                log("  -> %s (%s) [%s]" % (host, ip, "无SNI" if mode is None else "正常SNI"))
                return sock
            dead_modes.append(mode)
        else:
            continue
        break

    GOOD_PEER.pop(host, None)
    raise RuntimeError("所有通道失败(%d): %s" % (len(errs), "; ".join(errs[:3])))


def mark_channel_bad(host, chan=False):
    """某条通道出问题时调用：作废「上次成功的通道」，必要时给这个 SNI 模式记一笔惩罚。

    chan=True 表示「问题不在某一条连接，而在这条通道本身」——体传到一半卡死，
    或刚建立的连接连响应头都等不到（GFW 常放行握手、再把请求整个吞掉）。

    实测 github.com 首页正是后者：正常 SNI 握手永远成功、请求永远石沉大海。
    若只在「体传到一半」时才记惩罚，重试会一次次重新选中这条坏通道 ——
    明明另一条通道 2s 就通，却要空耗到预算尽、浏览器吃 502。
    """
    peer = GOOD_PEER.pop(host, None)
    if chan and peer:
        MODE_PENALTY[host] = (peer[1], time.time() + MODE_PENALTY_TTL)
        # 刚被证明「真的能跑通」的模式又坏了 → 撤回提升（惩罚已经压住它，这里保持状态诚实）
        if MODE_GOOD.get(host) == peer[1]:
            MODE_GOOD.pop(host, None)
        # 这条通道刚坐实不可用，它名下的池化连接也别再拿去试了（顺带把旧桶收掉）
        drop_pool(host, peer[1])


# ================================================================ 上游连接池

_pool = {}
_pool_lock = threading.Lock()


def pool_get(host, ip, mode):
    """取一条空闲连接；顺带清掉过期或超次数的。"""
    key = (host, ip, mode)
    now = time.time()
    with _pool_lock:
        bucket = _pool.get(key)
        if not bucket:
            return None
        while bucket:
            sock, nreq, ts = bucket.pop()
            if now - ts <= POOL_IDLE_TIMEOUT and nreq < POOL_MAX_REQ:
                return sock, nreq
            close_quietly(sock)
    return None


def pool_put(host, ip, mode, sock, nreq):
    """把连接放回池子；超次数或池满就关掉。

    顺手做一次「孤儿桶」清理。池是按 `(host, ip, 模式)` 分桶的，而 pool_get
    只会查**当前 GOOD_PEER** 对应的那一个桶 —— 于是只要 peer 换了 IP 或换了
    模式（拨号失败、模式惩罚都会），旧桶就再也没人查询，也就再也没人做过期回收
    （过期检查在 pop 那一侧），里面的 socket 会一直占着 fd 直到进程退出。
    这条路径每请求跑一次，正好当回收点；在飞的连接早已被 pop 出去，不受影响。
    """
    if nreq >= POOL_MAX_REQ:
        close_quietly(sock)
        return
    with _pool_lock:
        cur = GOOD_PEER.get(host)
        live = (cur[0], cur[1]) if cur else None     # 只有这个桶还有人查
        for k in [k for k in _pool if k[0] == host and (k[1], k[2]) != live]:
            for s, _n, _t in _pool.pop(k):
                close_quietly(s)
        if live != (ip, mode):
            # 别的线程刚把 GOOD_PEER 换掉了 → 我们这条不会再有人来取，存进去就是孤儿
            close_quietly(sock)
            return
        bucket = _pool.setdefault((host, ip, mode), [])
        if len(bucket) >= POOL_MAX_IDLE:
            close_quietly(sock)
            return
        bucket.append((sock, nreq, time.time()))


# ================================================================ 连接池保温
#
# 为什么需要（2026-09-21 定性）：
#   POOL_IDLE_TIMEOUT = 45s，而真实用法是「看一会儿、隔几分钟再点一下」
#   ⇒ 池子基本永远是空的，**每次点击都要重吃一遍冷连接学费**。
#   实测同一域名的学费：首次 2.16s / 池化 0.27s —— 差 8 倍。
#   保温把这条学费从「每次点击」摊成「每次连接过期」。
#
# 它**不改 GOOD_PEER 的选择逻辑**，只是在池子空了的时候先把连接拨好。
# 失败一律静默：保温是优化不是功能，它挂掉不影响任何正常路径。
WARM_HOSTS = ("github.com", "api.github.com", "codeload.github.com",
              "raw.githubusercontent.com")
WARM_INTERVAL = 20              # 秒。必须 **< POOL_IDLE_TIMEOUT(45)**，否则保了也白保
WARM_BUDGET = 8                 # 单条保温连接最多等多久。刻意不用满 REQUEST_BUDGET(24)，
                                # 免得保温线程跟用户请求抢通道
WARM_FIRST_DELAY = 3            # 启动后先等一会儿再保，别和「刚起来那批请求」挤在一起


def _pool_has(host):
    """池里该 host 有没有还没过期的空闲连接。**只看不取**
    （pool_get 是 pop，拿它做检查会把连接吃掉）。"""
    now = time.time()
    with _pool_lock:
        for k, bucket in _pool.items():
            if k[0] != host:
                continue
            for _s, nreq, ts in bucket:
                if now - ts <= POOL_IDLE_TIMEOUT and nreq < POOL_MAX_REQ:
                    return True
    return False


def start_warmer():
    """起后台保温线程。返回线程对象（供自测 join/检查）。"""
    def loop():
        time.sleep(WARM_FIRST_DELAY)
        while True:
            for host in WARM_HOSTS:
                try:
                    if _pool_has(host):
                        continue
                    sock, ip, mode = connect_upstream(host, budget=WARM_BUDGET)
                    pool_put(host, ip, mode, sock, 0)
                except Exception:
                    pass                        # 保温失败不影响任何正常路径
            time.sleep(WARM_INTERVAL)

    t = threading.Thread(target=loop, daemon=True, name="pool-warmer")
    t.start()
    return t


def drop_pool(host, mode=None):
    """丢掉池子里属于该 host（可选：限定某个模式）的连接。

    两个用途：
      ① 某条通道刚被判为不可用 → 它名下的池化连接同样可疑，没必要留着试；
      ② 池是按 `(host, ip, 模式)` 分桶的，而 `pool_get` 只会查「当前 GOOD_PEER」
         对应的那一个桶。**模式一切换，旧桶就再也没人查询，也就再也没人清理** ——
         里面的连接会一直占着 fd（每条最长 POOL_IDLE_TIMEOUT 也没用，因为
         过期检查是在 pop 的那一侧做的）。模式切换恰好被本次新增的惩罚机制变常见了，
         所以这里顺手收掉。
    """
    with _pool_lock:
        keys = [k for k in _pool
                if k[0] == host and (mode is None or k[2] == mode)]
        for k in keys:
            for sock, _n, _t in _pool.pop(k):
                close_quietly(sock)


def close_quietly(obj):
    try:
        obj.close()
    except Exception:
        pass


# ================================================================ HTTP 报文

HOP_BY_HOP = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"te", b"trailer", b"trailers", b"transfer-encoding", b"upgrade",
    b"proxy-connection",
}

# 回给浏览器要剥的头。注意 transfer-encoding 是**例外**：
# 我们原样中继 chunked 分块帧，所以必须保留 `Transfer-Encoding: chunked` 声明。
# 一旦把它剥掉，浏览器就会把块长（如 "16EC\r\n"）当成正文内容 —— 页面直接花掉。
# （这个坑真实踩过：github.com 首页 577KB 全是乱码，却因为「只看长度」的测试而蒙混过关。）
CLIENT_STRIP = (HOP_BY_HOP - {b"transfer-encoding"}) | {b"alt-svc"}


def read_head(sock, carry=b"", limit=64 << 10, budget=None):
    """读一个完整的报文头。返回 (head, 多读出来的字节)；对端正常关连接返回 (None, b"")。

    budget —— 整个头的**总**读取预算（秒）。缺省无总预算（上游响应头沿用各调用方
    已设的 socket 超时语义）；客户端侧传 HEADER_READ_TOTAL 防慢滴灌。

    超时必须把 socket.timeout 原样抛出去 —— 调用方得靠它区分两种截然不同的状况：
      · 对端关连接（读回 b""）：只是这条连接死了，换一条就行；
      · 超时（一个字节都没回）：通道把请求整个吞了，得换 SNI 模式。
    这里若把异常一并吞掉换成 (None, b"")，两者就再也分不出来了。
    """
    start = time.time()
    buf = carry
    while b"\r\n\r\n" not in buf:
        if budget is not None:
            wait = budget - (time.time() - start)
            if wait <= 0:
                raise socket.timeout("报文头总预算耗尽(%ds)" % budget)
            sock.settimeout(wait)
        data = sock.recv(CHUNK)
        if not data:
            return None, b""
        buf += data
        if len(buf) > limit:
            raise ValueError("报文头过大")
    idx = buf.index(b"\r\n\r\n")
    return buf[: idx + 4], buf[idx + 4:]


def parse_head(raw):
    """把报文头拆成 (起始行, [(名字小写, 原值)])。"""
    lines = raw.split(b"\r\n")
    start = lines[0] if lines else b""
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(b":")
        if sep:
            headers.append((name.strip().lower(), value.strip()))
    return start, headers


def header_value(headers, name):
    for k, v in headers:
        if k == name:
            return v
    return None


def connection_tokens(headers):
    """Connection 头里列出的字段名 —— 这些同样是 hop-by-hop，必须删。"""
    tokens = set()
    value = header_value(headers, b"connection")
    if value:
        for t in value.split(b","):
            t = t.strip().lower()
            if t:
                tokens.add(t)
    return tokens


def build_upstream_head(start, headers, host, body_len=0, req_te=None):
    """组装发往上游的请求头：剥 hop-by-hop、Host 去端口、强制 keep-alive。

    `Connection: keep-alive` 由我们自己加 —— 客户端说了 close 也不影响我们复用上游。
    （注意别把 connection_tokens 里的 keep-alive 再 discard 回来，那样客户端发来的
    `Keep-Alive:` 头就会漏给上游，它同样是 hop-by-hop。）

    分帧头由我们「按实际转发的字节」重写一条，绝不原样透传客户端的：
      · Content-Length：客户端若发了两个不一致的值，原样转发会给上游造成请求走私
        （上游按其中一条切帧，我们按另一条搬字节）。
      · req_te 非 None 时按原值补回 `Transfer-Encoding` 声明，并**必须**把客户端那条
        Content-Length 丢掉 —— RFC 9112 §6.3：TE 与 CL 同时出现时以 TE 为准，
        留着 CL 就是标准的走私构造。注意这里是 hop-by-hop 的**例外**，
        理由和响应侧的 CLIENT_STRIP 完全一样：我们原样中继分块帧，就必须保留声明。
        原值保留（而不是写死 "chunked"）：客户端可能用 "gzip, chunked"，
        只写 chunked 会让上游少解一层，应用层拿到的是 gzip 垃圾。
    """
    drop = set(HOP_BY_HOP) | connection_tokens(headers) | {b"content-length"}
    had_cl = header_value(headers, b"content-length") is not None

    out = [start, b"Host: " + host.encode("latin-1", "replace")]
    for k, v in headers:
        if k in drop or k == b"host":
            continue
        # 100-continue 我们已经代答过了，别再让上游等
        if k == b"expect" and b"100-continue" in v.lower():
            continue
        out.append(k.title() + b": " + v)
    if req_te is not None:
        out.append(b"Transfer-Encoding: " + req_te)
    elif had_cl:
        out.append(b"Content-Length: %d" % body_len)
    out.append(b"Connection: keep-alive")
    return b"\r\n".join(out) + b"\r\n\r\n"


def build_client_head(status, reason, headers, keep_alive):
    """组装回给浏览器的响应头。

    headers 已剥过 hop-by-hop；分帧头是我们自己重写过的，其中
    `Transfer-Encoding: chunked` 必须原样保留（见 CLIENT_STRIP 的注释）。
    """
    first = b"HTTP/1.1 %d %s" % (status, reason)
    parts = []
    for k, v in headers:
        if k in CLIENT_STRIP:
            continue
        parts.append(k.title() + b": " + v)
    parts.append(b"Connection: " + (b"keep-alive" if keep_alive else b"close"))
    return first + b"\r\n" + b"\r\n".join(parts) + b"\r\n\r\n"


class ChunkedScanner:
    """只看 chunked 的框架、不解码内容 —— 我们是原样转发的，只需要知道到哪结束。"""

    HEX = b"0123456789abcdefABCDEF"
    MAX_LINE = 1024               # 单个 chunk 长度行的上限（再长一定是垃圾）
    MAX_PENDING = 64 << 10        # 尾部/长度行攒着的上限，跟报文头一个量级

    def __init__(self):
        self.state = "size"        # size → data → size … → trailer
        self.need = 0              # data 状态还要跳过多少字节（含结尾的 CRLF）
        self.pending = b""         # 上一批「没等到 CRLF」的尾巴（这些字节已经转发过）
        self._tail = b""           # data 态最近消费的至多 2 字节（回看校验终止 CRLF）

    def feed(self, data):
        """喂入新收到的字节，返回 (是否结束, 本批属于体的字节数)。

        把 pending 拼回来一起解析，避免 CRLF 被 recv 切成两半时丢终止符；
        但返回值只统计「本批」的字节，上一批的尾巴不会重复计数。
        结束时 used 可能小于 len(data)（多出来的是下一个报文，本连接不复用，丢弃）。
        """
        pend = len(self.pending)
        if pend:
            data = self.pending + data
            self.pending = b""
        n = len(data)
        i = 0
        while i < n:
            if self.state == "size":
                j = data.find(b"\r\n", i)
                if j < 0:
                    if n - i > self.MAX_LINE:
                        raise ValueError("chunked 长度行过长(%d)" % (n - i))
                    self.pending = data[i:]
                    return False, n - pend
                line = data[i:j].split(b";")[0].strip()
                i = j + 2
                # 严格按 RFC 9112：chunk-size = 1*HEXDIG。
                # ⚠️ 绝不能只靠 int(line, 16)：Python 的 int 太宽容，会吃下
                # "+5"、"0x4"、"1_6"，甚至 **"-3"** —— 负长度会让 need 变负、
                # 把帧长账算乱，实测能让本函数**提前宣布响应结束**（done=True）。
                # 后果是半截响应被当成成功、错位的连接还被放回池子继续用。
                # （这正是当初「首页 577KB 全乱码却测试通过」的同款病根。）
                if not line or len(line) > 16 or any(c not in self.HEX for c in line):
                    raise ValueError("chunked 长度行非法: %r" % line[:16])
                size = int(line, 16)
                if size == 0:
                    self.state = "trailer"
                else:
                    self.need = size + 2          # 数据 + 结尾 CRLF
                    self.state = "data"
            elif self.state == "data":
                take = min(self.need, n - i)
                if take:
                    # 沙盒攻击实验（E7）坐实 R2-5：数据后的终止符若不回看校验，
                    # 「5\r\nAAAAA\rQ\n0\r\n\r\n」这类帧会被静默放行、原样中继给
                    # 客户端（客户端解析器可能错位）。终止符不是 CRLF 一律报错。
                    self._tail = (self._tail + data[i:i + take])[-2:]
                self.need -= take
                i += take
                if self.need == 0:
                    if self._tail != b"\r\n":
                        raise ValueError("chunk 数据后的终止符不是 CRLF")
                    self._tail = b""
                    self.state = "size"
            else:                                 # trailer
                j = data.find(b"\r\n", i)
                if j < 0:
                    if n - i > self.MAX_PENDING:
                        raise ValueError("chunked 尾部过大(%d)" % (n - i))
                    self.pending = data[i:]
                    return False, n - pend
                if j == i:                        # 空行 = 体结束
                    return True, max(0, j + 2 - pend)
                i = j + 2
        return False, n - pend


# ================================================================ 异常

class ClientGone(Exception):
    """浏览器那一端断了 —— 立刻停手，别继续浪费上游流量。"""


class BadRequest(Exception):
    """**客户端**发来的报文本身不合法（分块帧乱、长度对不上……）。

    必须和 UpstreamBroken 分开，否则会同时错两处：
      · 日志写成「上游失败」，把排查方向整个带偏（明明是对方发错了）；
      · 回 502 Bad Gateway，而正确答案是 400 —— 502 会让客户端以为「服务端
        的问题，重试一下也许就好了」，于是把同一个坏请求再送一遍。
    这类错误不值得重试：重发一次还是同样的坏字节。
    """


class UpstreamBroken(Exception):
    """上游传输出问题。

    sent —— 是否已经往浏览器发过字节（发过就改不了状态码，只能断开）。
    chan —— 这次失败是否指向「通道本身不可用」，而不是「碰上一条死连接」。
            置 True 的判据只有两条：
              · 体传到一半坏掉（握手、请求都好好的，通道中途没了）；
              · 在**刚建立的**连接上连响应头都没等到（超时 / 对端直接关）。
            这类失败要给当前的 SNI 模式记一笔惩罚，下次先试另一条通道。
            反之，池里捞出的死连接、sendall 当场报错，都只是连接级问题，不该牵连模式。
    ip_bad —— 对端答的压根不是这个域名（默认虚拟主机兜底）。说明这个 IP 走错了边缘，
            要把它拉黑，而不是怪 SNI 模式。详见 is_wrong_vhost。
    req_fully_sent —— 请求头是否已完整发出。False 仅出现在「sendall 半途失败」：
            此时上游应用不可能见过完整请求，重发无副作用（审计 S6.1 的幂等边界）。
    """

    def __init__(self, err, sent=False, chan=False, ip_bad=False,
                 req_fully_sent=True):
        super().__init__(str(err))
        self.sent = sent
        self.chan = chan
        self.ip_bad = ip_bad
        self.req_fully_sent = req_fully_sent


def send_to_client(sock, data):
    try:
        sock.sendall(data)
    except Exception as e:
        raise ClientGone(str(e)[:60])


# ================================================================ 流式搬运响应体

# 这些是「内容/接口域」——它们**从不**把请求原样挂到 github.com 下当 301。
# 反过来说：对它们而言，出现「同路径 301 → github.com」就是真·错虚拟主机。
# ⚠️ 但**根路径 `/` 永远豁免**：codeload / raw 的 `GET /` 回
#    `301 → https://github.com/` 是 CDN 的既定行为（实测两条 SNI 通道、
#    140.82.112.9 / 20.205.243.165 / 185.199.*.133 全部如此，与 IP 归属无关）。
#    旧版按「路径逐字节相同」判，`/` 与 `/` 相同 → codeload/raw 直接被误拉黑 600s，
#    症状是「健康 IP 被自己踢出竞速、且日志说它答错虚拟主机」（2026-09-21 踩）。
_STRICT_VHOST_HOSTS = frozenset((
    "api.github.com", "raw.githubusercontent.com", "codeload.github.com",
    "gist.github.com", "objects.githubusercontent.com", "media.githubusercontent.com",
    "release-assets.githubusercontent.com", "uploads.github.com",
    "camo.githubusercontent.com", "user-images.githubusercontent.com",
    "private-user-images.githubusercontent.com", "github-cloud.githubusercontent.com",
))


def is_wrong_vhost(host, req_path, status, headers):
    """这个回应是不是 CDN 的「默认虚拟主机」兜底 —— 即这个 IP 其实不属于该域名。

    判据刻意收得很紧：3xx + Location 恰好是「把**同一个路径**挂到 github.com 下」。
    实测错 IP 的回应：
        GET https://api.github.com/repos/torvalds/linux  (Host/SNI 都对)
        <- HTTP/1.1 301 Moved Permanently
           Location: https://github.com/repos/torvalds/linux      ← 路径一字未改

    真实的接口/内容域名（api / codeload / gist）从不这样回；
    而确实要跳转的页面（如某个子域跳到 github.com/resources）路径会变，
    所以「路径必须逐字节相同」这条能把误判挡掉。

    ⚠️ 光靠「路径相同」还不够：**根路径 `/` 是天然同路径**，
    而 `GET /` 在 codeload / raw 上本就该回 `301 → https://github.com/`。
    因此再加两道闸：
      ① req_path 就是 `/` → 一律不判错（无法用「同路径」区分真伪）；
      ② host 不在内容域白名单里 → 不判错（宁可漏判，也不误拉黑健康 IP：
         ip_bad 的代价是把这个 IP 踢出竞速 600s，会影响该域**所有**后续请求）。
    """
    if status not in (301, 302, 303, 307, 308) or not req_path:
        return False
    if host in ("github.com", "www.github.com"):
        return False                      # github.com 本来就是默认虚拟主机
    if req_path == "/":
        # 根路径的 301 → github.com/ 是 CDN 正常行为，不是错虚拟主机。
        # 实测：codeload.github.com GET / → 301 https://github.com/ （所有 IP、两种通道）
        return False
    if host not in _STRICT_VHOST_HOSTS:
        # 非内容域（如 avatars / githubassets / github.io 等静态资源域）不做这项判定：
        # 它们回 301 → github.com 可能是正常跳转，误拉的代价远大于收益。
        return False

    loc = (header_value(headers, b"location") or b"").strip()
    low = loc.lower()
    for pre in (b"https://", b"http://"):
        if low.startswith(pre):
            rest = loc[len(pre):]
            break
    else:
        return False

    rest = rest.split(b"#", 1)[0]
    authority, sep, path = rest.partition(b"/")
    if authority.split(b":")[0].lower() not in (b"github.com", b"www.github.com"):
        return False
    path = b"/" + path if sep else b"/"
    return path == req_path.encode("latin-1", "replace")


def relay_body(up_sock, carry, framing, length, head_out, client_sock, buffered,
               first_allow=None):
    """把上游响应体流式搬给浏览器。

    一开始先攒着不发；攒够 buffered 才把响应头 + 已攒数据一起发出。
    因此「小响应被截断」时一个字节都还没发出去，上层可以换通道重试。

    first_allow —— 等首个字节的预算（默认 DATA_TIMEOUT；调用方一般传
                   FIRST_BYTE_TIMEOUT，池里复用的连接给更短的）。

    正常搬完返回「响应体之后残留的字节数」（通常 0）；出错抛 UpstreamBroken；
    浏览器断了抛 ClientGone。
    残留 > 0 表示上游多给了字节（如 HEAD/204 之后又发了体），这条连接已经错位，
    调用方**必须放弃复用**，否则下一个请求会读到上一次的尾巴。
    """
    if first_allow is None:
        first_allow = DATA_TIMEOUT
    scan = ChunkedScanner() if framing == "chunked" else None
    remaining = length
    buf = carry
    sent = False
    pieces = []
    total = 0
    last = time.time()          # 上次收到数据的时刻
    got_any = False             # 是否已经收到过体数据

    def emit(data):
        nonlocal total
        if not data:
            return
        if sent:
            send_to_client(client_sock, data)
            return
        pieces.append(data)
        total += len(data)
        if total >= buffered:
            start()

    def start():
        nonlocal sent, pieces
        send_to_client(client_sock, head_out)
        for p in pieces:
            send_to_client(client_sock, p)
        pieces = []
        sent = True

    if framing == "none":            # HEAD / 204 / 304：没有体
        start()
        return len(carry)            # 上游若还塞了体，就是残留 → 别复用
    if framing == "length" and length == 0:   # CL:0 —— 一个字节都不会来，别去 recv
        start()
        return len(carry)

    while True:
        if buf:
            if framing == "chunked":
                try:
                    done, used = scan.feed(buf)
                except ValueError as e:
                    raise UpstreamBroken(e, sent, chan=True)
                emit(buf[:used])
                if done:
                    if not sent:
                        start()
                    return len(buf) - used       # 收尾块之后还有字节 = 残留
                buf = buf[used:]
            elif framing == "eof":
                emit(buf)
                buf = b""
            else:                    # length
                take = min(remaining, len(buf))
                emit(buf[:take])
                remaining -= take
                buf = buf[take:]
                if remaining == 0:
                    if not sent:
                        start()
                    return len(buf)              # 读满后还多出来的 = 残留

        # 等首个字节的预算由调用方给（first_allow）；一旦收到过数据，就改按「停滞」判死
        allow = BODY_STALL_TIMEOUT if got_any else first_allow
        wait = allow - (time.time() - last)
        if wait <= 0:
            raise UpstreamBroken("传输停滞 %ds" % allow, sent, chan=True)
        try:
            up_sock.settimeout(wait)
            data = up_sock.recv(CHUNK)
        except Exception as e:
            if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in str(e).lower():
                raise UpstreamBroken("传输停滞 %ds" % allow, sent, chan=True)
            raise UpstreamBroken(e, sent, chan=True)
        if not data:                 # 上游提前关了
            # 只有 eof 分帧才以「关连接」表示体结束，那是正常收尾。
            # chunked 若没读到收尾块、length 若没读满，都算被截断 —— 必须报错，
            # 绝不能当成成功：否则会把一个缺了收尾块的 chunked 体发给浏览器，
            # 浏览器会一直等下一个块，页面就此卡死（首页踩过这个坑）。
            if framing == "eof":
                if not sent:
                    start()
                return 0          # eof 分帧本就不复用，残留无意义
            raise UpstreamBroken("响应体提前结束（%s）" % framing, sent, chan=True)
        last = time.time()
        got_any = True
        buf = buf + data


# ================================================================ 核心：转发一次

def forward_once(client, up_sock, req_head, body_len, method, buffered,
                 client_wants_close=False, reused=False, host=None, req_path=None,
                 req_chunked=False):
    """在上游连接上跑一次请求，并把响应回传给浏览器。

    reused=True 表示这条上游连接是从池子里捞出来的 —— 它可能早被对端关了，
    因此把「等首字节」的预算压短，别让浏览器干等满 60s。

    req_path 是本次请求的路径，host 是对应的域名，两者合起来用来识别
    「答错虚拟主机」的兜底 3xx（见 is_wrong_vhost）。任一为 None 就跳过这项检查。

    req_chunked=True 表示请求体是 chunked 的（此时 body_len 无意义），
    走 pipe_chunked 原样中继分块帧 —— git push 超过 postBuffer 就是这种请求。

    失败时抛 UpstreamBroken；其中 chan / ip_bad 标记的含义见该异常。

    返回 reuse_up：这条上游连接是否还干净、可以放回池子复用。
    （注意与「客户端连接是否保持」是两回事：客户端说了 close 也该回收上游连接。）
    """
    # 等响应头的预算：刚建的连接用 HEADER_TIMEOUT，池里捞的用更短的 POOL_FIRST_BYTE_TIMEOUT。
    # 两条都远小于体传输的 DATA_TIMEOUT —— 「一个字节都不回」是通道故障的特征，
    # 不该按「服务端在慢慢算」来宽容（那 60s 会把重试预算整个吃光）。
    #
    # 再细分一层：**能安全重试的请求（无体的幂等请求）给更短的预算**。
    # 这类请求遇到「握手成功、请求石沉大海」时，正确的动作是尽快换通道重试，
    # 而不是陪着坏通道等满 20s —— 见 HEADER_TIMEOUT_GET 的注释（实测 40s → 20s）。
    #
    # first_allow 管的是「头回来了、体却不动」：头回来了不代表通道活着
    # （GFW 也会放行响应头再把体吞掉）。实测正常值 0.07~0.65s，所以给得比头预算更宽也行，
    # 但**必须明显小于重试总预算**，否则单次尝试就吃光预算、重试结构上不可能发生。
    retryable = (method in IDEMPOTENT and not body_len and not req_chunked)
    if retryable:
        head_allow = HEADER_TIMEOUT_GET
        first_allow = FIRST_BYTE_TIMEOUT_GET
    else:
        head_allow = HEADER_TIMEOUT
        first_allow = FIRST_BYTE_TIMEOUT
    if reused:
        # 池里捞出来的连接随时可能已经死了 → 两种预算都再压一道（min 保证单调）
        head_allow = min(head_allow, POOL_FIRST_BYTE_TIMEOUT)
        first_allow = min(first_allow, POOL_FIRST_BYTE_TIMEOUT)
        up_sock.settimeout(head_allow)      # 发请求这一步也别拖

    try:
        up_sock.sendall(req_head)
    except Exception as e:
        # 请求头没发完整 → 上游应用不可能见过完整请求（审计 S6.1 的重发豁免依据）
        raise UpstreamBroken(e, req_fully_sent=False)

    # 搬请求体前先恢复体预算：reused 分支为了「尽快发现死连接」把 socket 超时
    # 压到了等响应头的短预算（≤15s）；大 body 的发送（git push 的 packfile）
    # 完全可能因上游 TCP 窗口慢而短暂停顿，不该被那个短预算误杀 ——
    # DATA_TIMEOUT 的本职就是这一档（见配置区注释「发请求体等兜底用」）。
    if body_len or req_chunked:
        try:
            up_sock.settimeout(DATA_TIMEOUT)
        except Exception:
            pass

    if req_chunked:
        client.pipe_chunked(up_sock)
    elif body_len:
        client.pipe_out(up_sock, body_len)

    carry = b""
    while True:                      # 跳过 1xx 临时响应，取最终响应
        try:
            up_sock.settimeout(head_allow)
            head, carry = read_head(up_sock, carry)
        except (socket.timeout, TimeoutError):
            close_quietly(up_sock)
            raise UpstreamBroken("等响应头超时(%ds)" % head_allow, sent=False,
                                 chan=not reused)
        except Exception as e:
            close_quietly(up_sock)
            raise UpstreamBroken(e, sent=False, chan=not reused)
        if head is None:
            # 对端把请求收下了却直接关连接。池里捞的连接多半只是「早死了」，
            # 刚建的连接则说明这条通道收得下、送不回 —— 通道级故障。
            close_quietly(up_sock)
            raise UpstreamBroken("上游没给响应头就关了", sent=False, chan=not reused)

        start, headers = parse_head(head)
        parts = start.split(b" ", 2)
        try:
            status = int(parts[1])
        except Exception:
            close_quietly(up_sock)
            raise UpstreamBroken("响应状态行非法: %r" % start[:40])
        reason = parts[2] if len(parts) > 2 else b""
        if not (100 <= status < 200):
            break

    no_body = (method == "HEAD" or status in (204, 304))
    te = header_value(headers, b"transfer-encoding")
    cl = header_value(headers, b"content-length")

    # 先验货：这个回应到底是不是这个域名的？不是就换 IP，别把错内容端给浏览器。
    if is_wrong_vhost(host, req_path, status, headers):
        close_quietly(up_sock)
        raise UpstreamBroken("答错虚拟主机(%d → github.com)" % status, sent=False,
                             ip_bad=True)

    # ---- 决定回给浏览器用什么分帧，并重写响应头 ----
    # RFC 9110 §7.6.1：Connection 头里点名的字段同样是 hop-by-hop，必须删。
    # 请求侧早就这么剥了，响应侧原先漏了 —— 上游若回
    #   Connection: X-Foo   /   X-Foo: whatever
    # 这条 X-Foo 会原样漏给浏览器（还可能带上一些本该止步于本跳的私有头）。
    resp_drop = HOP_BY_HOP | connection_tokens(headers)
    kept = [(k, v) for k, v in headers
            if k not in resp_drop and k != b"content-length"]

    if no_body:
        framing, length = "none", 0
        if cl:                       # HEAD 的 Content-Length 有意义，要留着
            kept.append((b"content-length", cl))
    elif te and b"chunked" in te.lower():
        framing, length = "chunked", 0
        # 必须原样保留上游的 TE 值（可能是 "gzip, chunked"）。
        # 硬写成 "chunked" 会丢掉 gzip 那一层声明 —— 客户端解完分块得到的是
        # 仍被 gzip 压着的数据，却不知道要解压，页面直接花掉。
        kept.append((b"transfer-encoding", te))
    elif te:
        # TE 存在但不是 chunked（如 "gzip"）→ RFC 9112：这种体由「关连接」界定边界。
        # 不能错当 Content-Length 处理，否则会一直 recv 到超时。
        framing, length = "eof", 0
    elif cl is not None:
        try:
            length = int(cl)
        except ValueError:
            close_quietly(up_sock)
            raise UpstreamBroken("Content-Length 非法: %r" % cl)
        if length < 0:
            # 请求侧在 serve 里就拒了负值，响应侧原先漏了（审计 V9）——
            # 负长度会让 relay_body 的账目进入负切片的未定义行为。
            close_quietly(up_sock)
            raise UpstreamBroken("Content-Length 为负: %r" % cl)
        framing = "length"
        kept.append((b"content-length", b"%d" % length))
    else:
        framing, length = "eof", 0   # 只能靠关连接表示结束

    conn_hdr = (header_value(headers, b"connection") or b"").lower()
    upstream_wants_close = b"close" in conn_hdr or start.startswith(b"HTTP/1.0")

    # 204/304/HEAD 本来就不该有体，我们按 framing="none" 处理、不会去读体。
    # 但若上游偏偏声明了 Transfer-Encoding，说明它打算发点什么 —— 那些字节没人读，
    # 这条流就永远留着未消化数据。放回池子的话，下一个请求会把上一次的残体
    # 当成响应头读（内容错乱，且极难归因）。所以这种连接一律不复用。
    # （实测 GitHub 的 HEAD/304 都不带 TE，所以这条是白拿的保险。）
    tainted = no_body and te is not None
    reuse_up = (not upstream_wants_close) and framing != "eof" and not tainted

    # 回给浏览器的 Connection：只有「上游能复用」且「客户端没说要关」才 keep-alive
    keep_client = reuse_up and not client_wants_close
    head_out = build_client_head(status, reason, kept, keep_client)
    try:
        leftover = relay_body(up_sock, carry, framing, length, head_out, client.sock,
                              buffered, first_allow)
    finally:
        # relay_body 为判定「停滞」会临时改小 socket 超时，复用前必须还原，
        # 否则这条连接放回池子后，下一个请求的头读取会瞬间超时。
        try:
            up_sock.settimeout(DATA_TIMEOUT)
        except Exception:
            pass

    if leftover:
        # 上游在响应体之后还多给了字节 → 这条连接已错位，放回池子会让
        # 下一个请求读到上一次的尾巴（内容错乱）。
        log("  上游多给 %d 字节，放弃复用该连接" % leftover, warn=True)
        reuse_up = False

    if not reuse_up:
        close_quietly(up_sock)
    return reuse_up


# ================================================================ 客户端连接

class Client:
    """带缓冲的客户端连接：能精确「读头」和「读 N 字节体」。"""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.body_consumed = False   # 是否已从浏览器读过请求体（读过就不可重放）
        self.head_too_big = False    # 请求头超限（serve 据此回 431 而不是静默断连）

    def read_head(self):
        """客户端侧读头：超时 / 断开都只当作「这轮对话结束」，不往上抛。

        唯一例外是「报文头过大」：单独标记出来，让 serve 能回 431 并留日志
        （审计 V19：原先 ValueError 被一并吞掉，超大头静默断连无从排查）。"""
        try:
            head, self.buf = read_head(self.sock, self.buf,
                                       budget=HEADER_READ_TOTAL)
        except ValueError as e:
            self.head_too_big = True
            log("  请求头超限: %s" % e, warn=True)
            return None
        except Exception:
            return None
        return head

    def recv(self, n=CHUNK):
        if self.buf:
            data, self.buf = self.buf[:n], self.buf[n:]
            return data
        return self.sock.recv(n)

    def pipe_out(self, dst, n):
        """把恰好 n 字节搬到 dst（流式，不驻留内存）—— 给 git push 的大 body 用。

        开头就置 body_consumed：**只要动过这些字节，本请求就不可重放了**。
        请求体只存在于浏览器那一侧，读过就没了 —— 若还去重试，就会带着
        `Content-Length: n` 却一个字节都发不出，上游苦等、浏览器那头则是
        连接被直接掐断（比回 502 更难懂）。上层据此禁止重试。
        """
        self.body_consumed = True
        left = n
        while left > 0:
            piece = self.recv(min(CHUNK, left))
            if not piece:
                raise ClientGone("请求体提前结束")
            try:
                dst.sendall(piece)
            except Exception as e:
                raise UpstreamBroken(e)
            left -= len(piece)

    def pipe_chunked(self, dst):
        """原样中继一个 chunked 请求体（连分块帧一起搬），到收尾块为止。

        为什么必须有这条路：**git push 的请求体超过 http.postBuffer（默认 1 MiB）
        就会切成 chunked**。实测（2026-09-12，git 2.55 + git http-backend）一次
        3.1 MB 的推送：
            POST /r.git/git-receive-pack   Transfer-Encoding: chunked   CL=None
        旧版对任何带 TE 的请求一律回 411，等于「仓库大一点就推不上去」，且报错
        发生在客户端、日志里只有一行 warn，极难归因。

        复用响应侧那个严格扫描器 —— 请求体和响应体的分块框架是同一套 RFC 9112，
        没必要写两份（也能一起吃到「严格 HEXDIG」那个修复）。

        契约与 pipe_out 一致：一动手就置 body_consumed（读过就不可重放）。
        """
        self.body_consumed = True
        scan = ChunkedScanner()
        while True:
            piece = self.recv(CHUNK)
            if not piece:
                raise ClientGone("请求体提前结束")
            try:
                done, used = scan.feed(piece)
            except ValueError as e:
                # 客户端自称 chunked 却发不出合法分块帧 —— 这条连接已经没法再对齐，
                # 只能断开（绝不能当成功，否则后面全错位）。
                raise BadRequest("请求分块非法: %s" % str(e)[:60])
            if used:
                try:
                    dst.sendall(piece[:used])
                except Exception as e:
                    raise UpstreamBroken(e)
            if done:
                # 收尾块之后多出来的字节属于下一个请求（流水线），塞回缓冲区
                rest = piece[used:]
                if rest:
                    self.buf = rest + self.buf
                return


# ================================================================ 连接处理

SERVER_CTX = None
_slots = threading.BoundedSemaphore(MAX_CLIENT_CONNS)


def handle(raw_client, addr):
    """一个客户端连接一个线程；同一条连接上支持 keep-alive 多请求。"""
    if not _slots.acquire(blocking=False):
        log("并发已满，拒绝 %s" % (addr[0],), warn=True)
        close_quietly(raw_client)
        return

    tls = None
    try:
        try:
            # 握手独立预算（审计 S2）：槽已在本函数入口占用，握手若无限期挂起，
            # 128 个慢握手就能永久占满并发槽。20s 宽值，劣化链路合法握手也够。
            try:
                raw_client.settimeout(TLS_HANDSHAKE_CLIENT_TIMEOUT)
            except Exception:
                pass
            tls = SERVER_CTX.wrap_socket(raw_client, server_side=True)
        except Exception as e:
            log("  TLS 握手失败(%s): %s" % (addr[0], str(e)[:60]))
            return

        tls.settimeout(CLIENT_IDLE_TIMEOUT)
        try:
            tls.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        try:
            serve(Client(tls), addr)
        except Exception as e:
            log("  处理异常(%s): %s" % (addr[0], str(e)[:90]))
    finally:
        close_quietly(tls if tls is not None else raw_client)
        _slots.release()


def serve(client, addr):
    """一条客户端连接上可以跑多个请求。"""
    while True:
        head = client.read_head()
        if head is None:
            if getattr(client, "head_too_big", False):
                try:
                    send_to_client(client.sock, b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                                                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                except Exception:
                    pass
            return

        start, headers = parse_head(head)
        parts = start.split(b" ")
        method = parts[0].decode("ascii", "replace").upper() if parts else ""
        target = parts[1] if len(parts) > 1 else b"/"

        # RFC 9112 §3.2.2：absolute-form 的目标必须改写成 origin-form 再转给上游。
        # 按请求行结构判断（审计 S6.2：旧版 b"://" in target 的子串匹配会把查询串
        # 里恰好含 :// 的普通 origin-form 请求静默改写丢路径）。
        # 浏览器走我们这条 MITM 永远是 origin-form，但「配了 http_proxy 环境变量的
        # 工具」（curl / git 都会）会发 `GET http://github.com/x HTTP/1.1`。
        # 原样转发有两个现成后果：
        #   · 上游按**请求行里的 authority** 选虚拟主机，与 Host 头打架时会被路由到
        #     别的 vhost（拿到别人的内容，或一个 301）；
        #   · 那个 301 恰好长得像「答错虚拟主机」，于是 is_wrong_vhost 把一个好 IP
        #     拉黑 10 分钟 —— 自己把自己最好的通道踢出竞速，且完全无从归因。
        # （实测触发过：探针脚本里 git 就发出过 absolute-form 的 POST。）
        _t8 = target[:8].lower()
        if _t8.startswith(b"http://") or _t8.startswith(b"https://"):
            rest = target.split(b"://", 1)[1]
            target = (b"/" + rest.split(b"/", 1)[1]) if b"/" in rest else b"/"
            ver = parts[2] if len(parts) > 2 else b"HTTP/1.1"
            start = b" ".join((parts[0], target, ver))

        path = target.decode("latin-1", "replace")

        host_raw = header_value(headers, b"host") or b""
        # 统一小写（审计 V11）：host 同时是白名单键、SNI、上游 Host、池键与拉黑键，
        # 原始大小写会让 is_wrong_vhost 的白名单比较漏判、误把好 IP 拉黑
        host = host_raw.decode("latin-1", "replace").split(":")[0].strip().lower()
        if not host:
            # RFC 9112 §3.2：HTTP/1.1 请求必须带 Host。静默断连只会让客户端看到
            # 「连接莫名被掐」，既不合规也无从排障 —— 明确回 400 并写进日志。
            log("请求缺少 Host 头，回 400", warn=True)
            send_to_client(client.sock, b"HTTP/1.1 400 Bad Request\r\n"
                                        b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return

        # ---- 专一：只服务 GitHub ----
        if not host_allowed(host):
            log("拒绝非 GitHub 域名 %s" % host, warn=True)
            send_to_client(client.sock, b"HTTP/1.1 403 Forbidden\r\n"
                                        b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return

        if header_value(headers, b"upgrade"):
            log("收到 Upgrade 请求，已按 RFC 剥离（本代理不支持 WebSocket）", warn=True)

        # ---- 请求体分帧 ----
        # 两种都必须支持：
        #   · `Content-Length: n`（绝大多数请求）
        #   · `Transfer-Encoding: chunked`（git push 超过 http.postBuffer 就切它，
        #     见 Client.pipe_chunked 的注释 —— 旧版一律 411 是真实的功能缺陷）
        # 只有「最后一个编码不是 chunked」时才真的没法界定边界 → 501。
        req_te = header_value(headers, b"transfer-encoding")
        req_chunked = False
        body_len = 0
        if req_te is not None:
            codings = [c.strip().lower() for c in req_te.split(b",") if c.strip()]
            # RFC 9112 §6.1：chunked 必须是最后一层编码，否则无法判断体到哪结束。
            if not codings or codings[-1] != b"chunked":
                log("请求 Transfer-Encoding 无法界定边界: %r (%s %s)"
                    % (req_te[:40], method, path[:40]), warn=True)
                send_to_client(client.sock, b"HTTP/1.1 501 Not Implemented\r\n"
                                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                return
            req_chunked = True
            if header_value(headers, b"content-length") is not None:
                # 走私构造的典型特征：两者同时出现。我们按 RFC 以 TE 为准并丢掉 CL，
                # 上游只会看到一条 TE，切帧口径与我们一致，构不成走私。
                log("请求同时带 Transfer-Encoding 与 Content-Length，按 RFC 9112 §6.3 "
                    "以 TE 为准（%s %s）" % (method, path[:40]), warn=True)
        cl = header_value(headers, b"content-length")
        if cl is not None:
            try:
                body_len = int(cl)
                if body_len < 0:
                    raise ValueError(cl)
            except ValueError:
                log("Content-Length 非法: %r" % cl[:40], warn=True)
                send_to_client(client.sock, b"HTTP/1.1 400 Bad Request\r\n"
                                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if len([1 for k, _v in headers if k == b"content-length"]) > 1:
                log("请求有多个 Content-Length，按第一条 %d 转发并去重（%s %s）"
                    % (body_len, method, path[:40]), warn=True)

        # 浏览器在等我们放行才肯发 body，那我们就自己先回 100
        if b"100-continue" in (header_value(headers, b"expect") or b"").lower():
            send_to_client(client.sock, b"HTTP/1.1 100 Continue\r\n\r\n")

        req_head = build_upstream_head(start, headers, host, body_len, req_te)
        client_wants_close = b"close" in connection_tokens(headers)

        # ---- 发出去；失败就换通道重试 ----
        done = False
        last_err = None
        t_start = time.time()
        for attempt in range(MAX_ATTEMPTS):
            if attempt and time.time() - t_start > ATTEMPT_BUDGET:
                last_err = "重试超预算(%.0fs)" % (time.time() - t_start)
                break

            sock = None
            from_pool = False
            nreq = 0

            peer = GOOD_PEER.get(host)
            if peer:
                got = pool_get(host, peer[0], peer[1])
                if got:
                    sock, nreq = got
                    from_pool = True
            if sock is None:
                remain = ATTEMPT_BUDGET - (time.time() - t_start)
                try:
                    sock = connect_upstream(
                        host, max(6, min(REQUEST_BUDGET, remain)))
                except Exception as e:
                    last_err = e
                    break
                # 用连接自带身份（审计 S5.6）：GOOD_PEER 可能已被其它线程换掉，
                # 二次查表的旧快照会把好 IP 拉黑/把连接归错池桶
                peer = getattr(sock, "_ghp_peer", None) or GOOD_PEER.get(host)

            try:
                reuse_up = forward_once(client, sock, req_head, body_len,
                                        method, FLUSH_THRESHOLD, client_wants_close,
                                        from_pool, host, path, req_chunked)
            except ClientGone:
                close_quietly(sock)
                return                        # 浏览器走了，收工
            except BadRequest as e:
                # 是对方发错了，不是上游坏了 —— 回 400、别重试、日志如实说
                close_quietly(sock)
                log("  客户端报文非法: %s" % e, warn=True)
                send_to_client(client.sock, b"HTTP/1.1 400 Bad Request\r\n"
                                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                return
            except UpstreamBroken as e:
                last_err = e
                if e.ip_bad and peer:
                    # 这个 IP 答的不是这个域名 → 拉黑它，下次竞速直接跳过。
                    # 不惩罚 SNI 模式：换模式也救不了，换 IP 才行。
                    mark_ip_bad(host, peer[0])
                    log("  %s 回错虚拟主机，拉黑该 IP %s" % (host, peer[0]), warn=True)
                mark_channel_bad(host, e.chan)
                close_quietly(sock)
                if e.sent:
                    return                    # 已经发了一半，状态码改不了，只能断开
                if attempt + 1 >= MAX_ATTEMPTS:
                    break
                # ⚠️ 请求体一旦被读过就不可重放（body 只在浏览器那一侧）。
                # 这里必须挡在 from_pool 前面：池里捞出的连接失败时，
                # 上面那条 from_pool 短路会让带 body 的请求也去重试 ——
                # 结果是上游苦等一个永远不来的 body，浏览器则等到连接被掐断。
                if getattr(client, "body_consumed", False):
                    break
                # 幂等边界（审计 S6.1）：无体幂等请求重试永远安全；池连接的豁免
                # 只给「请求头还没完整发出」的连接级失败——请求已完整送达、只是
                # 响应没回来时重发非幂等方法，上游副作用会执行两次。
                can_retry = (method in IDEMPOTENT and body_len == 0
                             and not req_chunked)
                if from_pool and not getattr(e, "req_fully_sent", True):
                    can_retry = True
                if can_retry:
                    continue                  # 池里的死连接 / 幂等无体请求 → 换条再来
                break

            if reuse_up:
                if peer:
                    pool_put(host, peer[0], peer[1], sock, nreq + 1)
                else:
                    close_quietly(sock)
            log("%s %s%s" % (method, host, path[:60]))
            done = True
            # 这次**真的把请求跑通了**（而不只是握手成功）→ 记住这条模式，
            # 下次优先用它。见 MODE_GOOD 的注释：只按握手选模式会被 GFW 反复骗。
            if peer:
                MODE_GOOD[host] = peer[1]
            if (not reuse_up) or client_wants_close:
                return                        # 已经跟浏览器说了 close，收工
            break

        if not done:
            log("  上游失败 %s: %s" % (host, last_err), warn=True)
            send_to_client(client.sock, b"HTTP/1.1 502 Bad Gateway\r\n"
                                        b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return


# ================================================================ 启动

def build_server_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    try:
        ctx.set_alpn_protocols(["http/1.1"])       # 只做 HTTP/1.1，简单可控
    except Exception:
        pass
    return ctx


def _write_pid():
    """把当前进程号落到 gh-proxy.pid —— 无论由谁拉起（deploy / 计划任务 / 手动）。
    没有它，「开机自启」路径启动的实例对 status_gui 和卸载脚本就是隐形的：
    进程灯误报「未运行」、按 pid 清场也找不到人。写失败不影响运行。"""
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def _clear_pid():
    """只清「属于自己」的 pid 文件：若期间有新实例把它改写，别动人家的。"""
    try:
        with open(PID_FILE, "r") as f:
            if f.read().strip() == str(os.getpid()):
                os.remove(PID_FILE)
    except Exception:
        pass


def main():
    global SERVER_CTX, VERBOSE

    ap = argparse.ArgumentParser(description="本机 GitHub 专用 HTTPS 反代")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("-q", "--quiet", action="store_true", help="只报错")
    ap.add_argument("--no-verify-upstream", action="store_true",
                    help="危险：跳过上游证书链验证（仅限排障临时用，勿常开）")
    ap.add_argument("--no-warm", action="store_true",
                    help="关闭连接池保温（默认开；关掉后每次冷启动都要重吃握手学费）")
    args = ap.parse_args()
    global CLIENT_CTX_SNI, CLIENT_CTX_NOSNI, CLIENT_CTX
    VERBOSE = not args.quiet

    if args.no_verify_upstream:
        CLIENT_CTX_SNI = build_client_ctx(True, verify_chain=False)
        CLIENT_CTX_NOSNI = build_client_ctx(False, verify_chain=False)
        CLIENT_CTX = CLIENT_CTX_SNI

    for f in (CERT_FILE, KEY_FILE):
        if not os.path.exists(f):
            print("[x] 缺少证书文件: %s" % f)
            sys.exit(1)

    SERVER_CTX = build_server_ctx()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows 的 SO_REUSEADDR 允许第二个 socket 绑定同一端口（连接交付不定）——
    # 既给本机进程留了劫持面（安全审计 F4），也让误双开变成玄学故障。
    # 独占绑定才是本机服务的正确语义；非 Windows 平台没有这个选项。
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    except (AttributeError, OSError):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        print("[x] 绑定 %s:%d 被拒绝 —— 请以管理员身份运行" % (args.host, args.port))
        sys.exit(1)
    except OSError as e:
        print("[x] 绑定失败: %s" % e)
        sys.exit(1)

    srv.listen(128)
    _write_pid()
    _crl_srv = start_crl_server()
    if not args.no_warm:
        start_warmer()
    print("=" * 62)
    print("  GitHub 无SNI反代 v2 已启动")
    print("  监听: %s:%d   证书: %s" % (args.host, args.port, os.path.basename(CERT_FILE)))
    print("  流式搬运 · 上游连接池 · 只服务 GitHub 域名")
    if _crl_srv:
        print("  CRL : http://127.0.0.1:%d/ca.crl（供 schannel 做吊销检查）"
              % _crl_port())
    else:
        print("  CRL : 未启动 ⚠ schannel 工具（curl）会报 CRYPT_E_NO_REVOCATION_CHECK")
    print("  池保温: %s（%d 个热门域，%ds 一轮）"
          % ("关" if args.no_warm else "开", len(WARM_HOSTS), WARM_INTERVAL))
    print("  上游验证: %s" % ("已关闭(--no-verify-upstream) ⚠" if args.no_verify_upstream
                            else "系统根证书（链 + SNI 主机名）"))
    print("  Ctrl+C 停止")
    print("=" * 62)

    try:
        while True:
            try:
                conn, addr = srv.accept()
            except OSError as e:
                # 客户端在 connect 与 accept 之间 RST 时，Windows 的 accept 会抛
                # ConnectionResetError/ConnectionAbortedError —— 浏览器预连接的
                # 常态噪声（审计 S3：原先直接穿出循环、整个进程带栈退出）。
                # 但监听套接字本身失效（已关闭）必须退出，否则 100% CPU 自旋。
                if srv.fileno() == -1:
                    break
                log("  accept 失败，忽略并继续: %s" % str(e)[:60], warn=True)
                time.sleep(0.05)
                continue
            try:
                threading.Thread(target=handle, args=(conn, addr),
                                 daemon=True).start()
            except Exception as e:
                # 线程资源耗尽等派生失败：连接必须有人关，进程继续活着
                close_quietly(conn)
                log("  线程派生失败，连接已关闭: %s" % str(e)[:60], warn=True)
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.close()
        _clear_pid()


if __name__ == "__main__":
    main()
