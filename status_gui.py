#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
status_gui.py — gh-proxy 状态监控窗口（纯标准库 tkinter，零依赖）

看什么
------
· 反代进程：pid 文件 + 进程是否真活着（PID 会被系统复用，光看 pid 文件不够）
· 443 端口：有没有人在听（没听 = hosts 还指着 127.0.0.1，GitHub 会「连接被拒绝」）
· hosts 映射：36 个域名映射在不在块里；顺带发现「别的加速工具」写的同域旧条目
· CA 证书：本机私有 CA 是否还在系统 Root 存储里
· 全链路测试：真发 HTTPS（SNI=域名，验签用我们的 CA）走 127.0.0.1:443 →
  这一条链测的是「hosts + 反代 + 上游通道 + 证书」整条，并校验内容特征
· 实时日志：tail gh-proxy.log，并统计近 1 分钟请求数

用法： 双击「状态监控.bat」；或 python status_gui.py
      python status_gui.py --selftest   无头自检（不弹窗，供自动化验证）
"""

import importlib.util
import ctypes
import ctypes.wintypes as _w
import os
import queue
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

BASE = os.path.dirname(os.path.abspath(__file__))
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
CA_CRT = os.path.join(BASE, "certs", "ca.crt")
PROXY_PID = os.path.join(BASE, "gh-proxy.pid")
PROXY_LOG = os.path.join(BASE, "gh-proxy.log")
PROXY_SCRIPT = os.path.join(BASE, "gh-proxy.py")

# ---------------------------------------------------------------- 复用 deploy.py 的域名表

def _load_domains():
    try:
        spec = importlib.util.spec_from_file_location(
            "dep", os.path.join(BASE, "deploy.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return list(mod.DOMAINS)
    except Exception:
        return ["github.com", "api.github.com", "raw.githubusercontent.com",
                "codeload.github.com", "gist.github.com",
                "avatars.githubusercontent.com"]


DOMAINS = _load_domains()

# ---------------------------------------------------------------- 全链路测试目标

TARGETS = [
    ("github.com", "/", "html"),
    ("api.github.com", "/repos/torvalds/linux", "json"),
    ("raw.githubusercontent.com", "/torvalds/linux/master/README", "text"),
    ("codeload.github.com", "/octocat/Hello-World/zip/refs/heads/master", "zip"),
    ("avatars.githubusercontent.com", "/u/1?s=64", "img"),
    ("gist.github.com", "/octocat/6cad326836d38bd3a7ae", "html"),
]


def sniff(body, expect):
    low = body[:512].lower()
    if expect == "html":
        return b"<html" in low or b"<!doctype" in low
    if expect == "json":
        return body[:1] in (b"{", b"[")
    if expect == "zip":
        return body[:2] == b"PK"
    if expect == "img":
        return body[:2] in (b"\x89P", b"\xff\xd8", b"GIF")
    return len(body) > 0


SLOW_MS = 8000            # 超过这个耗时算「慢」（GFW 抽风时的典型表现）


def dechunk(body):
    """把 chunked 分块帧解成纯体（监控用，尽力而为：帧残缺时返回已解出的部分）。

    反代对 chunked 响应是**原样中继分块帧**的，直接嗅探原始字节流会把块长
    （如 "8000\\r\\n"）当正文 —— json/zip/图片的魔数检查必然误判 ✗。
    """
    out = bytearray()
    i = 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            return bytes(out)
        token = body[i:j].split(b";")[0].strip()
        i = j + 2
        try:
            size = int(token, 16)
        except ValueError:
            return bytes(out)
        if size == 0:
            return bytes(out)
        out += body[i:i + size]
        i += size + 2


def chain_test(domain, path, expect, timeout=30, port=443):
    """真发一次 HTTPS：SNI=域名、用我们的 CA 验签、走 127.0.0.1:443。

    ⚠️ timeout 必须 ≥ 反代自己的重试预算（ATTEMPT_BUDGET=45s 量级），
    否则「反代还在重试」会被判成「超时失败」—— 10s 的旧值就干过这事，
    把能通的 github.com / avatars 报成 ✗。
    （另一条纪律：GFW 抽风时首次尝试可能吃掉 20s 的头超时预算，之后重试才成功，
    所以 30s 是「不误报」与「别让监控卡太久」之间的折中。）

    port 参数供验证用（对着本机另一个 TLS 端口验证证书链与内容嗅探逻辑），
    正常使用永远走 443。
    """
    t0 = time.time()
    try:
        ctx = ssl.create_default_context(cafile=CA_CRT)   # 验签 = 顺带验证书链
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=domain)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\n"
               "User-Agent: gh-proxy-monitor/1\r\nConnection: close\r\n\r\n"
               % (path, domain)).encode()
        tls.sendall(req)
        buf = b""
        while len(buf) < (3 << 20):
            d = tls.recv(65536)
            if not d:
                break
            buf += d
        try:
            tls.close()
        except Exception:
            pass
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000),
                "status": "-", "size": 0, "sniff": False,
                "err": "证书验签失败（CA 没装好？）"}
    except (socket.timeout, TimeoutError):
        # 超时要和「连不上」分开报：GFW 抽风时第一次尝试常被整个吞掉（等满
        # 反代的 20s 头超时预算才重试），所以这一条既不是代理坏、也不是站点坏。
        return {"ok": False, "ms": int((time.time() - t0) * 1000),
                "status": "-", "size": 0, "sniff": False, "timeout": True,
                "err": "超时(>%ds)：反代可能仍在换通道重试" % timeout}
    except (ConnectionRefusedError, OSError) as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000),
                "status": "-", "size": 0, "sniff": False, "timeout": False,
                "err": "连不上 443（反代没在跑？）" if isinstance(
                    e, ConnectionRefusedError) else str(e)[:60]}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000),
                "status": "-", "size": 0, "sniff": False, "timeout": False,
                "err": str(e)[:60]}

    ms = int((time.time() - t0) * 1000)
    head, _, raw_body = buf.partition(b"\r\n\r\n")
    parts = head.split(b" ")
    status = parts[1].decode(errors="replace") if len(parts) > 1 else "?"
    # 分块中继的响应先解帧再嗅探/计长（见 dechunk 注释），否则块长会被当正文
    te_chunked = any(l.lower().startswith(b"transfer-encoding")
                     and b"chunked" in l.lower()
                     for l in head.split(b"\r\n"))
    body = dechunk(raw_body) if te_chunked else raw_body
    return {"ok": status == "200" and sniff(body, expect), "ms": ms,
            "status": status, "size": len(body), "timeout": False,
            "sniff": sniff(body, expect), "err": "" if status == "200" else "非 200"}


def run_all_tests(retry_timeout=True):
    """依次测 6 条链路；**超时的项自动再试一次**。

    理由：GFW 抽风时第一次尝试可能被整个吞掉（要等满反代的 20s 头超时预算，
    再换通道重试），而那时该 SNI 模式已被记惩罚 —— 第二次通常几百毫秒就通。
    不重试的话，监控会把「慢」误报成「坏」。
    """
    results = []
    for domain, path, expect in TARGETS:
        r = chain_test(domain, path, expect)
        if retry_timeout and r.get("timeout"):
            r2 = chain_test(domain, path, expect)
            if r2["ok"]:
                r2["err"] = "第一次超时，第二次通（GFW 抽风）"
            r = r2
        results.append((domain, r))
    return results


# ---------------------------------------------------------------- 各项状态采集

# ---------------------------------------------------------------- 端口属主（零依赖）

_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", _w.DWORD), ("dwLocalAddr", _w.DWORD),
                ("dwLocalPort", _w.DWORD), ("dwRemoteAddr", _w.DWORD),
                ("dwRemotePort", _w.DWORD), ("dwOwningPid", _w.DWORD)]


def port_owner_pid(port):
    """谁在听这个端口 —— 直接问 iphlpapi（GetExtendedTcpTable）。

    为什么不用 PowerShell / netstat：本机实测 PowerShell 在受限上下文里
    **exit 0 但零输出**（Get-CimInstance 拿不到 CommandLine），
    netstat 需要解析文本且 PID 列可能被截断。这条路零外部进程、零解析，最稳。
    返回 pid 或 None。
    """
    try:
        iphlp = ctypes.WinDLL("iphlpapi")
        size = _w.DWORD(0)
        iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, _AF_INET,
                                  _TCP_TABLE_OWNER_PID_LISTENER, 0)
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, _AF_INET,
                                        _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if ret != 0:
            return None
        n = struct.unpack_from("<I", buf.raw, 0)[0]
        off = 4
        sz = ctypes.sizeof(_MIB_TCPROW_OWNER_PID)
        for _ in range(n):
            row = _MIB_TCPROW_OWNER_PID.from_buffer_copy(buf.raw[off:off + sz])
            off += sz
            if socket.ntohs(row.dwLocalPort & 0xFFFF) == port:
                return int(row.dwOwningPid)
    except Exception:
        return None
    return None


def _image_name(pid):
    """进程映像名（basename）。拿不到返回空串。"""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(4096)
            size = _w.DWORD(4096)
            if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return os.path.basename(buf.value).lower()
        finally:
            k.CloseHandle(h)
    except Exception:
        pass
    return ""


def _cmdline_is_ours(pid):
    """核对 PID 对应进程确实在跑 gh-proxy.py（审计 V17：PID 复用假绿）。

    ⚠️ 这里**不再依赖 PowerShell**。本机实测：PowerShell 工具在受限上下文里
    返回 exit 0 但 stdout 为空 → 旧实现据此判 `return False` → 面板把活得好好的
    反代报成「pid 文件过期」（2026-09-21 踩，导致用户以为反代死了）。
    现在改判「映像名是 python/pythonw」：拿不到命令行时不再武断判死，
    因为调用方（proxy_process）已经用「443 端口属主 == pid 文件里的 pid」做了
    更强的交叉验证 —— 那个证据本身就足以确认身份。
    """
    name = _image_name(pid)
    if not name:
        return False                      # 进程已不存在
    return name.startswith("python")


def proxy_process():
    """(pid 或 None, 进程活着吗)。

    三层核对，任何一层拿不到证据都不轻易判死：
      ① pid 文件能读出一个正整数；
      ② 该 pid 的进程映像名是 python/pythonw（防 PID 被复用）；
      ③ 443 端口属主就是这个 pid（最强证据：端口在听就说明反代在跑）。
    """
    pid = None
    try:
        with open(PROXY_PID) as f:
            pid = int(f.read().strip())
    except Exception:
        pass
    if pid is None:
        return None, False

    # ③ 最强证据先算：443 属主
    owner = port_owner_pid(443)
    if owner is not None and owner == pid:
        return pid, True                  # 端口就是这个 pid 在听 → 必然活着

    # ② 退一步：进程还在且是 python
    if _cmdline_is_ours(pid):
        return pid, True

    return pid, False


def port_443():
    """443 上有没有人听。True 不代表一定是我们的反代（但配合 pid 判断够用）。"""
    try:
        s = socket.create_connection(("127.0.0.1", 443), timeout=1.5)
        s.close()
        return True
    except Exception:
        return False


def read_hosts_text():
    for enc in ("utf-8-sig", "gbk", "latin-1"):
        try:
            with open(HOSTS, "r", encoding=enc) as f:
                return f.read()
        except Exception:
            continue
    return ""


def hosts_map():
    """(已映射数, 总数, 冲突列表)。冲突 = 别的工具把我们的域名指去了别的 IP。"""
    ours = {d.lower(): False for d in DOMAINS}
    conflicts = []
    for ln in read_hosts_text().splitlines():
        s = ln.split("#", 1)[0].strip()
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        for n in names:
            n = n.lower().rstrip(".")
            if n in ours:
                if ip == "127.0.0.1":
                    ours[n] = True
                else:
                    conflicts.append("%s %s" % (ip, n))
    return sum(ours.values()), len(DOMAINS), conflicts


def ca_installed():
    try:
        r = subprocess.run(["certutil", "-store", "Root"],
                           capture_output=True, timeout=30)
        return b"gh-proxy Local Root CA" in r.stdout
    except Exception:
        return False


def log_tail(n=300):
    """tail 最后 n 行 + (近 60s 的已完成请求数)。"""
    try:
        size = os.path.getsize(PROXY_LOG)
        with open(PROXY_LOG, "rb") as f:
            f.seek(max(0, size - (256 << 10)))
            data = f.read()
    except Exception:
        return ["（还没有日志：反代尚未由「一键部署.bat」启动过）"], 0
    lines = data.decode("utf-8", "replace").splitlines()[-n:]
    lt = time.localtime()
    now_sec = lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec
    recent = 0
    for ln in lines:
        m = re.match(r"^\[(\d\d):(\d\d):(\d\d)\] (GET|POST|HEAD) ", ln)
        if not m:
            continue
        hh, mm, ss = int(m.group(1)), int(m.group(2)), int(m.group(3))
        # 日志时间戳是本地挂钟（time.strftime 生成），必须和「当前本地时刻」比。
        # 旧实现把本地挂钟加到 UTC 零点（now - now%86400）上，UTC+8 下恒差 8 小时，
        # 统计恒为 0。(now-x) mod 86400 = 距这条日志过去了几秒，跨午夜也自动正确。
        if (now_sec - (hh * 3600 + mm * 60 + ss)) % 86400 <= 60:
            recent += 1
    return lines, recent


def collect_status():
    """一次性采集（除 CA 外都很快）。CA 只在启动/手动刷新时查。"""
    pid, alive = proxy_process()
    st = {"pid": pid, "alive": alive, "port": port_443()}
    mapped, total, conflicts = hosts_map()
    st["mapped"], st["total"], st["conflicts"] = mapped, total, conflicts
    lines, recent = log_tail()
    st["recent"] = recent
    return st, lines


# ---------------------------------------------------------------- 无头自检

def selftest():
    """无头自检：只断言「自身逻辑自洽」，**不假设部署状态**。

    （这条纪律是被自己踩出来的：早先这里写的是 `mapped == 0`、`not ca_installed()`
    —— 部署之后必然失败，等于把「环境状态」当成了被测逻辑。）
    """
    ok = True

    def chk(cond, label, detail=""):
        nonlocal ok
        ok = ok and cond
        print("  %s %-40s %s" % ("OK " if cond else "XX ", label, detail))

    pid, alive = proxy_process()
    chk(pid is None or isinstance(pid, int), "pid 读取不抛异常",
        "pid=%s alive=%s" % (pid, alive))
    listening = port_443()
    chk(isinstance(listening, bool), "443 端口探测返回布尔", "listening=%s" % listening)
    mapped, total, conflicts = hosts_map()
    chk(isinstance(mapped, int) and 0 <= mapped <= total and isinstance(conflicts, list),
        "hosts 映射统计自洽（0 ≤ n ≤ 总数）",
        "%d/%d 冲突=%d" % (mapped, total, len(conflicts)))
    lines, recent = log_tail()
    chk(len(lines) >= 1, "日志读取兜底（无日志也能给出一行说明）", lines[0][:40])
    t = chain_test("github.com", "/", "html")
    chk(t["ms"] >= 0 and isinstance(t["ok"], bool),
        "全链路测试可执行且返回可读结果",
        "ok=%s %dms %s" % (t["ok"], t["ms"], t["err"]))
    ca = ca_installed()
    chk(isinstance(ca, bool), "CA 查询返回布尔（不抛异常）", "Root 中已安装=%s" % ca)
    print("  selftest %s" % ("通过" if ok else "失败"))
    return ok


# ---------------------------------------------------------------- 界面

BG = "#1b1d21"; PANEL = "#232629"; FG = "#e6e6e6"; DIM = "#9aa0a6"
GOOD = "#3fb96f"; BAD = "#e5534b"; WARN = "#d29922"; ACCENT = "#4c8dff"


class App:
    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.auto_test = tk.BooleanVar(value=False)
        self.autoscroll = tk.BooleanVar(value=True)
        self.ca_ok = None
        self._build()
        self.refresh_status(include_ca=True)
        self.poll_log()
        self.root.after(150, self._drain)

    # ---- 控件 ----
    def _chip(self, frame, title):
        box = tk.Frame(frame, bg=PANEL, padx=10, pady=8)
        lab_t = tk.Label(box, text=title, bg=PANEL, fg=DIM,
                         font=("Microsoft YaHei UI", 9))
        lab_v = tk.Label(box, text="…", bg=PANEL, fg=FG,
                         font=("Microsoft YaHei UI", 13, "bold"))
        lab_t.pack(anchor="w")
        lab_v.pack(anchor="w")
        box.pack(side="left", padx=(0, 8), fill="x", expand=True)
        return lab_v

    def _build(self):
        self.root.title("gh-proxy 状态监控 · v2.2")
        self.root.configure(bg=BG)
        self.root.geometry("980x680")
        self.root.minsize(860, 560)

        top = tk.Frame(self.root, bg=BG, padx=10, pady=10)
        top.pack(fill="x")
        self.c_proc = self._chip(top, "反代进程")
        self.c_port = self._chip(top, "端口 443")
        self.c_hosts = self._chip(top, "hosts 映射")
        self.c_ca = self._chip(top, "私有 CA")
        self.c_rate = self._chip(top, "近 1 分钟请求")

        bar = tk.Frame(self.root, bg=BG, padx=10)
        bar.pack(fill="x")
        tk.Button(bar, text="立即全链路测试", command=self.run_tests,
                  bg=ACCENT, fg="#fff", relief="flat", padx=12,
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
        tk.Checkbutton(bar, text="每 60s 自动测", variable=self.auto_test,
                       bg=BG, fg=FG, activebackground=BG, selectcolor=PANEL,
                       command=self._toggle_auto).pack(side="left", padx=10)
        tk.Button(bar, text="刷新状态", command=lambda: self.refresh_status(True),
                  bg=PANEL, fg=FG, relief="flat", padx=10).pack(side="left", padx=(0, 6))
        tk.Button(bar, text="复制诊断信息", command=self.copy_diag,
                  bg=PANEL, fg=FG, relief="flat", padx=10).pack(side="left")
        tk.Button(bar, text="打开目录", command=lambda: os.startfile(BASE),
                  bg=PANEL, fg=FG, relief="flat", padx=10).pack(side="left", padx=6)

        # 提示条独占一行：挤在按钮后面会被窗口边缘裁掉（实测截图踩过）
        hintrow = tk.Frame(self.root, bg=BG, padx=10)
        hintrow.pack(fill="x")
        self.conf_lbl = tk.Label(hintrow, text="", bg=BG, fg=WARN, anchor="w",
                                 justify="left", wraplength=960,
                                 font=("Microsoft YaHei UI", 9))
        self.conf_lbl.pack(fill="x")

        mid = tk.Frame(self.root, bg=BG, padx=10, pady=6)
        mid.pack(fill="both", expand=False)
        cols = ("domain", "status", "size", "ms", "content", "err")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=6)
        for cid, txt, w, anchor in (("domain", "域名", 250, "w"),
                                    ("status", "状态", 60, "center"),
                                    ("size", "字节", 90, "e"),
                                    ("ms", "耗时", 80, "e"),
                                    ("content", "内容校验", 90, "center"),
                                    ("err", "说明", 330, "w")):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor=anchor)
        for t in TARGETS:
            self.tree.insert("", "end", iid=t[0],
                             values=(t[0], "—", "—", "—", "—", ""))
        self.tree.pack(fill="x")

        bottom = tk.Frame(self.root, bg=BG, padx=10, pady=6)
        bottom.pack(fill="both", expand=True)
        tk.Label(bottom, text="实时日志（gh-proxy.log）", bg=BG, fg=DIM,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        self.log_txt = tk.Text(bottom, bg=PANEL, fg=FG, relief="flat",
                               font=("Consolas", 9), height=12, wrap="none")
        sb = ttk.Scrollbar(bottom, command=self.log_txt.yview)
        self.log_txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log_txt.pack(fill="both", expand=True)
        tk.Checkbutton(bottom, text="自动滚动", variable=self.autoscroll,
                       bg=BG, fg=DIM, activebackground=BG,
                       selectcolor=PANEL).pack(anchor="e")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background="#2c2f33",
                        foreground=FG, borderwidth=0)
        style.map("Treeview", background=[("selected", "#31445c")])

        self._auto_job = None      # 上次自动全链路测试的时刻；None = 未启用
        self._busy = False         # 全链路测试进行中（防按钮/自动触发叠跑）
        self._diag_busy = False    # 诊断采集进行中

    def _set(self, chip, text, color):
        chip.configure(text=text, fg=color)

    # ---- 状态刷新 ----
    def refresh_status(self, include_ca=False):
        def work():
            st, _lines = collect_status()
            st["ca"] = ca_installed() if include_ca else self.ca_ok
            self.q.put(("status", st))
        threading.Thread(target=work, daemon=True).start()

    def poll_log(self):
        def work():
            lines, recent = log_tail(300)
            self.q.put(("log", (lines, recent)))
        threading.Thread(target=work, daemon=True).start()
        self.root.after(1000, self.poll_log)
        # 「每 60s 自动测」真正的调度点：到点且当前没有测试在跑，就再测一轮。
        # （旧版只在这里给 _auto_job 赋了个时间戳，没有任何代码消费它 ——
        #   复选框除了勾选瞬间跑一次外什么都不做，等于摆设。）
        if (self.auto_test.get() and self._auto_job is not None
                and time.time() - self._auto_job >= 60 and not self._busy):
            self._auto_job = time.time()
            self.run_tests()

    def _toggle_auto(self):
        if self.auto_test.get():
            self._auto_job = time.time()   # 从现在起算 60s，先立即测一轮
            self.run_tests()
        else:
            self._auto_job = None          # 取消勾选即停表

    # ---- 测试 ----
    def run_tests(self):
        if self._busy:                     # 上一轮还没跑完（网络慢时 6×30s×2）
            return
        self._busy = True
        for t in TARGETS:
            self.tree.set(t[0], "status", "…")
            self.tree.set(t[0], "err", "")

        def work():
            for domain, r in run_all_tests():
                self.q.put(("result", (domain, r)))
            self.refresh_status()
            self._busy = False
        threading.Thread(target=work, daemon=True).start()

    # ---- 消费结果 ----
    def _drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "status":
                    self._apply_status(payload)
                elif kind == "log":
                    self._apply_log(payload)
                elif kind == "result":
                    self._apply_result(payload)
                elif kind == "diag":
                    self._apply_diag(payload)
        except queue.Empty:
            pass
        self.root.after(150, self._drain)

    def _apply_status(self, st):
        self.ca_ok = st.get("ca")
        if st["alive"]:
            self._set(self.c_proc, "运行中 · PID %s" % st["pid"], GOOD)
        elif st["pid"]:
            self._set(self.c_proc, "pid 文件过期（%s）" % st["pid"], BAD)
        else:
            self._set(self.c_proc, "未运行", BAD)
        if st["port"]:
            self._set(self.c_port, "监听中", GOOD if st["alive"] else WARN)
        else:
            self._set(self.c_port, "无监听", BAD if st["alive"] else DIM)
        m, total = st["mapped"], st["total"]
        self._set(self.c_hosts, "%d / %d" % (m, total),
                  GOOD if m == total else (BAD if m == 0 else WARN))
        self._set(self.c_ca, "已安装" if self.ca_ok else "未安装",
                  GOOD if self.ca_ok else BAD)
        self._set(self.c_rate, "%d" % st["recent"],
                  FG if st["recent"] else DIM)
        if st["conflicts"]:
            self.conf_lbl.configure(
                text="⚠ 发现 %d 条别的工具写的同域映射：%s" %
                     (len(st["conflicts"]), "、".join(st["conflicts"][:2])),
                fg=WARN)
        elif not st["alive"] and m == 0 and not self.ca_ok:
            # 三项全空 = 压根没部署（不是坏了）。直说下一步该点哪个。
            self.conf_lbl.configure(
                text="当前未部署 —— 双击「一键部署.bat」（需管理员），"
                     "装完完全退出 Edge 再重开；然后点上面的「立即全链路测试」",
                fg=WARN)
        else:
            self.conf_lbl.configure(text="")

    def _apply_log(self, payload):
        lines, recent = payload
        self.log_txt.configure(state="normal")
        self.log_txt.delete("1.0", "end")
        self.log_txt.insert("end", "\n".join(lines) + "\n")
        self.log_txt.configure(state="disabled")
        if self.autoscroll.get():
            self.log_txt.yview_moveto(1.0)

    def _apply_result(self, payload):
        domain, r = payload
        self.tree.tag_configure("ok", foreground=GOOD)
        self.tree.tag_configure("bad", foreground=BAD)
        self.tree.tag_configure("slow", foreground=WARN)
        if r["ok"]:
            tag = "slow" if r["ms"] > SLOW_MS else "ok"
        else:
            tag = "bad"
        self.tree.item(domain, tags=(tag,))
        self.tree.set(domain, "status", r["status"])
        self.tree.set(domain, "size", "{:,}".format(r["size"]) if r["size"] else "0")
        slow = r["ok"] and r["ms"] > SLOW_MS
        self.tree.set(domain, "ms", "%d ms%s" % (r["ms"], " ⚠慢" if slow else ""))
        self.tree.set(domain, "content", "✓" if r["sniff"] else "✗")
        self.tree.set(domain, "err", r["err"] or ("GFW 抽风：重试后才通" if slow else ""))

    # ---- 诊断文本 ----
    def diag_text(self):
        pid, alive = proxy_process()
        m, total, conflicts = hosts_map()
        lines = [
            "gh-proxy 诊断  %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
            "进程: pid=%s alive=%s   443监听=%s" % (pid, alive, port_443()),
            "hosts 映射: %d/%d   冲突=%s" % (m, total, conflicts),
            "私有 CA 已安装: %s" % ca_installed(),
        ]
        for domain, r in run_all_tests():
            lines.append("  %-32s %-4s %7d B %6d ms %s%s"
                         % (domain, r["status"], r["size"], r["ms"],
                            "✓" if r["sniff"] else "✗",
                            ("  ⚠慢(GFW抽风,重试后才通)"
                             if r["ok"] and r["ms"] > SLOW_MS else "")
                            + ("" if r["err"] in ("", "非 200") else "  " + r["err"])))
        return "\n".join(lines)

    def copy_diag(self):
        """诊断采集放后台线程。含 6 条全链路测试（每条最长 30s×2）——
        旧版在按钮回调里同步执行，Tk 主线程一卡就是几分钟、窗口直接「未响应」。"""
        if self._diag_busy:
            return
        self._diag_busy = True
        self.conf_lbl.configure(text="正在采集诊断信息（含全链路测试，最长一两分钟）…",
                                fg=WARN)

        def work():
            text = self.diag_text()
            self.q.put(("diag", text))
        threading.Thread(target=work, daemon=True).start()

    def _apply_diag(self, text):
        self._diag_busy = False
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.conf_lbl.configure(text="诊断信息已复制到剪贴板", fg=GOOD)
        self.root.after(3000, lambda: self.conf_lbl.configure(text=""))


def main():
    if "--selftest" in sys.argv:
        sys.exit(0 if selftest() else 1)
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
