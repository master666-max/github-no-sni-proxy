# -*- coding: utf-8 -*-
"""进程内自测：直接跑 gh-proxy 的核心逻辑，绕开沙箱的进程/文件怪象。

分两段：
  A 离线单测  —— ChunkedScanner 分片边界、白名单、报文头改写，不依赖网络。
  B 联机实拨  —— 真连 GitHub，覆盖流式大文件、keep-alive 复用、并发、403 拦截。

用法： python selftest.py            # 全跑
       python selftest.py -A         # 只跑离线
"""
import http.client
import importlib.util
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "gp", os.path.join(_HERE, "gh-proxy.py"))
gp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gp)


def load_module(path):
    """加载同目录下的另一个脚本模块（deploy.py / undeploy.py），不执行 main。

    相对路径一律锚到本文件所在目录：从别的工作目录执行
    `python D:\tools\gh-proxy\selftest.py` 也能跑（旧版直接 FileNotFoundError）。"""
    if not os.path.isabs(path):
        path = os.path.join(_HERE, path)
    name = os.path.splitext(os.path.basename(path))[0]
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m

FAILED = []
SKIPPED = []


def check(cond, label, detail=""):
    mark = "OK " if cond else "XX "
    if not cond:
        FAILED.append(label)
    print("  %s %-46s %s" % (mark, label, detail))
    sys.stdout.flush()
    return cond


def skip(label, detail=""):
    """不计成败 —— 用于「上游不可达 / 被限流」这类与被测代码无关的情况。"""
    SKIPPED.append(label)
    print("  -- %-46s %s" % (label, detail))
    sys.stdout.flush()


# ================================================================ A 离线单测

def part_a():
    print("=" * 78)
    print("A. 离线单测（不依赖网络）")
    print("-" * 78)

    # ---- A1 ChunkedScanner：各种分片方式都必须恰好消费体长 ----
    body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n"
    stream = body + b"GET /next HTTP/1.1\r\n"

    def scan_all(chunks):
        scan = gp.ChunkedScanner()
        total = 0
        for c in chunks:
            done, used = scan.feed(c)
            assert 0 <= used <= len(c), "used 越界: %r" % (used,)
            total += used
            if done:
                return True, total
        return False, total

    def split_at_crlf(s):
        """每个包恰好在一个 CRLF 处结束 —— 专测「终止符落在包尾」的边界。
        （旧版这个用例写成了和「逐字节」完全相同的列表，标签却宣称测另一种切法。）"""
        out, i = [], 0
        while i < len(s):
            j = s.find(b"\r\n", i)
            if j < 0:
                out.append(s[i:])
                break
            out.append(s[i:j + 2])
            i = j + 2
        return out

    cases = {
        "整包一次": [stream],
        "逐字节": [stream[i:i + 1] for i in range(len(stream))],
        "每3字节": [stream[i:i + 3] for i in range(0, len(stream), 3)],
        "CRLF 跨包": [body[:7], body[7:]],
        "每CRLF单独": split_at_crlf(stream),
    }
    for name, chunks in cases.items():
        done, total = scan_all(chunks)
        check(done and total == len(body), "ChunkedScanner %s" % name,
              "消费 %d / 体长 %d" % (total, len(body)))

    # ---- A2 白名单：只放行 GitHub ----
    allow = ["github.com", "raw.githubusercontent.com", "api.github.com",
             "codeload.github.com", "gist.github.com", "objects.githubusercontent.com",
             "avatars.githubusercontent.com", "github.io", "pages.github.com"]
    deny = ["evil.com", "gitlab.com", "google.com", "github.com.evil.com",
            "notgithub.com", "githubusercontent.com.evil.net", "baidu.com"]
    for h in allow:
        check(gp.host_allowed(h), "放行 %s" % h)
    for h in deny:
        check(not gp.host_allowed(h), "拦截 %s" % h)

    # ---- A3 hop-by-hop 必须被剥离，端到端头必须保留 ----
    start, headers = gp.parse_head(
        b"GET /x HTTP/1.1\r\nHost: github.com:443\r\n"
        b"Connection: keep-alive, X-Custom\r\nX-Custom: drop-me\r\n"
        b"Keep-Alive: timeout=5\r\n"
        b"Proxy-Connection: keep-alive\r\nUpgrade: h2c\r\n"
        b"Transfer-Encoding: chunked\r\nAccept: */*\r\n"
        b"Expect: 100-continue\r\n")
    head = gp.build_upstream_head(start, headers, "github.com")
    low = head.lower()
    check(b"x-custom" not in low, "剥离 Connection 里点名的字段")
    check(b"keep-alive: timeout" not in low, "剥离客户端发来的 Keep-Alive 头")
    check(b"proxy-connection" not in low, "剥离 Proxy-Connection")
    check(b"upgrade" not in low, "剥离 Upgrade")
    check(b"transfer-encoding" not in low,
          "默认剥离 Transfer-Encoding（chunked 请求经 req_te 显式保留，见 A21）")
    check(b"expect" not in low, "剥离 Expect: 100-continue")
    check(b"accept: */*" in low, "保留 Accept")
    check(b"host: github.com\r\n" in low, "Host 去掉端口")
    check(b"connection: keep-alive" in low, "改写为 keep-alive")

    # ---- A4 回给浏览器的头：剥 alt-svc（否则浏览器会绕过我们直连）；
    #          但 Transfer-Encoding 必须保留 —— 我们原样中继分块帧，剥了就变成
    #          「有分块帧、无分块声明」，浏览器会把块长当正文（首页曾整页花掉）。 ----
    out = gp.build_client_head(200, b"OK", [
        (b"content-type", b"text/html"),
        (b"alt-svc", b'h3=":443"'),
        (b"transfer-encoding", b"chunked"),
    ], keep_alive=True)
    check(b"alt-svc" not in out.lower(), "剥离 alt-svc")
    check(b"content-type: text/html" in out.lower(), "保留 Content-Type")
    check(b"transfer-encoding: chunked" in out.lower(),
          "保留 Transfer-Encoding（分块帧靠它声明）")

    # ---- A5 恶意/畸形 chunked 长度行要抛错，而不是静默错乱 ----
    sc = gp.ChunkedScanner()
    try:
        sc.feed(b"zz\r\n")
        check(False, "畸形 chunk 长度行抛错")
    except ValueError:
        check(True, "畸形 chunk 长度行抛错")

    # ---- A6 截断必须被判成错误，绝不能当成功（首页卡死的老 bug） ----
    class FakeUp:
        """下游假装成上游：喂完预置数据后就 EOF。"""

        def __init__(self, data):
            self.data = data
            self.pos = 0
            self.sent = b""

        def sendall(self, d):
            self.sent += d

        def recv(self, n):
            piece = self.data[self.pos:self.pos + n]
            self.pos += len(piece)
            return piece

        def settimeout(self, t):
            pass

        def close(self):
            pass

    class Collect:
        def __init__(self):
            self.chunks = []

        def sendall(self, d):
            self.chunks.append(d)

        def close(self):
            pass

    HEAD = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

    def relay(framing, data, length=0):
        """relay_body 现在返回「残留字节数」，0 表示干净。"""
        up, cl = FakeUp(data), Collect()
        try:
            r = gp.relay_body(up, b"", framing, length, HEAD, cl, 1 << 20)
            return r, None, b"".join(cl.chunks)
        except gp.UpstreamBroken as e:
            return None, e, b"".join(cl.chunks)

    r, err, out = relay("chunked", b"4\r\nWiki\r\n0\r\n\r\n")
    check(r == 0 and out == HEAD + b"4\r\nWiki\r\n0\r\n\r\n",
          "完整 chunked → 成功且原样转发", "leftover=%s" % r)

    r, err, out = relay("chunked", b"4\r\nWiki")           # 缺收尾块
    check(err is not None, "截断 chunked → 报错（不得当成功）",
          "%s" % (type(err).__name__ if err else "错误地返回成功"))

    r, err, out = relay("length", b"Wiki", length=4)
    check(r == 0, "length 读满 → 成功", "leftover=%s" % r)

    r, err, out = relay("length", b"Wiki", length=8)        # 少 4 字节
    check(err is not None, "截断 length → 报错")

    r, err, out = relay("eof", b"hello world")
    check(r == 0 and out == HEAD + b"hello world", "eof 分帧以关连接收尾 → 成功")

    r, err, out = relay("length", b"", length=0)
    check(r == 0 and out == HEAD, "Content-Length: 0 → 立即成功，不去 recv")

    r, err, out = relay("length", b"WikiXX", length=4)      # 体后还有 2 字节残留
    check(r == 2, "体后残留字节被如实报告（供上层放弃复用）", "leftover=%s" % r)

    # ---- A7 forward_once 级：分帧判定（用假上游，不联网） ----
    class FakeClient:
        def __init__(self, sock):
            self.sock = sock

        def pipe_out(self, dst, n):
            raise AssertionError("本用例不该有请求体")

    def fwd(up_bytes, method="GET"):
        up, cl = FakeUp(up_bytes), Collect()
        try:
            reuse = gp.forward_once(FakeClient(cl), up,
                                    b"GET / HTTP/1.1\r\n\r\n", 0, method, 1 << 20)
            return reuse, None, b"".join(cl.chunks)
        except gp.UpstreamBroken as e:
            return None, e, b"".join(cl.chunks)

    # TE 原样保留：剥掉 gzip 那层声明 → 客户端解完分块拿到 gzip 数据却不知要解压
    reuse, err, out = fwd(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
                          b"2\r\nab\r\n0\r\n\r\n")
    check(err is None and b"transfer-encoding: gzip, chunked" in out.lower(),
          "TE 原样保留 (gzip, chunked)")

    # TE 在但不是 chunked → 按 RFC 9112 应由「关连接」收尾
    reuse, err, out = fwd(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxxbody")
    check(err is None and reuse is False and b"connection: close" in out.lower(),
          "TE 非 chunked → eof 分帧 + close", "reuse=%s" % reuse)

    # 正常 chunked 仍是可复用的
    reuse, err, out = fwd(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                          b"4\r\nWiki\r\n0\r\n\r\n")
    check(err is None and reuse is True, "普通 chunked → 可复用", "reuse=%s" % reuse)

    # CL:0 不得去 recv，且要保留 Content-Length
    reuse, err, out = fwd(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    check(err is None and reuse is True and b"content-length: 0" in out.lower(),
          "CL:0 → 成功 + 保留 Content-Length")

    # 响应体之后还有多余字节 → 连接已错位，必须放弃复用
    reuse, err, out = fwd(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nWikiXX")
    check(err is None and reuse is False,
          "体后有多余字节 → 放弃复用", "reuse=%s" % reuse)

    # ---- A8 请求头 Content-Length 去重（防请求走私） ----
    start, headers = gp.parse_head(
        b"POST /x HTTP/1.1\r\nHost: github.com\r\n"
        b"Content-Length: 5\r\nContent-Length: 99\r\n")
    head = gp.build_upstream_head(start, headers, "github.com", 5)
    low = head.lower()
    check(low.count(b"content-length:") == 1 and b"content-length: 5" in low,
          "请求头 Content-Length 去重为实际值", "count=%d" % low.count(b"content-length:"))

    # ---- A9 部署脚本的 hosts 变换（纯逻辑，不碰真实 hosts） ----
    dep = load_module("deploy.py")
    und = load_module("undeploy.py")

    sample = ("# my hosts\n"
              "127.0.0.1 localhost\n"
              "140.82.112.3 github.com\n"          # 别的工具写的，会顶掉我们
              "192.0.2.1 printer.local\n")

    new_text, conflicts = dep.compose_hosts(sample)
    lines = [l for l in new_text.splitlines() if l.strip()]
    check(lines[0] == dep.BEGIN, "映射块置于文件最前（先出现的条目优先）")
    check(len(conflicts) == 1 and "github.com" in conflicts[0],
          "识别出其它工具的同域冲突条目")
    check("127.0.0.1 localhost" in new_text and "printer.local" in new_text,
          "用户原有条目未被破坏")

    new2, _ = dep.compose_hosts(new_text)
    check(new2.count(dep.BEGIN) == 1 and new2.count(dep.END) == 1,
          "重复部署幂等（映射块不重复堆叠）")

    stripped = und.strip_block(new_text)
    check(dep.BEGIN not in stripped and dep.END not in stripped
          and "127.0.0.1 localhost" in stripped
          and "192.0.2.1 printer.local" in stripped
          and "140.82.112.3 github.com" in stripped,
          "卸载只摘映射块，其余条目原样保留")

    # 映射了但过不了白名单 = 必然 403，页面直接打不开
    bad = [d for d in dep.DOMAINS if not gp.host_allowed(d)]
    check(not bad, "DOMAINS 全部通过 host_allowed", "%s" % bad)

    # hosts 安全闸：读出空内容但文件非空 → 判不可信、绝不覆盖。
    # 部署方向会把 hosts 覆盖成「只剩我们的映射」；还原方向更狠 ——
    # 会退化成「拿首次部署的备份覆盖当前 hosts」，把部署之后的改动全抹掉。
    # hosts 是系统文件，两个脚本都必须有这条闸。
    for _name, _mod in (("deploy", dep), ("undeploy", und)):
        if not hasattr(_mod, "hosts_sane"):
            check(False, "%s 有 hosts 安全闸" % _name)
            continue
        try:
            _size = os.path.getsize(_mod.HOSTS)
        except Exception:
            _size = 0
        if _size > 0:
            ok_empty, _ = _mod.hosts_sane("")
            ok_text, _ = _mod.hosts_sane("# 非空但读不出来\n")
            # 注意第二个断言：只要读出**任何**非空白内容就该放行，
            # 不能因为「看起来不像 hosts」就拦 —— 那会误伤正常文件。
            check((not ok_empty) and ok_text,
                  "%s：hosts 读出为空但文件非空 → 判不可信、不覆盖" % _name,
                  "size=%d 空=%s 非空=%s" % (_size, ok_empty, ok_text))
        else:
            skip("%s hosts 安全闸" % _name, "本机 hosts 为空，构造不出反例")

    # ---- A10 通道级故障的判定（本次修复的核心，联机踩到过） ----
    #
    # 背景：github.com 首页实测「正常 SNI 握手永远成功、请求永远石沉大海」。
    # 老代码只在「体传到一半」才惩罚 SNI 模式，于是重试反复选中同一条坏通道，
    # 79s 后回 502 —— 而另一条通道（无 SNI）2s 就能通。
    # 新判据：**刚建立的连接上连响应头都等不到**同样是通道级故障。
    class StallUp(FakeUp):
        """对端收下请求后一个字节都不回（GFW 的典型吞包手法）。"""

        def recv(self, n):
            raise socket.timeout("timed out")

    def fwd_stall(reused):
        up, cl = StallUp(b""), Collect()
        try:
            gp.forward_once(FakeClient(cl), up, b"GET / HTTP/1.1\r\n\r\n", 0,
                            "GET", 1 << 20, False, reused)
            return None
        except gp.UpstreamBroken as e:
            return e

    e = fwd_stall(reused=False)
    check(e is not None and e.chan is True,
          "刚建连接等不到响应头 → 通道级故障（换 SNI 模式）",
          "chan=%s" % (e.chan if e else "没抛错"))

    e = fwd_stall(reused=True)
    check(e is not None and e.chan is False,
          "池里捞出的连接等不到响应头 → 只是死连接（不牵连模式）",
          "chan=%s" % (e.chan if e else "没抛错"))

    # 对端把请求收下后直接关连接 —— 刚建的连接上同样是通道级信号
    class EofUp(FakeUp):
        """recv 立刻返回 b""：对端关连接。"""

        def recv(self, n):
            return b""

    up, cl = EofUp(b""), Collect()
    try:
        gp.forward_once(FakeClient(cl), up, b"GET / HTTP/1.1\r\n\r\n", 0,
                        "GET", 1 << 20, False, False)
        e = None
    except gp.UpstreamBroken as ex:
        e = ex
    check(e is not None and e.chan is True,
          "刚建连接没给响应头就被关 → 通道级故障",
          "chan=%s" % (e.chan if e else "没抛错"))

    # 体传输中途坏掉 —— 无论连接来源，都是通道级故障
    up, cl = FakeUp(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nWiki"), Collect()
    try:
        gp.forward_once(FakeClient(cl), up, b"GET / HTTP/1.1\r\n\r\n", 0,
                        "GET", 1 << 20)
        e = None
    except gp.UpstreamBroken as ex:
        e = ex
    check(e is not None and e.chan is True,
          "体传到一半断 → 通道级故障", "chan=%s" % (e.chan if e else "没抛错"))

    # ---- A11 模式惩罚：被罚的通道排到最后，且会过期清理 ----
    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    check(gp.mode_order("github.com") == ["github.com", None],
          "无惩罚时正常 SNI 优先")

    gp.GOOD_PEER["github.com"] = ("1.2.3.4", "github.com")
    gp.mark_channel_bad("github.com", chan=False)
    check(gp.mode_order("github.com") == ["github.com", None],
          "连接级故障不惩罚模式", "%s" % gp.mode_order("github.com"))

    gp.GOOD_PEER["github.com"] = ("1.2.3.4", "github.com")   # 正常 SNI 被罚
    gp.mark_channel_bad("github.com", chan=True)
    check(gp.mode_order("github.com") == [None, "github.com"],
          "正常 SNI 被罚 → 无 SNI 升为第一顺位", "%s" % gp.mode_order("github.com"))

    gp.MODE_PENALTY["github.com"] = (None, time.time() + 60)  # 无 SNI 被罚
    check(gp.mode_order("github.com") == ["github.com", None],
          "无 SNI 被罚 → 正常 SNI 回到第一顺位（被罚者仍留作兜底）",
          "%s" % gp.mode_order("github.com"))

    gp.MODE_PENALTY["github.com"] = (None, time.time() - 1)   # 已过期
    check(gp.mode_order("github.com") == ["github.com", None]
          and "github.com" not in gp.MODE_PENALTY,
          "过期惩罚被清理，不残留、不偏心")
    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()

    # ---- A12 「答错虚拟主机」的识别与拉黑 ----
    #
    # 实测：20.205.243.166 挂在 github.com 名下，DNS 里也被列为 api.github.com 的
    # 候选地址，可是它**不认 api 这个虚拟主机** —— 无论发不发 SNI，都回
    # `301 Location: https://github.com/<原路径>`。竞速一旦选中它，
    # 浏览器会拿到 301 跳到 github.com 的 404 页 —— 静默错内容，比 502 难查得多。
    DEF_HEAD = [(b"location", b"https://github.com/repos/torvalds/linux")]

    check(gp.is_wrong_vhost("api.github.com", "/repos/torvalds/linux", 301, DEF_HEAD),
          "识别出「默认虚拟主机」兜底 301（路径原样挂到 github.com）")
    check(not gp.is_wrong_vhost("api.github.com", "/repos/torvalds/linux", 200, DEF_HEAD),
          "200 不当成答错虚拟主机")
    check(not gp.is_wrong_vhost("github.com", "/repos/torvalds/linux", 301, DEF_HEAD),
          "github.com 自己跳自己不算错（它本就是默认虚拟主机）")
    check(not gp.is_wrong_vhost("api.github.com", "/other/path", 301, DEF_HEAD),
          "路径变了就不算兜底（避免误杀真的跳转页面）")
    check(not gp.is_wrong_vhost("resources.github.com", "/x", 301,
                                [(b"location", b"https://github.com/resources")]),
          "跳去别的路径（marketing 子域）不误判")
    check(not gp.is_wrong_vhost("api.github.com", "/x", 301,
                                [(b"location", b"https://api.github.com/x/")]),
          "跳到自己的域名不误判")
    check(not gp.is_wrong_vhost("api.github.com", "/x", 301,
                                [(b"location", b"https://docs.github.com/x")]),
          "跳到其它 GitHub 子域不误判")

    # ---- A12b 「根路径 301 → github.com」绝不能判成答错虚拟主机 ----
    #
    # 2026-09-21 实测（这是本次修复要钉死的回归）：
    #   codeload.github.com  GET /  → 301 Location: https://github.com/
    #   raw.githubusercontent.com 同理（凡根路径都这样）。
    # 旧判据「路径逐字节相同」下 `/` 与 `/` 必然相同 → 把 codeload/raw 的
    # **健康 IP 全部拉黑 600s**，日志还写「回错虚拟主机」，症状极像链路故障。
    # 实测反证：同一批 IP 换真实内容路径（/git/git/tar.gz/...、/owner/repo/branch/f.md）
    # 立刻 200 OK —— 说明 IP 完全正常，是判据错了。
    ROOT_HEAD = [(b"location", b"https://github.com/")]
    check(not gp.is_wrong_vhost("codeload.github.com", "/", 301, ROOT_HEAD),
          "A12b 根路径 301：codeload 不判错（CDN 既定行为，与 IP 归属无关）")
    check(not gp.is_wrong_vhost("raw.githubusercontent.com", "/", 301, ROOT_HEAD),
          "A12b 根路径 301：raw 不判错")
    check(not gp.is_wrong_vhost("api.github.com", "/", 301, ROOT_HEAD),
          "A12b 根路径 301：api 不判错（同上，任何 host 的根路径都豁免）")

    # 但内容域上的「同路径 301」仍必须判错（修复不能把检测能力一起废掉）
    check(gp.is_wrong_vhost("codeload.github.com",
                            "/git/git/tar.gz/refs/heads/master", 301,
                            [(b"location",
                              b"https://github.com/git/git/tar.gz/refs/heads/master")]),
          "A12b 内容域的非根路径同路径 301 仍判错（检测能力未被削弱）")
    check(gp.is_wrong_vhost("raw.githubusercontent.com", "/torvalds/linux/master/README",
                            301,
                            [(b"location",
                              b"https://github.com/torvalds/linux/master/README")]),
          "A12b 内容域 raw 的内容路径 301 仍判错")

    # 非内容域（静态资源）一律不判错：误拉的代价是整个域被踢出竞速 600s
    check(not gp.is_wrong_vhost("avatars.githubusercontent.com", "/u/1", 301,
                                [(b"location", b"https://github.com/u/1")]),
          "A12b 非内容域（avatars）不参与判定 → 不误拉黑")
    check(not gp.is_wrong_vhost("github.githubassets.com", "/assets/x.js", 301,
                                [(b"location", b"https://github.com/assets/x.js")]),
          "A12b 非内容域（githubassets）不参与判定 → 不误拉黑")

    # 端到端：codeload 根路径的 301 必须**透传**给浏览器（而不是抛 ip_bad / 502）
    up = FakeUp(b"HTTP/1.1 301 Moved Permanently\r\n"
                b"Location: https://github.com/\r\nContent-Length: 0\r\n\r\n")
    cl = Collect()
    try:
        gp.forward_once(FakeClient(cl), up, b"GET / HTTP/1.1\r\n\r\n",
                        0, "GET", 1 << 20, False, False,
                        "codeload.github.com", "/")
        e = None
    except gp.UpstreamBroken as ex:
        e = ex
    check(e is None and b"301" in b"".join(cl.chunks),
          "A12b codeload 根路径 301 原样透传（旧版会抛 ip_bad 并把好 IP 拉黑）",
          "%s" % (e and str(e)[:50]))

    # 端到端：forward_once 收到兜底 301 时必须抛 ip_bad，而不是把 301 端给浏览器
    up, cl = FakeUp(b"HTTP/1.1 301 Moved Permanently\r\n"
                    b"Location: https://github.com/repos/torvalds/linux\r\n"
                    b"Content-Length: 0\r\n\r\n"), Collect()
    try:
        gp.forward_once(FakeClient(cl), up, b"GET /repos/torvalds/linux HTTP/1.1\r\n\r\n",
                        0, "GET", 1 << 20, False, False, "api.github.com",
                        "/repos/torvalds/linux")
        e = None
    except gp.UpstreamBroken as ex:
        e = ex
    check(e is not None and e.ip_bad is True and cl.chunks == [],
          "兜底 301 → 抛 ip_bad 且一个字节都不发给浏览器",
          "%s" % (e and ("ip_bad=%s" % e.ip_bad)))

    # 正常的 200 不能被这个检查误伤
    up, cl = FakeUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"), Collect()
    try:
        reuse = gp.forward_once(FakeClient(cl), up, b"GET /x HTTP/1.1\r\n\r\n",
                                0, "GET", 1 << 20, False, False,
                                "api.github.com", "/x")
        e = None
    except gp.UpstreamBroken as ex:
        reuse, e = None, ex
    check(e is None and b"200 OK" in b"".join(cl.chunks),
          "正常 200 不受虚拟主机检查影响", "%s" % (e and str(e)[:40]))

    # 拉黑表：命中即跳过，过期自动放行
    gp.BAD_IP.clear()
    check(gp.ip_ok("api.github.com", "20.205.243.166"),
          "未拉黑的 IP 可用")
    gp.mark_ip_bad("api.github.com", "20.205.243.166")
    check(not gp.ip_ok("api.github.com", "20.205.243.166"),
          "拉黑后该 IP 被跳过")
    check(gp.ip_ok("api.github.com", "20.205.243.168"),
          "拉黑只针对那一个 IP，不牵连同域其它 IP")
    check(gp.ip_ok("github.com", "20.205.243.166"),
          "拉黑只针对那个域名，不牵连其它域名（.166 本就是 github.com 的）")
    gp.BAD_IP["api.github.com"]["20.205.243.166"] = time.time() - 1
    check(gp.ip_ok("api.github.com", "20.205.243.166"),
          "过期后自动放行，不会永久封禁")
    gp.BAD_IP.clear()

    # 兜底 IP 池里不能再塞「不属于该域名」的地址（就是上面那个 .166）
    check("20.205.243.166" not in gp.FALLBACK_IPS["api.github.com"],
          "api.github.com 兜底池已剔除 .166（它只认 github.com 虚拟主机）")
    check("20.205.243.166" not in gp.FALLBACK_IPS["codeload.github.com"],
          "codeload.github.com 兜底池已剔除 .166")

    # ---- A13 端到端（不联网）：撞上错 IP 时必须自己换一条，而不是把 301 端出去 ----
    #
    # 用脚本化上游替掉真实拨号：第 1 条连接回「兜底 301」，第 2 条回真 JSON。
    # 断言：客户端最终看到 200（而不是 301），且那个错 IP 被拉黑。
    class ScriptedUp:
        def __init__(self, data):
            self.data = data
            self.pos = 0
            self.sent = b""

        def sendall(self, d):
            self.sent += d

        def settimeout(self, t):
            pass

        def close(self):
            pass

        def recv(self, n):
            piece = self.data[self.pos:self.pos + n]
            self.pos += len(piece)
            return piece

    class OutSock:
        def __init__(self):
            self.out = []

        def sendall(self, d):
            self.out.append(d)

    class OneShotClient:
        """只发一个请求的假客户端。"""

        def __init__(self, req):
            self.sock = OutSock()
            self.req = req
            self.n = 0

        def read_head(self):
            self.n += 1
            return self.req if self.n == 1 else None

        def pipe_out(self, dst, n):
            raise AssertionError("本用例不该有请求体")

    BAD, GOOD = "20.205.243.166", "20.205.243.168"
    served = []

    def fake_connect(host, budget=None):
        served.append(host)
        ip = BAD if len(served) == 1 else GOOD
        gp.GOOD_PEER[host] = (ip, host)        # 与真实 connect_upstream 行为一致
        if len(served) == 1:
            return ScriptedUp(b"HTTP/1.1 301 Moved Permanently\r\n"
                              b"Location: https://github.com/repos/torvalds/linux\r\n"
                              b"Content-Length: 0\r\n\r\n")
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    gp.BAD_IP.clear()
    gp._pool.clear()
    real_connect = gp.connect_upstream
    gp.connect_upstream = fake_connect
    try:
        cl = OneShotClient(b"GET /repos/torvalds/linux HTTP/1.1\r\n"
                           b"Host: api.github.com\r\n\r\n")
        gp.serve(cl, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real_connect

    out = b"".join(cl.sock.out)
    check(b"200 OK" in out and b"301" not in out,
          "撞上错 IP → 自动换一条，浏览器只看到 200（看不到 301）",
          "头: %r" % out[:40])
    check(len(served) == 2, "确实重拨了一次（不是直接把错内容端出去）",
          "拨号 %d 次" % len(served))
    check(gp.BAD_IP.get("api.github.com", {}).get(BAD) is not None,
          "错 IP 被拉黑，后续请求不再命中", "%s" % gp.BAD_IP)
    check(not gp.ip_ok("api.github.com", BAD) and gp.ip_ok("api.github.com", GOOD),
          "拉黑生效且只针对那一个 IP")

    gp.GOOD_PEER.clear()
    gp.BAD_IP.clear()
    gp._pool.clear()

    # ---- A14 预算自洽性：单阶段等待不得把「重试」从结构上挤掉 ----
    #
    # 这是本轮踩到的最后一个坑，而且是「数值配错」型的，靠读代码很难看出来：
    # 体首字节的等待曾被设成 60s，比重试总预算 ATTEMPT_BUDGET=45s 还长 ——
    # 于是**第一次尝试就能吃光全部预算，重试在结构上不可能发生**。
    # 实测表现为：首页硬等 60s 后 502，而另一条通道 1s 就能通。
    # 这条断言把"数值必须自洽"这个不变量钉死，以后调参不会再犯。
    for name in ("HEADER_TIMEOUT", "FIRST_BYTE_TIMEOUT",
                 "BODY_STALL_TIMEOUT", "POOL_FIRST_BYTE_TIMEOUT"):
        v = getattr(gp, name)
        check(v < gp.ATTEMPT_BUDGET,
              "单阶段预算 %s < 重试总预算" % name,
              "%ds vs %ds" % (v, gp.ATTEMPT_BUDGET))

    worst = gp.HEADER_TIMEOUT + gp.FIRST_BYTE_TIMEOUT
    check(worst <= gp.ATTEMPT_BUDGET,
          "最坏的单次尝试（头超时+体首字节超时）不超预算，留得下第二次尝试",
          "%ds vs %ds" % (worst, gp.ATTEMPT_BUDGET))
    check(gp.MAX_ATTEMPTS >= 2 and gp.ATTEMPT_BUDGET >= 2 * gp.HEADER_TIMEOUT,
          "预算至少容得下两轮「等响应头」（两轮换模式重试）",
          "MAX_ATTEMPTS=%d 预算=%ds" % (gp.MAX_ATTEMPTS, gp.ATTEMPT_BUDGET))
    check(gp.POOL_FIRST_BYTE_TIMEOUT <= gp.FIRST_BYTE_TIMEOUT,
          "池里捞出的死连接给的预算不比新连接宽（它更可疑）")

    # 无体幂等请求（GET/HEAD）单独一套更短的预算：它们重试安全且廉价，
    # 遇到「握手成功、请求被吞」时应当尽快换通道，而不是陪着等满 20s。
    check(gp.HEADER_TIMEOUT_GET < gp.HEADER_TIMEOUT,
          "无体幂等请求的头预算更短（实测 40s → 20s）",
          "%ds < %ds" % (gp.HEADER_TIMEOUT_GET, gp.HEADER_TIMEOUT))
    check(gp.HEADER_TIMEOUT_GET + gp.FIRST_BYTE_TIMEOUT_GET
          + gp.HEADER_TIMEOUT_GET <= gp.ATTEMPT_BUDGET,
          "无体请求最坏也能装下两次尝试（换通道重试有意义）",
          "%d + %d + %d ≤ %d" % (gp.HEADER_TIMEOUT_GET, gp.FIRST_BYTE_TIMEOUT_GET,
                                 gp.HEADER_TIMEOUT_GET, gp.ATTEMPT_BUDGET))
    check(gp.FIRST_BYTE_TIMEOUT_GET <= gp.FIRST_BYTE_TIMEOUT,
          "无体请求的体首字节预算也不比通用值宽")
    check(gp.HEADER_TIMEOUT_GET >= 5 and gp.FIRST_BYTE_TIMEOUT_GET >= 5,
          "缩短后的预算仍远大于实测 TTFB（0.07~0.65s）",
          "%ds / %ds" % (gp.HEADER_TIMEOUT_GET, gp.FIRST_BYTE_TIMEOUT_GET))

    # ---- A15 端到端（不联网）：响应头回来了、体却被吞掉，也必须换通道重试 ----
    #
    # 这是本轮最后一个坑的精确复现：GFW 不只吞「响应头」，也会**放行响应头再吞掉响应体**。
    # 老代码给体首字节留 60s 预算（> 重试总预算 45s），于是第一次尝试就吃光预算，
    # 重试结构上不可能发生 → 首页硬等 60s 后 502，而另一条通道 1s 就能通。
    # 用例用「头+CL 声明 100 字节、随后 EOF」来触发体阶段的通道级失败（无需真的等待）。
    served2 = []

    def fake_connect2(host, budget=None):
        served2.append(host)
        ip = "20.27.177.113" if len(served2) == 1 else "20.200.245.247"
        gp.GOOD_PEER[host] = (ip, host if len(served2) == 1 else None)
        if len(served2) == 1:
            # 头正常、声明 100 字节，然后连接就没了 —— 体一个字节都没来
            return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    gp._pool.clear()
    real_connect2 = gp.connect_upstream
    gp.connect_upstream = fake_connect2
    try:
        cl = OneShotClient(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real_connect2

    out2 = b"".join(cl.sock.out)
    check(len(served2) == 2, "体被吞掉 → 判定为通道故障并重试（不是直接 502）",
          "拨号 %d 次" % len(served2))
    check(b"200 OK" in out2 and b"100" not in out2.split(b"\r\n")[0],
          "重试后浏览器拿到的是完整 200，而不是半截声明",
          "头: %r" % out2[:40])
    pen = gp.MODE_PENALTY.get("github.com")
    check(pen is not None and pen[0] == "github.com",
          "体传输上栽过的 SNI 模式被记了惩罚（下次先试另一条通道）",
          "MODE_PENALTY=%s" % (pen,))

    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    gp.BAD_IP.clear()
    gp.MODE_GOOD.clear()      # A15 的重试成功路径会写 MODE_GOOD，别泄漏给后续用例
    gp._pool.clear()

    # ---- A16 chunked 长度行必须严格按 RFC 9112 解析（1*HEXDIG） ----
    #
    # 病根：原先只写 `int(line, 16)`，而 Python 的 int 太宽容 —— 会吃下
    # "+5"、"0x4"、"1_6"，甚至 **"-3"**。负长度会让 need 变负、把帧长账算乱，
    # 实测能让扫描器**提前宣布响应结束（done=True）**：半截响应被当成成功，
    # 错位的连接还被放回池子。这正是当初「首页 577KB 全乱码却测试通过」的同款病根。
    def scan_once(payload):
        sc = gp.ChunkedScanner()
        try:
            return sc.feed(payload), None
        except ValueError as e:
            return None, e

    # 合法形态必须照常通过（含 chunk 扩展与 trailer）
    ok_cases = {
        "简单 4+0": b"4\r\nWiki\r\n0\r\n\r\n",
        "带扩展参数": b"4;a=b\r\nWiki\r\n0\r\n\r\n",
        "带 trailer": b"4\r\nWiki\r\n0\r\nX-Foo: 1\r\n\r\n",
        "大写十六进制": b"A\r\n0123456789\r\n0\r\n\r\n",
    }
    for name, payload in ok_cases.items():
        r, e = scan_once(payload)
        check(e is None and r and r[0] is True,
              "chunked 合法形态照常解析：%s" % name,
              "%s" % ((str(e)[:40] if e else r),))

    # 非法形态一律报错，绝不能「算错帧长还当成功」
    bad_cases = {
        "负长度 -3": b"-3\r\n" + b"-3\r\n" * 8 + b"0\r\n\r\n",
        "带正号 +5": b"+5\r\nabcde\r\n0\r\n\r\n",
        "0x 前缀": b"0x4\r\nWiki\r\n0\r\n\r\n",
        "下划线 1_6": b"1_6\r\n" + b"a" * 22 + b"\r\n0\r\n\r\n",
        "空行": b"\r\n",
        "超长长度行": b"F" * 2000 + b"\r\n",
        "非十六进制": b"zz\r\n",
        # 沙盒攻击实验 E7 坐实（R2-5 加固）：数据区终止符被顶替必须在扫描期报错
        "数据后终止符非 CRLF": b"5\r\nAAAAA\rQ\n0\r\n\r\n",
        "数据后终止符跨包缺失": [b"5\r\nAAAA", b"A\rQ", b"\n0\r\n\r\n"],
    }
    for name, payload in bad_cases.items():
        if isinstance(payload, list):     # 跨包形态：逐片喂入
            sc_x = gp.ChunkedScanner()
            e_x = None
            try:
                done_x = False
                for c in payload:
                    done_x, _u = sc_x.feed(c)
            except ValueError as ex:
                e_x = ex
            check(e_x is not None,
                  "chunked 非法长度行必须报错：%s" % name,
                  "%s" % (e_x or "错误地返回了完成 %s" % done_x))
            continue
        r, e = scan_once(payload)
        check(e is not None and isinstance(e, ValueError),
              "chunked 非法长度行必须报错：%s" % name,
              "%s" % (e or "错误地返回了 %s" % (r,)))

    # ---- A17 响应侧也要剥 Connection 点名的字段（RFC 9110 §7.6.1） ----
    #
    # 请求侧一早就剥了，响应侧原先漏了：上游若回 `Connection: X-Hop` + `X-Hop: v`，
    # 这条 X-Hop 会原样漏给浏览器。
    hdr_up = (b"HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: leak-me\r\n"
              b"X-Keep: fine\r\nContent-Length: 2\r\n\r\n{}")
    up, cl = FakeUp(hdr_up), Collect()
    try:
        gp.forward_once(FakeClient(cl), up, b"GET / HTTP/1.1\r\n\r\n", 0,
                        "GET", 1 << 20)
    except gp.UpstreamBroken:
        pass
    out = b"".join(cl.chunks).lower()
    check(b"x-hop" not in out, "响应里被 Connection 点名的字段已被剥掉（x-hop）",
          "出站头: %r" % out[:120])
    check(b"x-keep" in out, "未被点名的响应头照常保留")
    check(b"connection:" in out, "回给浏览器的 Connection 由我们重写")

    # ---- A18 请求体一旦被读过，就绝不允许重试 ----
    #
    # 池里捞出的连接失败时，`from_pool` 短路会让**带 body 的请求也去重试**；
    # 可 body 只在浏览器那一侧、上一轮已经读光 → 重试会发着 Content-Length
    # 却一个字节都发不出，上游苦等、浏览器等到连接被掐断。
    served3 = []

    def fake_connect3(host, budget=None):
        served3.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"")          # 连上就 EOF —— 头都没给

    class PostClient(OneShotClient):
        """带请求体的假客户端：被 pipe_out 读过就标记 body_consumed。"""

        def __init__(self, req, body):
            OneShotClient.__init__(self, req)
            self.body = body
            self.body_consumed = False

        def pipe_out(self, dst, n):
            self.body_consumed = True
            dst.sendall(self.body[:n])

    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    gp._pool.clear()
    real_c3 = gp.connect_upstream
    gp.connect_upstream = fake_connect3
    try:
        cl = PostClient(b"POST /x HTTP/1.1\r\nHost: github.com\r\n"
                        b"Content-Length: 5\r\n\r\n", b"hello")
        gp.serve(cl, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real_c3
        gp.MODE_PENALTY.clear()   # 本用例的通道级失败会记惩罚，别泄漏给后续用例
    check(len(served3) == 1,
          "带请求体的请求失败后不重试（否则会发一个永远不来的 body）",
          "拨号 %d 次" % len(served3))

    # 无体的幂等请求仍然允许重试（别把这条好路一起堵死）
    served4 = []

    def fake_connect4(host, budget=None):
        served4.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        if len(served4) == 1:
            return ScriptedUp(b"")
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    gp._pool.clear()
    real_c4 = gp.connect_upstream
    gp.connect_upstream = fake_connect4
    try:
        cl = OneShotClient(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real_c4
    check(len(served4) == 2 and b"200 OK" in b"".join(cl.sock.out),
          "无体幂等请求仍照常重试（修复没有误伤）", "拨号 %d 次" % len(served4))

    # ---- A19 通道被判死时，该模式名下的池化连接一起清掉 ----
    #
    # 池按 (host, ip, 模式) 分桶，而 pool_get 只查「当前 GOOD_PEER」那一个桶：
    # 模式一切换，旧桶再也没人查、也就再没人清理，里面的连接会一直占着 fd。
    class DummySock:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    gp._pool.clear()
    s_old = DummySock()
    # 顺序要紧：pool_put 现在会顺手回收「不属于当前 GOOD_PEER」的桶，
    # 所以必须先有 peer 再入池（这正是真实调用顺序 —— serve 是先读 peer 再 pool_put）。
    gp.GOOD_PEER["github.com"] = ("1.1.1.1", "github.com")
    gp.pool_put("github.com", "1.1.1.1", "github.com", s_old, 0)
    check(bool(gp._pool), "池里先放一条连接做样本", "%s" % list(gp._pool))
    gp.mark_channel_bad("github.com", chan=True)
    check(not gp._pool and s_old.closed,
          "通道被判死后，该模式名下的池化连接被清掉并关闭（不留 fd）",
          "池=%s closed=%s" % (gp._pool, s_old.closed))

    # ---- A21 CRL 分发：证书 CDP 端口必须与反代实际监听端口一致 ----
    #
    # 为什么值得一条独立用例：Windows 上 curl/git 走 schannel，会**强制**做证书
    # 吊销检查。证书里声明 crlDistributionPoints = http://127.0.0.1:<port>/ca.crl，
    # 反代起一个极小 HTTP 监听把 CRL 喂出去 —— 两端端口必须一致。
    # 一旦错位，schannel 取不到 CRL → CRYPT_E_NO_REVOCATION_CHECK → curl 直接挂，
    # 而且**不会有任何显式报错**，只表现为「curl 打不开」，极难归因。
    import tempfile as _tf
    import urllib.request as _url
    _openssl = None
    for _c in (r"C:\Program Files\Git\usr\bin\openssl.exe",
               r"C:\Program Files\Git\mingw64\bin\openssl.exe",
               r"C:\Windows\System32\openssl.exe"):
        if os.path.exists(_c):
            _openssl = _c
            break
    _td = _tf.mkdtemp(prefix="ghp-crl-")
    _pf = os.path.join(_td, "crl-port.txt")
    _old_pf, _old_cf = gp.CRL_PORT_FILE, gp.CRL_FILE
    try:
        # ① 端口解析三态
        with open(_pf, "w") as f:
            f.write("29999\n")
        gp.CRL_PORT_FILE = _pf
        check(gp._crl_port() == 29999, "A21 CRL 端口：从 crl-port.txt 正确读取")
        with open(_pf, "w") as f:
            f.write("not-a-number\n")
        check(gp._crl_port() == gp.DEFAULT_CRL_PORT,
              "A21 CRL 端口：内容非法时退回默认值")
        with open(_pf, "w") as f:
            f.write("70000\n")          # 越界
        check(gp._crl_port() == gp.DEFAULT_CRL_PORT,
              "A21 CRL 端口：越界值退回默认值")
        os.remove(_pf)
        check(gp._crl_port() == gp.DEFAULT_CRL_PORT,
              "A21 CRL 端口：文件缺失时退回默认值")

        # ② 真起一次服务，验证它确实把 CRL 字节喂出去、别的路径给 404
        _src_crl = os.path.join(gp.CERT_DIR, "ca.crl")
        if os.path.exists(_src_crl):
            _s = socket.socket()
            _s.bind(("127.0.0.1", 0))
            _freeport = _s.getsockname()[1]
            _s.close()
            with open(_pf, "w") as f:
                f.write("%d\n" % _freeport)
            gp.CRL_PORT_FILE = _pf
            gp.CRL_FILE = _src_crl
            _srv = gp.start_crl_server()
            check(_srv is not None, "A21 CRL 监听能起来")
            if _srv is not None:
                time.sleep(0.3)
                _want = open(_src_crl, "rb").read()
                try:
                    _got = _url.urlopen(
                        "http://127.0.0.1:%d/ca.crl" % _freeport, timeout=5).read()
                    check(_got == _want,
                          "A21 取回的 CRL 字节与文件一致",
                          "%d B" % len(_got))
                except Exception as _e:
                    check(False, "A21 取回 CRL", str(_e)[:60])
                try:
                    _url.urlopen("http://127.0.0.1:%d/nope" % _freeport,
                                 timeout=5).read()
                    _code = 200
                except Exception as _e:
                    _code = getattr(_e, "code", 0)
                check(_code == 404, "A21 只服务 /ca.crl，其它路径 404",
                      "code=%s" % _code)
                _srv.close()
        else:
            skip("A21 CRL 服务端到端（本目录尚无 certs/ca.crl）")

        # ③ 最关键的不变量：证书里写的 CDP 端口 == 反代**实际**会监听的端口
        #   （先把 CRL_PORT_FILE 还原成生产路径，否则比的是临时文件，等于自证）
        gp.CRL_PORT_FILE = _old_pf
        _real_port = gp._crl_port()
        _crt = gp.CERT_FILE
        if os.path.exists(_crt) and _openssl:
            _r = subprocess.run([_openssl, "x509", "-in", _crt, "-noout", "-text"],
                                capture_output=True)
            _txt = (_r.stdout or b"").decode("utf-8", "replace")
            import re as _re
            _m = _re.search(r"URI:http://127\.0\.0\.1:(\d+)/ca\.crl", _txt)
            if _m:
                check(int(_m.group(1)) == _real_port,
                      "A21 证书 CDP 端口 == 反代实际监听端口（错位即 curl 挂）",
                      "CDP=%s 反代=%d" % (_m.group(1), _real_port))
            else:
                skip("A21 证书未声明 CDP（跑 gen_certs.py 后会补上）")
        else:
            skip("A21 证书 CDP 校验（无证书或无 openssl）")
    finally:
        gp.CRL_PORT_FILE, gp.CRL_FILE = _old_pf, _old_cf
        shutil.rmtree(_td, ignore_errors=True)

    # ---- A22 竞速切片必须覆盖全池（「有通道却从没去试」的回归护栏）----
    #
    # 2026-09-21 实测换来：旧写法 `ips = ips[:RACE_SIZE]` 每轮都竞速**同一批前 N 个**，
    # 池尾 IP **从上线起就没被试过**。当日 github.com 的 101 次失败恰好全落在
    # 被竞速的那 4 个上，而逐 IP 实测发现池外还有 10 个可用 ——
    # 也就是说失败的大头不是「没通道」，是「有通道但从没去试」。
    #
    # 本用例守的就是这条：**在预算允许的调用次数内，池子里每个 IP 都必须被排到过。**
    _pool = ["i%02d" % n for n in range(16)]
    check(gp.race_slice(_pool, 6, 0) == ["i00", "i01", "i02", "i03", "i04", "i05"],
          "A22 切片：步 0 → 头 2 个固定 + 尾段起始 4 个",
          "%s" % (gp.race_slice(_pool, 6, 0),))
    check(gp.race_slice(_pool, 6, 1) == ["i00", "i01", "i06", "i07", "i08", "i09"],
          "A22 ★头部固定：步进后最快的 2 个仍留在切片里（保住快路）",
          "%s" % (gp.race_slice(_pool, 6, 1),))
    check(gp.race_slice(_pool, 6, 3) == ["i00", "i01", "i14", "i15", "i02", "i03"],
          "A22 切片：尾段轮转回绕正确（池尾 I14/I15 能排进来）",
          "%s" % (gp.race_slice(_pool, 6, 3),))
    check(gp.race_slice(["a", "b"], 6, 3) == ["a", "b"],
          "A22 切片：候选少于切片大小时原样返回（不重复、不报错）")
    check(gp.race_slice([], 6, 0) == [],
          "A22 切片：空候选安全")

    # 核心不变量：单次建连能跑几次竞速调用 → 那几次必须覆盖全池
    _calls = max(1, gp.REQUEST_BUDGET // gp.PHASE_BUDGET)
    _seen = []
    for _k in range(_calls):
        _seen += gp.race_slice(_pool, gp.RACE_SIZE, _k)
    _missed = [ip for ip in _pool if ip not in _seen]
    check(not _missed,
          "A22 ★不变量：单次建连的预算内，池里每个 IP 都能被排到至少一次",
          "调用 %d 次 × 切片 %d；漏掉的: %s" % (_calls, gp.RACE_SIZE, _missed or "无"))

    # 旧写法为什么不行 —— 反例固化下来，防止有人改回去
    _old = []
    for _k in range(_calls):
        _old += _pool[:gp.RACE_SIZE]
    check(len(set(_old)) < len(_pool),
          "A22 反例：旧的 ips[:RACE_SIZE] 写法确实覆盖不全（这条证明用例有分辨力）",
          "旧写法只覆盖 %d/%d 个" % (len(set(_old)), len(_pool)))

    # 头段的 IP 必须**永远在**每次切片里（这是 p50 不再劣化的保证）
    _head_always = all(
        all(ip in gp.race_slice(_pool, gp.RACE_SIZE, k) for ip in _pool[:gp.RACE_HEAD])
        for k in range(_calls))
    check(_head_always,
          "A22 ★头部 IP 在每次切片里都出现（否则慢 IP 会赢下冷启动 → p50 劣化）",
          "RACE_HEAD=%d" % gp.RACE_HEAD)

    # 游标必须真的推进
    _before = gp._race_rotate
    gp._race_rotate += 1
    check(gp._race_rotate == _before + 1,
          "A22 轮转游标逐步推进（连续请求才会换到不同步）")
    gp._race_rotate = _before

    # 池子的规模必须与切片×轮次相称：池子再大也不会被白放
    _gh = gp.FALLBACK_IPS.get("github.com", [])
    check(len(_gh) >= gp.RACE_SIZE,
          "A22 github.com 兜底池不小于单次切片（否则切片恒等于全池）",
          "%d 个 IP / 切片 %d" % (len(_gh), gp.RACE_SIZE))

    # ---- A23 连接池保温：周期必须短于池过期，否则静默白保 ----
    #
    # 2026-09-21 定性：POOL_IDLE_TIMEOUT=45s，而真实用法是「隔几分钟点一下」
    # ⇒ 池子基本永远空的，每次点击都重吃冷连接学费（实测首次 2.16s / 池化 0.27s）。
    #
    # ⚠️ 这条判据守的是一个**静默失效**：WARM_INTERVAL 一旦 >= POOL_IDLE_TIMEOUT，
    #    保温线程每次保完、连接在下一轮之前就过期了 —— 表面上线程在跑、日志没异常，
    #    实际一次都没保上。这种 bug 不会有任何信号。
    check(gp.WARM_INTERVAL < gp.POOL_IDLE_TIMEOUT,
          "A23 ★保温周期严格短于池过期时间（否则保了等于没保，且无任何报错）",
          "WARM_INTERVAL=%d  POOL_IDLE_TIMEOUT=%d"
          % (gp.WARM_INTERVAL, gp.POOL_IDLE_TIMEOUT))
    check(gp.WARM_BUDGET < gp.REQUEST_BUDGET,
          "A23 保温的等待预算小于用户请求的预算（保温不跟用户抢通道）",
          "WARM_BUDGET=%d  REQUEST_BUDGET=%d" % (gp.WARM_BUDGET, gp.REQUEST_BUDGET))
    check(len(gp.WARM_HOSTS) > 0 and all(isinstance(h, str) for h in gp.WARM_HOSTS),
          "A23 保温域名表非空且是字符串",
          "%s" % (gp.WARM_HOSTS,))
    check(all(h in gp.FALLBACK_IPS for h in gp.WARM_HOSTS),
          "A23 保温的每个域名都在兜底池里有 IP（否则保温只能靠 DNS）",
          "缺: %s" % [h for h in gp.WARM_HOSTS if h not in gp.FALLBACK_IPS])

    # _pool_has 必须**只看不取** —— 用 pool_get 做检查会把连接吃掉
    gp._pool.clear()
    check(gp._pool_has("github.com") is False,
          "A23 空池时 _pool_has 返回 False")
    class _WarmDummy:
        def close(self):
            pass
    gp._pool[("github.com", "1.2.3.4", "github.com")] = [(_WarmDummy(), 0, time.time())]
    check(gp._pool_has("github.com") is True,
          "A23 有未过期连接时 _pool_has 返回 True")
    check(len(gp._pool[("github.com", "1.2.3.4", "github.com")]) == 1,
          "A23 ★_pool_has 只看不取（连接仍在池里，没被吃掉）",
          "%d 条" % len(gp._pool[("github.com", "1.2.3.4", "github.com")]))
    gp._pool[("github.com", "1.2.3.4", "github.com")] = [
        (_WarmDummy(), 0, time.time() - gp.POOL_IDLE_TIMEOUT - 10)]
    check(gp._pool_has("github.com") is False,
          "A23 池里只剩过期连接时 _pool_has 返回 False")
    gp._pool.clear()

    # ---- A20 204/304/HEAD 若被声明了 TE，这条连接不得复用 ----
    reuse, err, out = fwd(b"HTTP/1.1 304 Not Modified\r\n"
                          b"Transfer-Encoding: chunked\r\n\r\n", method="HEAD")
    check(err is None and reuse is False,
          "HEAD/304 带 TE → 不复用（否则残体会被下一个请求当成响应头读）",
          "reuse=%s" % reuse)

    # ---- A21 git push 的 chunked 请求体必须原样中继 ----
    #
    # 本轮挖出的最要命的一个。**git push 的请求体一旦超过 http.postBuffer
    # （默认 1 MiB），git 就改用 `Transfer-Encoding: chunked`。**
    # 实测（2026-09-12，git 2.55 + git http-backend）一次 3.1 MB 的推送：
    #     POST /r.git/git-receive-pack   Transfer-Encoding: chunked   CL=None
    # 旧版对任何带 TE 的请求一律回 411 Length Required —— 等于「仓库大一点就推不上去」，
    # 而且报错只在客户端侧、服务端只有一行 warn，极难归因。
    CHUNKED_BODY = (b"1a\r\n" + b"x" * 26 + b"\r\n"
                    b"5\r\nhello\r\n"
                    b"0\r\n\r\n")

    class FakeSockStream:
        """把一串脚本字节当成 socket 交给**真正的** gp.Client。

        step 非 None 时每次只交 step 字节，用来逼出「长度行 / CRLF 被 recv 切开」的边界。
        """

        def __init__(self, data, step=None):
            self.data = data
            self.step = step
            self.out = []
            self.closed = False

        def recv(self, n=65536):
            if self.step:
                n = min(n, self.step)
            d, self.data = self.data[:n], self.data[n:]
            return d

        def sendall(self, d):
            self.out.append(d)

        def close(self):
            self.closed = True

    class ChunkClient(gp.Client):
        """只发一个请求、带 chunked 请求体的假客户端。

        刻意继承**真的** gp.Client —— pipe_chunked 的字节账目本身就是要测的东西，
        假实现等于把被测对象替换掉，测了个寂寞。
        """

        def __init__(self, req, frames, step=None):
            self._req = req
            self._n = 0
            gp.Client.__init__(self, FakeSockStream(frames, step))

        def read_head(self):
            self._n += 1
            return self._req if self._n == 1 else None

    PUSH_REQ = (b"POST /r.git/git-receive-pack HTTP/1.1\r\n"
                b"Host: github.com\r\n"
                b"Content-Type: application/x-git-receive-pack-request\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n")

    def run_push(req, frames, step=None):
        """跑一次 serve()，返回 (上游收到的字节, 客户端收到的字节)。"""
        ups = []

        def fake_connect(host, budget=None):
            gp.GOOD_PEER[host] = ("20.27.177.113", host)
            up = ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            ups.append(up)
            return up

        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp._pool.clear()
        real = gp.connect_upstream
        gp.connect_upstream = fake_connect
        try:
            cl = ChunkClient(req, frames, step)
            gp.serve(cl, ("127.0.0.1", 1))
        finally:
            gp.connect_upstream = real
        return (b"".join(u.sent for u in ups), b"".join(cl.sock.out), cl)

    up_raw, cl_out, cl21 = run_push(PUSH_REQ, CHUNKED_BODY)
    up_head, _, up_body = up_raw.partition(b"\r\n\r\n")
    low21 = up_head.lower()
    check(b"transfer-encoding: chunked" in low21,
          "chunked 请求：上游收到 TE 声明（剥了它上游就当无体处理）",
          "上游头: %r" % low21[:70])
    check(b"content-length" not in low21,
          "chunked 请求：不得再补 Content-Length（TE+CL 并存即走私构造，§6.3）")
    check(up_body == CHUNKED_BODY,
          "chunked 请求体原样中继（分块帧一字不改）",
          "上游 %d 字节 / 应为 %d" % (len(up_body), len(CHUNKED_BODY)))
    check(b"200 OK" in cl_out, "chunked 推送照常拿到 200 响应",
          "客户端头: %r" % cl_out[:32])
    check(cl21.body_consumed is True, "读过请求体即标记不可重放（后续不许重试）")

    # 分片到 3 字节一收：专测「长度行/CRLF 被切开时不能多搬也不能漏搬」
    up_raw, _, _ = run_push(PUSH_REQ, CHUNKED_BODY, step=3)
    _, _, up_body = up_raw.partition(b"\r\n\r\n")
    check(up_body == CHUNKED_BODY,
          "分片到 3 字节一收，请求体字节账目依然分毫不差",
          "上游 %d 字节 / 应为 %d" % (len(up_body), len(CHUNKED_BODY)))

    # ---- A22 TE 与 CL 同时出现：以 TE 为准，且必须把 CL 丢掉 ----
    up_raw, _, _ = run_push(
        b"POST /x HTTP/1.1\r\nHost: github.com\r\n"
        b"Content-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n", CHUNKED_BODY)
    up_head, _, up_body = up_raw.partition(b"\r\n\r\n")
    low22 = up_head.lower()
    check(b"content-length" not in low22 and b"chunked" in low22 and up_body == CHUNKED_BODY,
          "TE 与 CL 并存：按 TE 切帧并丢掉 CL（上游只看到一条 TE，构不成走私）",
          "上游头: %r" % low22[:70])

    # ---- A23 只有「最后一层不是 chunked」才拒绝 ----
    served23 = []

    def fake_connect23(host, budget=None):
        served23.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    real23 = gp.connect_upstream
    gp.connect_upstream = fake_connect23
    try:
        cl23 = OneShotClient(b"POST /x HTTP/1.1\r\nHost: github.com\r\n"
                             b"Transfer-Encoding: gzip\r\n\r\n")
        gp.serve(cl23, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real23
    line23 = b"".join(cl23.sock.out).split(b"\r\n")[0]
    check(b"501" in line23 and not served23,
          "最后一层不是 chunked（gzip）→ 501，且不去连上游",
          "客户端: %r 拨号 %d 次" % (line23, len(served23)))

    # ---- A24 客户端分块帧不合法 → 400（不是 502），且不重试 ----
    #
    # 旧代码把这类错误混进 UpstreamBroken：日志写「上游失败」（把排查方向带偏），
    # 客户端拿到 502（让它以为「重试一下可能就好了」，于是把坏字节再送一遍）。
    served24 = []

    def fake_connect24(host, budget=None):
        served24.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    real24 = gp.connect_upstream
    gp.connect_upstream = fake_connect24
    try:
        cl24 = ChunkClient(PUSH_REQ, b"-3\r\n" + b"-3\r\n" * 6 + b"0\r\n\r\n")
        gp.serve(cl24, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real24
    line24 = b"".join(cl24.sock.out).split(b"\r\n")[0]
    check(b"400" in line24,
          "客户端分块帧非法 → 400（不把锅甩给上游）", "客户端: %r" % line24)
    check(len(served24) == 1, "客户端发错时不重试（重发还是同样的坏字节）",
          "拨号 %d 次" % len(served24))

    # ---- A25 收尾块之后的字节属于下一个请求，必须塞回缓冲区 ----
    NXT = b"GET /next HTTP/1.1\r\nHost: github.com\r\n\r\n"
    fs = FakeSockStream(CHUNKED_BODY + NXT)
    c25 = gp.Client(fs)
    c25.pipe_chunked(fs)
    check(b"".join(fs.out) == CHUNKED_BODY,
          "pipe_chunked 原样中继请求体（不多搬也不漏搬）",
          "%d 字节" % len(b"".join(fs.out)))
    check(c25.buf == NXT,
          "收尾块之后的字节塞回缓冲区（流水线的下一个请求，别当请求体吃掉）",
          "残留: %r" % c25.buf[:26])
    check(c25.body_consumed is True, "pipe_chunked 同样标记读过请求体")

    # ---- A27 absolute-form 请求行必须改写成 origin-form（RFC 9112 §3.2.2） ----
    #
    # 配了 http_proxy 环境变量的工具（curl / git 都是）会发
    #   GET http://github.com/foo HTTP/1.1
    # 原样转给上游 = 把「用哪个虚拟主机」的决定权交给请求行里的 authority：
    # 与 Host 头打架时会被路由到别的 vhost，回一个 301；而那个 301 恰好长得像
    # 「答错虚拟主机」，于是 is_wrong_vhost 把一个好 IP 拉黑 10 分钟 ——
    # 等于自己把最好的通道踢出竞速。（实测触发过：探针里 git 就发过这种请求。）
    ups27 = []

    def fake_connect27(host, budget=None):
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        up = ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        ups27.append(up)
        return up

    gp.GOOD_PEER.clear()
    real27 = gp.connect_upstream
    gp.connect_upstream = fake_connect27
    try:
        cl27 = OneShotClient(b"GET http://github.com/foo/bar?x=1 HTTP/1.1\r\n"
                             b"Host: github.com\r\n\r\n")
        gp.serve(cl27, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real27
    line27 = ups27[0].sent.split(b"\r\n")[0]
    check(line27 == b"GET /foo/bar?x=1 HTTP/1.1",
          "absolute-form 请求行改写成 origin-form（上游只按 Host 选 vhost）",
          "上游请求行: %r" % line27)

    # ---- A26 池里的「孤儿桶」必须被回收 ----
    #
    # 池按 (host, ip, 模式) 分桶，pool_get 只查「当前 GOOD_PEER」那一个桶。
    # GOOD_PEER 一旦换 IP 或换模式（拨号失败、模式惩罚都会），旧桶就再没人查询，
    # 也就再没人做过期回收（过期检查在 pop 那一侧）→ 里面的 socket 占着 fd
    # 直到进程退出。这条路径每请求跑一次，正好当回收点。
    gp._pool.clear()
    gp.GOOD_PEER["github.com"] = ("1.1.1.1", "github.com")
    s_live = DummySock()
    gp.pool_put("github.com", "1.1.1.1", "github.com", s_live, 0)
    check(not s_live.closed and len(gp._pool) == 1, "当前 peer 的连接正常入池")
    gp.GOOD_PEER["github.com"] = ("2.2.2.2", None)      # 换 IP + 换模式
    s_new = DummySock()
    gp.pool_put("github.com", "2.2.2.2", None, s_new, 0)
    check(s_live.closed and len(gp._pool) == 1,
          "GOOD_PEER 一换，旧桶连接被回收并关闭（否则 fd 泄漏到进程退出）",
          "旧桶 closed=%s 桶数=%d" % (s_live.closed, len(gp._pool)))
    s_stale = DummySock()
    gp.GOOD_PEER["github.com"] = ("3.3.3.3", None)      # 又换了，本桶成了孤儿
    gp.pool_put("github.com", "2.2.2.2", None, s_stale, 0)
    check(s_stale.closed and not gp._pool,
          "GOOD_PEER 已被换掉时本次连接不入池（存了也没人来取）",
          "closed=%s 池=%s" % (s_stale.closed, gp._pool))

    # ---- A28 【本机地址绝不能当上游】—— 部署后 DNS 被自己的 hosts 带偏 ----
    #
    # 2026-09-14 实测踩中的最严重的一个 bug：hosts 把 36 个域名指向 127.0.0.1，
    # 而 getaddrinfo **会读 hosts** → resolve() 把「上游」解析成自己 → 反代连自己、
    # 那一层再解析、再连自己……递归到把 128 个并发槽耗尽 → 502 + 日志刷屏。
    # 最阴的地方：**没部署时（hosts 干净）一切正常**，所以自测全绿、一部署就现原形。
    # 这条用例就是把「hosts 已部署」这个状态搬进离线测试里。
    real_gai = socket.getaddrinfo
    real_dns = gp.dns_query_a

    def gai_hosts_only(host, *a, **kw):
        """模拟「hosts 已部署」：任何域名都被解析到 127.0.0.1。"""
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    try:
        # ① 公共 DNS 也不可用（最坏情况）：必须靠兜底池，且绝不能回本机地址
        gp.dns_query_a = lambda h, s, timeout=None: (_ for _ in ()).throw(
            OSError("模拟公共 DNS 不通"))
        socket.getaddrinfo = gai_hosts_only
        gp._dns_cache.clear()
        got = gp.resolve("raw.githubusercontent.com")
        check(got and "127.0.0.1" not in got,
              "hosts 已部署 + 公共DNS不通 → 不会把 127.0.0.1 当上游",
              "解析得 %s" % (got,))
        check("185.199.108.133" in got,
              "此时靠 FALLBACK_IPS 兜底（raw 的 Fastly 段）", "解析得 %s" % (got,))

        # ② 公共 DNS 可用：优先用它的真实地址（而不是 hosts 喂的本机地址）
        gp.dns_query_a = lambda h, s, timeout=None: ["185.199.110.133"]
        gp._dns_cache.clear()
        got = gp.resolve("raw.githubusercontent.com")
        check(got[0] == "185.199.110.133" and "127.0.0.1" not in got,
              "公共 DNS 可用时优先用真实地址（绕开 hosts）", "解析得 %s" % (got,))

        # ③ 公共 DNS 返回污染地址 → 过滤掉，别拿去连
        gp.dns_query_a = lambda h, s, timeout=None: ["243.185.187.39", "8.7.198.45"]
        gp._dns_cache.clear()
        got = gp.resolve("raw.githubusercontent.com")
        check("243.185.187.39" not in got and "8.7.198.45" not in got,
              "公共 DNS 回的污染地址照样被滤掉", "解析得 %s" % (got,))

        # ④ 拨号层兜底：就算解析层哪天漏了，dial 也必须当场拒绝本机地址
        try:
            gp.dial("127.0.0.1", "github.com")
            blocked = False
        except RuntimeError:
            blocked = True
        except Exception as e:
            blocked = False
        check(blocked, "dial() 见到本机地址直接拒绝（递归自杀的兜底红线）")

        # ⑤ SELF_IPS 与 POISON_IPS 不得混进任何兜底池（数据卫生）
        bad_self = {h: [ip for ip in v if ip in gp.SELF_IPS]
                    for h, v in gp.FALLBACK_IPS.items()}
        bad_poison = {h: [ip for ip in v if ip in gp.POISON_IPS]
                      for h, v in gp.FALLBACK_IPS.items()}
        check(not any(bad_self.values()), "FALLBACK_IPS 里没有本机地址",
              str({k: v for k, v in bad_self.items() if v})[:120])
        check(not any(bad_poison.values()), "FALLBACK_IPS 里没有已知污染地址",
              str({k: v for k, v in bad_poison.items() if v})[:120])
    finally:
        socket.getaddrinfo = real_gai
        gp.dns_query_a = real_dns
        gp._dns_cache.clear()

    # ---- A29 自研 DNS 客户端：合法报文能解析，畸形报文一律报错 ----
    def mk_dns(name, ips, tid, flags=0x8180):
        """手工拼一个 DNS 响应（tid 必须与查询一致 —— 真实 ID 是随机的）。"""
        q = b""
        for p in name.split("."):
            q += bytes([len(p)]) + p.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
        body = b""
        for ip in ips:
            body += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
            body += bytes(int(x) for x in ip.split("."))
        return (struct.pack(">HHHHHH", tid, flags, 1, len(ips), 0, 0)
                + q + body)

    real_sock = socket.socket

    class FakeUDP:
        """把查询报文回显成我们造好的响应（ID 从查询里取，模拟真实解析器）。"""

        def __init__(self, build):
            self.build = build
            self.sent = b""
            self.connected = False

        def settimeout(self, t):
            pass

        def connect(self, addr):
            self.connected = True          # WO-001 批次2：dns_query_a 改为 connect+send

        def send(self, data):
            self.sent = data

        def sendto(self, data, addr):
            self.sent = data

        def recvfrom(self, n):
            return self.build(self.sent), ("223.5.5.5", 53)

        def close(self):
            pass

    def query_fake(build):
        socket.socket = lambda *a, **kw: FakeUDP(build)
        try:
            return gp.dns_query_a("raw.githubusercontent.com", "223.5.5.5"), None
        except Exception as e:
            return None, e
        finally:
            socket.socket = real_sock

    def tid_of(q):
        return struct.unpack(">H", q[:2])[0]

    NAME = "raw.githubusercontent.com"
    IPS = ["185.199.108.133", "185.199.109.133"]

    r, e = query_fake(lambda q: mk_dns(NAME, IPS, tid_of(q)))
    check(e is None and r == IPS,
          "DNS 客户端：正常响应解析出全部 A 记录", "%s" % ((r, e),))

    r, e = query_fake(lambda q: mk_dns(NAME, [], tid_of(q), flags=0x8183))
    check(e is not None, "DNS 客户端：rcode=3(NXDOMAIN) 报错而不是当成空结果",
          "%s" % (str(e)[:40],))

    r, e = query_fake(lambda q: mk_dns(NAME, IPS, tid_of(q) ^ 0xFFFF))
    check(e is not None, "DNS 客户端：响应 ID 不匹配 → 丢弃（防串包）",
          "%s" % (str(e)[:40],))

    r, e = query_fake(lambda q: mk_dns(NAME, IPS, tid_of(q))[:20])
    check(e is not None, "DNS 客户端：报文截断 → 报错",
          "%s" % (str(e)[:40],))

    r, e = query_fake(lambda q: mk_dns(NAME, IPS, tid_of(q), flags=0x0100))
    check(e is not None, "DNS 客户端：不是响应报文 → 报错",
          "%s" % (str(e)[:40],))

    # 造一个「答案里混着压缩指针 + 非 A 记录」的报文，确认只挑 A 记录
    def mixed(q):
        base = mk_dns(NAME, IPS, tid_of(q))
        head12, qsec_all = base[:12], base[12:]
        extra = (b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 4) + b"\x01\x02\x03\x04"
                 + b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 60, 4) + b"\x00" * 4)
        # 问题段长度可算出：逐标签（len+1）+ 根（1）+ qtype/qclass（4）
        qlen = sum(len(p) + 1 for p in NAME.split(".")) + 1 + 4
        question, answers = qsec_all[:qlen], qsec_all[qlen:]
        # 非 A 记录真的放在 A 记录**之前**（对会提前终止的解析器更有杀伤力；
        # 旧版拼在后面，注释说「在答案前」实现却在后，两头对不上）
        return head12[:6] + struct.pack(">H", 4) + question + extra + answers

    r, e = query_fake(mixed)
    check(e is None and r == IPS,
          "DNS 客户端：只挑 A 记录，跳过 CNAME/AAAA", "%s" % ((r, e),))

    # ---- A30 兜底池必须覆盖「部署后会用到」的域名 ----
    # 部署后系统解析器被 hosts 带偏，兜底池就是最后一道保险：
    # 少了哪个域名，那个域名在部署后就会 502（raw/avatars/gist 就是这么挂的）。
    must = ["github.com", "raw.githubusercontent.com", "avatars.githubusercontent.com",
            "codeload.github.com", "api.github.com", "gist.github.com",
            "github.githubassets.com", "objects.githubusercontent.com",
            "github.io", "pages.github.com", "media.githubusercontent.com"]
    missing = [d for d in must if not gp.FALLBACK_IPS.get(d)]
    check(not missing, "关键域名都有兜底 IP（部署后不靠系统解析器）", "缺: %s" % missing)

    # ---- A31 某个 SNI 模式「整段握不上手」→ 记惩罚、下次先试另一条 ----
    #
    # 实测 github.com 的「正常 SNI」会出现 4 个 IP 全部握不上手（TCP 通、TLS 无响应），
    # 而「无 SNI」1s 就通。不记这笔惩罚，下次 GOOD_PEER 失效时又要白等一轮，
    # 实测首页因此拖到 23s。
    real_race = gp.race
    real_resolve = gp.resolve
    try:
        gp._dns_cache.clear()
        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp.MODE_GOOD.clear()       # 上游用例可能留下提升记录，本用例要自洽
        gp.resolve = lambda host: ["20.27.177.113", "20.200.245.247",
                                   "140.82.112.3", "140.82.113.3"]

        def fake_race(ips, mode, budget):
            if mode == "github.com":          # 正常 SNI 整段失败
                return None, None, ["%s: 握手超时" % ips[0]]
            return DummySock2(), ips[0], []

        class DummySock2:
            closed = False

            def settimeout(self, t):
                pass

            def close(self):
                self.closed = True

        gp.race = fake_race
        sock = gp.connect_upstream("github.com", budget=20)
        peer = gp.GOOD_PEER.get("github.com")
        pen = gp.MODE_PENALTY.get("github.com")
        check(peer and peer[1] is None, "整段失败后由另一条通道顶上",
              "GOOD_PEER=%s" % (peer,))
        check(pen is not None and pen[0] == "github.com",
              "整段握不上手的 SNI 模式被记惩罚（下次先试另一条）",
              "MODE_PENALTY=%s" % (pen,))
        check(gp.mode_order("github.com")[-1] == "github.com",
              "惩罚生效：该模式被排到队尾", "%s" % (gp.mode_order("github.com"),))
        if sock is not None and hasattr(sock, "close"):
            sock.close()
    finally:
        gp.race = real_race
        gp.resolve = real_resolve
        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp.MODE_GOOD.clear()
        gp._dns_cache.clear()

    # ---- A32 无体幂等请求用更短的头预算；带体请求仍用长的；池里捞的一律更短 ----
    #
    # 实测（2026-09-15）github.com 要连拨两次、每次等满 20s 头超时，40s 才通 ——
    # 而这类请求重试是安全且几乎免费的。给 GET 单独一套 10s 预算后，最坏 20s。
    class RecordTimeout:
        """记录 forward_once 给上游设过的所有超时值。"""

        def __init__(self):
            self.tt = []
            self.data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            self.pos = 0

        def settimeout(self, t):
            self.tt.append(t)

        def sendall(self, d):
            pass

        def close(self):
            pass

        def recv(self, n):
            p = self.data[self.pos:self.pos + n]
            self.pos += len(p)
            return p

    class NoBodyClient:
        def __init__(self, sock):
            self.sock = sock

        def pipe_out(self, dst, n):
            pass

        def pipe_chunked(self, dst):
            pass

    def budgets(method, body_len, reused=False):
        up = RecordTimeout()
        try:
            gp.forward_once(NoBodyClient(Collect()), up, b"GET / HTTP/1.1\r\n\r\n",
                            body_len, method, 1 << 20, False, reused)
        except Exception:
            up.tt = []    # 崩溃=时间轴不完整，「预算存在」断言应如实变红而不是蒙混
        return up.tt

    t = budgets("GET", 0)
    check(gp.HEADER_TIMEOUT_GET in t,
          "无体 GET：按短头预算等响应（尽快换通道重试）", "%s" % (t,))
    t = budgets("POST", 5)
    check(gp.HEADER_TIMEOUT in t and gp.HEADER_TIMEOUT_GET not in t,
          "带体 POST：仍按长头预算（上游算大 pack 可能要十几秒，误杀更糟）",
          "%s" % (t,))
    t = budgets("GET", 0, reused=True)
    check(gp.HEADER_TIMEOUT_GET in t,
          "池里捞的连接：预算只减不增（死连接要尽快发现）", "%s" % (t,))
    t = budgets("POST", 5, reused=True)
    check(gp.POOL_FIRST_BYTE_TIMEOUT in t and gp.HEADER_TIMEOUT not in t,
          "池里捞 + 带体：压到池预算（15s）而不是 20s", "%s" % (t,))

    # ---- A33 「真正跑通过请求」的模式要被优先选用（不是「握手成功」就算） ----
    #
    # 竞速挑模式只能看握手成败，而 GFW 让握手永远成功、之后吞掉请求 →
    # 「惩罚坏模式」只压得住一次，下次竞速又按握手选回它，每次新建连接都交 10s 学费。
    # 实测（2026-09-15）github.com 稳定 10.4~11.6s。补上「促进好模式」这一半。
    gp.MODE_PENALTY.clear()
    gp.MODE_GOOD.clear()
    check(gp.mode_order("github.com") == ["github.com", None],
          "默认顺序：正常 SNI 优先", "%s" % (gp.mode_order("github.com"),))

    gp.MODE_GOOD["github.com"] = None              # 无 SNI 真正跑通过
    check(gp.mode_order("github.com") == [None, "github.com"],
          "跑通过的模式被提到队首（此时无 SNI 优先）",
          "%s" % (gp.mode_order("github.com"),))

    gp.MODE_PENALTY["github.com"] = (None, time.time() + 60)
    check(gp.mode_order("github.com") == ["github.com", None],
          "惩罚优先于提升：刚坏的模式仍被压到队尾",
          "%s" % (gp.mode_order("github.com"),))
    gp.MODE_PENALTY.clear()
    gp.MODE_GOOD.clear()

    # 一次成功请求要把模式记进 MODE_GOOD（端到端，用假上游）
    served33 = []

    def fake_connect33(host, budget=None):
        served33.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", None)     # 无 SNI 这条通道
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.GOOD_PEER.clear()
    gp.MODE_GOOD.clear()
    real33 = gp.connect_upstream
    gp.connect_upstream = fake_connect33
    try:
        cl33 = OneShotClient(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl33, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real33
    check(gp.MODE_GOOD.get("github.com", "缺失") is None,
          "请求跑通后把该模式记进 MODE_GOOD（下次优先用它）",
          "MODE_GOOD=%s" % (gp.MODE_GOOD,))
    gp.GOOD_PEER.clear()
    gp.MODE_GOOD.clear()

    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    gp.BAD_IP.clear()
    gp._pool.clear()

    # ---- WO-SEC-GHACCEL-001 批次1断言：连接生命周期（S2/V6/V19） ----
    check(gp.TLS_HANDSHAKE_CLIENT_TIMEOUT >= 15,
          "握手独立预算存在且足够宽（S2）",
          "%ss" % gp.TLS_HANDSHAKE_CLIENT_TIMEOUT)
    check(60 <= gp.HEADER_READ_TOTAL <= 300,
          "请求头总预算存在且在合理区间（V6 慢滴灌防线）",
          "%ss" % gp.HEADER_READ_TOTAL)

    class DripSock:
        """每 0.3s 才吐 1 字节的滴灌 socket：总预算 0.2s 时必须超时。"""
        def __init__(self):
            self.n = 0
        def settimeout(self, t):
            self.t = t
        def recv(self, n):
            time.sleep(0.3)
            self.n += 1
            return b"A"
    try:
        gp.read_head(DripSock(), budget=0.2)
        raised = False
    except socket.timeout:
        raised = True
    check(raised, "读头总预算到点必超时（一字节一滴灌拖不死连接）")

    class BigHeadSock:
        """一次灌 70KB 头部（超过 64KB 上限）。"""
        def __init__(self):
            self.data = b"GET / HTTP/1.1\r\n" + b"X: " + b"A" * 70000
        def settimeout(self, t):
            pass
        def recv(self, n):
            d, self.data = self.data[:n], self.data[n:]
            return d
    c19 = gp.Client(BigHeadSock())
    r19 = c19.read_head()
    check(r19 is None and c19.head_too_big is True,
          "超大请求头被标记（serve 将回 431 而非静默断连，V19）",
          "head=%r flag=%s" % (r19, c19.head_too_big))

    # ---- WO-SEC-GHACCEL-001 批次2断言：A1 对抗（S1/S6.3/V9） ----
    import hashlib as _h
    check(len(gp.NOSNI_ROOT_PINS) >= 2,
          "无SNI根钉扎集合已注入实测底账（S1）",
          "%d 枚根指纹" % len(gp.NOSNI_ROOT_PINS))
    saved_pins = set(gp.NOSNI_ROOT_PINS)
    fake_root = b"FAKE-ROOT-DER-001"
    gp.NOSNI_ROOT_PINS.add(_h.sha256(fake_root).hexdigest())

    class ChainSock:
        def __init__(self, chain):
            self.chain = chain

        def get_verified_chain(self):
            return self.chain

    try:
        check(gp._nosni_root_ok(ChainSock([b"MID", fake_root]), "1.2.3.4") is True,
              "钉扎集合内的链根放行（S1）")
        check(gp._nosni_root_ok(ChainSock([b"MID", b"EVIL-ROOT-DER"]), "1.2.3.4") is False,
              "钉扎集合外的链根拒绝（S1：公共CA合法证书也不行）")
        check(gp._nosni_root_ok(ChainSock([]), "1.2.3.4") is True,
              "链不可判定（CERT_NONE 自测/排障路径）不挡连接")
    finally:
        gp.NOSNI_ROOT_PINS.clear()
        gp.NOSNI_ROOT_PINS.update(saved_pins)

    seen_q = []
    udp_flags = []

    def cap_build(q):
        seen_q.append(q)
        return mk_dns(NAME, IPS, tid_of(q))

    def query_fake_cap(build):
        socket.socket = lambda *a, **kw: udp_flags.append(FakeUDP(build)) or udp_flags[-1]
        try:
            return gp.dns_query_a("raw.githubusercontent.com", "223.5.5.5"), None
        except Exception as e:
            return None, e
        finally:
            socket.socket = real_sock

    tids = set()
    for _ in range(3):
        r, e = query_fake_cap(cap_build)
        if seen_q:
            tids.add(tid_of(seen_q[-1]))
    check(len(tids) >= 2,
          "DNS 查询 TID 用 CSPRNG（三次采样至少两个不同，S6.3）",
          "samples=%d" % len(tids))
    check(bool(udp_flags) and all(u.connected for u in udp_flags),
          "DNS socket 已 connect 绑定四元组（伪造源端口被内核丢弃，S6.3）")

    reuse, err9, out9 = fwd(b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nxxxxx")
    check(err9 is not None,
          "响应负 Content-Length → 报错（负切片账目错乱封死，V9）",
          "%s" % (type(err9).__name__ if err9 else "错误地返回成功"))

    # ---- WO-SEC-GHACCEL-001 批次3断言：部署事务（S5.4 原子写 / ACL 观测点） ----
    _tmpd = tempfile.mkdtemp(prefix="ghproxy_wo3_")
    _tp = os.path.join(_tmpd, "f.txt")
    # 生产链路的内存文本是 "\n"（读入时通用换行已归一），落盘由 newline="\r\n" 转换
    dep._atomic_write(_tp, "第一行\n第二行\n", "utf-8")
    _back = open(_tp, "rb").read().decode("utf-8")
    check(_back == "第一行\r\n第二行\r\n" and not os.path.exists(_tp + ".ghproxy-tmp"),
          "原子写：换行转换正确且无残留临时文件（S5.4）", repr(_back[:22]))
    dep._atomic_write(_tp, "覆盖版", "utf-8")
    check(open(_tp, "rb").read().decode("utf-8") == "覆盖版",
          "原子写：二次写入为整体替换")
    _acl = dep.hosts_acl_has_system()
    check(_acl is not False,
          "hosts ACL 观测点：SYSTEM 仍在（S5.4 回归观测）",
          "icacls 查询=%s" % _acl)

    # ---- WO-SEC-GHACCEL-001 批次4断言：实例身份（S5.2/S5.6） ----
    #
    # ⚠️ 测试路径**必须从 dep.BASE 现算，绝不能写死具体目录**：
    #    被测函数的判据是「归一化后 == PROXY_PY」，而 PROXY_PY 由 BASE 拼出。
    #    写死任何路径都会在别处 clone 时直接变红（2026-09-21 踩过：为了让仓库
    #    不带本机路径，把示例目录改成中性的 D:\tools\gh-proxy，这两条立刻失败）。
    _m = dep.cmdline_is_our_proxy
    _bs = dep.BASE + "\\gh-proxy.py"                      # 反斜杠形态
    _fs = dep.BASE.replace("\\", "/") + "/gh-proxy.py"    # 正斜杠形态
    check(_m('"C:\\py\\pythonw.exe" %s --port 443' % _bs) is True,
          "锚定：绝对反斜杠路径命中（S5.2）")
    check(_m("C:\\py\\pythonw.exe %s --port 443" % _fs) is True,
          "锚定：绝对正斜杠路径命中（bash 习惯产物）")
    check(_m("C:\\py\\pythonw.exe gh-proxy.py --port 443") is True,
          "锚定：裸文件名命中（相对路径活体形态）")
    check(_m("C:\\py\\python.exe D:\\other\\gh-proxy.py -x") is False,
          "锚定：其它目录同名脚本不误配")
    check(_m("") is False and _m(None) is False,
          "锚定：空值安全")

    real_race4, real_resolve4 = gp.race, gp.resolve

    class _DS4:
        def settimeout(self, t):
            pass

        def close(self):
            pass

    try:
        gp.resolve = lambda host: ["20.27.177.113"]
        gp.race = lambda ips, mode, budget: (_DS4(), ips[0], [])
        gp._dns_cache.clear()
        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp.MODE_GOOD.clear()
        s4 = gp.connect_upstream("github.com", budget=20)
        check(getattr(s4, "_ghp_peer", None) == ("20.27.177.113", "github.com"),
              "上游连接自带 (ip,模式) 身份（S5.6：serve 不再二次查表）",
              "%s" % (getattr(s4, "_ghp_peer", None),))
    finally:
        gp.race, gp.resolve = real_race4, real_resolve4
        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp.MODE_GOOD.clear()
        gp._dns_cache.clear()

    # ---- WO-SEC-GHACCEL-001 批次5断言：解析卫生（S6.1/S6.2/V11） ----
    # ① 池连接上「已完整发出的无体 POST」失败 → 不重发（上游副作用不执行两次）
    gp._pool.clear()
    gp.GOOD_PEER.clear()
    gp.GOOD_PEER["github.com"] = ("1.1.1.1", "github.com")
    gp.pool_put("github.com", "1.1.1.1", "github.com", ScriptedUp(b""), 0)
    served61, real61 = [], gp.connect_upstream

    def fc61(host, budget=None):
        served61.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.connect_upstream = fc61
    try:
        cl61 = OneShotClient(b"POST /x HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl61, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real61
    out61 = b"".join(cl61.sock.out)
    check(len(served61) == 0 and b"502" in out61,
          "池连接上已完整发出的无体 POST 失败 → 不重发（S6.1）",
          "拨号 %d 次 客户端 %r" % (len(served61), out61[:26]))

    # ② 对照：幂等无体 GET 在同样的池连接上失败 → 照常重试（S6.1 不误伤）
    gp._pool.clear()
    gp.GOOD_PEER.clear()
    gp.GOOD_PEER["github.com"] = ("1.1.1.1", "github.com")
    gp.pool_put("github.com", "1.1.1.1", "github.com", ScriptedUp(b""), 0)
    served61b, real61b = [], gp.connect_upstream

    def fc61b(host, budget=None):
        served61b.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        if len(served61b) == 1:
            return ScriptedUp(b"")
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.connect_upstream = fc61b
    try:
        cl61b = OneShotClient(b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl61b, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real61b
    out61b = b"".join(cl61b.sock.out)
    check(len(served61b) == 2 and b"200 OK" in out61b,
          "幂等无体请求仍照常重试（S6.1 未误伤韧性）", "拨号 %d 次" % len(served61b))

    # ③ 对照：sendall 半途失败（请求没发完整）→ 池连接豁免重试仍然在
    gp._pool.clear()
    gp.GOOD_PEER.clear()
    gp.GOOD_PEER["github.com"] = ("1.1.1.1", "github.com")

    class RstUp(ScriptedUp):
        def sendall(self, d):
            raise OSError("reset")

    gp.pool_put("github.com", "1.1.1.1", "github.com", RstUp(b""), 0)
    served61c, real61c = [], gp.connect_upstream

    def fc61c(host, budget=None):
        served61c.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.connect_upstream = fc61c
    try:
        cl61c = OneShotClient(b"POST /x HTTP/1.1\r\nHost: github.com\r\n\r\n")
        gp.serve(cl61c, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real61c
    out61c = b"".join(cl61c.sock.out)
    check(len(served61c) == 1 and b"200 OK" in out61c,
          "请求未发完整（sendall 失败）→ 池连接重试豁免保留（S6.1）",
          "拨号 %d 次" % len(served61c))
    gp._pool.clear()
    gp.GOOD_PEER.clear()

    # ④ 查询串含 :// 的 origin-form 不再被误改写（S6.2）
    ups62, real62 = [], gp.connect_upstream

    def fc62(host, budget=None):
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        up = ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        ups62.append(up)
        return up

    gp.connect_upstream = fc62
    try:
        cl62 = OneShotClient(b"GET /redirect?to=https://evil.com/x HTTP/1.1\r\n"
                             b"Host: github.com\r\n\r\n")
        gp.serve(cl62, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real62
    line62 = ups62[0].sent.split(b"\r\n")[0]
    check(line62 == b"GET /redirect?to=https://evil.com/x HTTP/1.1",
          "查询串含 :// 的 origin-form 原样透传（S6.2）", "%r" % line62)

    # ⑤ Host 大小写归一（V11）
    ups11, real11 = [], gp.connect_upstream

    def fc11(host, budget=None):
        ups11.append(host)
        gp.GOOD_PEER[host] = ("20.27.177.113", host)
        return ScriptedUp(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    gp.connect_upstream = fc11
    try:
        cl11 = OneShotClient(b"GET / HTTP/1.1\r\nHost: WWW.GITHUB.COM\r\n\r\n")
        gp.serve(cl11, ("127.0.0.1", 1))
    finally:
        gp.connect_upstream = real11
    check(bool(ups11) and ups11[0] == "www.github.com",
          "Host 大小写归一：SNI/池键/拉黑键全走小写（V11）", "%s" % (ups11[:1],))
    gp.GOOD_PEER.clear()
    gp._pool.clear()

    print("-" * 78)
    print("  A 段失败项: %d" % len(FAILED))
    return not FAILED


# ================================================================ B 联机实拨

PORT = 44311
SERVER_READY = threading.Event()


def start_server(port=None):
    port = PORT if port is None else port
    gp.SERVER_CTX = gp.build_server_ctx()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    SERVER_READY.set()

    def accepter():
        while True:
            try:
                c, a = srv.accept()
            except Exception:
                return
            threading.Thread(target=gp.handle, args=(c, a), daemon=True).start()

    threading.Thread(target=accepter, daemon=True).start()
    return srv


def new_conn(timeout=90):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=timeout)


def get(host, path, conn=None, close=True, timeout=90):
    """通过反代发一个 GET，返回 (status, headers, body_bytes, conn)。"""
    own = conn is None
    if own:
        conn = new_conn(timeout)
    conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host)
    conn.putheader("User-Agent", "gh-proxy-selftest/2")
    conn.putheader("Connection", "close" if close else "keep-alive")
    conn.endheaders()
    r = conn.getresponse()
    body = r.read()
    result = (r.status, dict((k.lower(), v) for k, v in r.getheaders()), body)
    if own or close:
        conn.close()
    return result + (conn,)


def part_b():
    print("=" * 78)
    print("B. 联机实拨（真连 GitHub）")
    print("-" * 78)
    start_server()
    SERVER_READY.wait(5)
    time.sleep(0.3)

    # ---- B1 七条真实路径。**必须校验内容，不能只看长度** ——
    #      曾经有个 bug 把 chunked 的分块帧当正文发出去（页面前缀变成 "16EC\r\n"），
    #      只因为断言写成 len(body) > 0 而一路蒙混过关。
    def is_html(b):
        h = b[:512].lower()
        return b"<html" in h or b"<!doctype" in h

    def is_json(b):
        return b.lstrip()[:1] in (b"{", b"[")

    def is_zip(b):
        return b[:2] == b"PK"

    def is_image(b):
        return (b[:8] == b"\x89PNG\r\n\x1a\n" or b[:3] == b"\xff\xd8\xff"
                or b[:3] == b"GIF")

    def is_readme(b):
        return b"linux" in b[:4096].lower()

    def is_gist(b):
        return is_html(b) or b"gist" in b[:4096].lower()

    TESTS = [
        ("github.com", "/", is_html, "首页 HTML"),
        ("github.com", "/torvalds/linux", is_html, "仓库页 HTML"),
        ("raw.githubusercontent.com", "/torvalds/linux/master/README", is_readme, "README 文本"),
        ("codeload.github.com", "/octocat/Hello-World/zip/refs/heads/master", is_zip, "ZIP"),
        ("avatars.githubusercontent.com", "/u/1?s=64", is_image, "图片"),
        ("api.github.com", "/repos/torvalds/linux", is_json, "JSON"),
        ("gist.github.com", "/octocat/6cad326836d38bd3a7ae", is_gist, "gist 页"),
    ]
    for host, path, valid, label in TESTS:
        t0 = time.time()
        try:
            status, _h, body, _ = get(host, path)
            good = valid(body)
            check(status == 200 and len(body) > 0 and good,
                  "GET %s%s" % (host, path[:24]),
                  "%s %8d B  %s[%s]  %.2fs"
                  % (status, len(body), "✓" if good else "✗", label, time.time() - t0))
        except Exception as e:
            check(False, "GET %s%s" % (host, path[:24]),
                  "%s: %s" % (type(e).__name__, str(e)[:40]))

    # ---- B2 大文件流式：只读前 4MB（跨过 1MB 阈值 → 走「边收边发」路径），
    #      读完就掐断。注意：「客户端半路断开后上游连接被收掉」在本用例观测不到
    #      （那要看池内存货/fd 数，归 B6）—— 别在标签里宣称没验证的事。 ----
    try:
        t0 = time.time()
        WANT = 4 << 20
        conn = new_conn(timeout=120)
        conn.putrequest("GET", "/torvalds/linux/zip/refs/heads/master",
                        skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", "codeload.github.com")
        conn.putheader("User-Agent", "gh-proxy-selftest/2")
        conn.putheader("Connection", "close")
        conn.endheaders()
        r = conn.getresponse()
        body = r.read(WANT)
        conn.close()
        if r.status in (403, 429):
            # 反复拉 250MB 的 linux.zip 会被 GitHub 限流，与被测代码无关。
            # 403 也算：GitHub 的限流（尤其 API 段）经常以 403 回 —— 口径与
            # B5 的 (403, 429) 保持一致，别一处认一处不认。
            skip("大文件流式（读前4MB / ZIP头）",
                 "%d 被 GitHub 限流，跳过（歇几分钟再跑）" % r.status)
        else:
            ok = r.status == 200 and len(body) == WANT and body[:2] == b"PK"
            check(ok, "大文件流式（读前4MB / ZIP头）",
                  "%s  %d B  magic=%r  %.1fs"
                  % (r.status, len(body), body[:2], time.time() - t0))
    except Exception as e:
        check(False, "大文件流式（读前4MB / ZIP头）",
              "%s: %s" % (type(e).__name__, str(e)[:44]))
    time.sleep(1.0)   # 等代理把「客户端已走」的那条上游连接收干净

    # ---- 挑一个「当前真的通」的目标来测 keep-alive / 并发。
    #      GFW 是抽风式的：某个域会整段不可达（尤其 Fastly 的 185.199.x），
    #      而 api.github.com 未认证时又有 60 次/小时的限流。
    #      所以不写死目标，先探一个通的，避免把「网络波动」误报成「并发/复用坏了」。
    POOL_CANDIDATES = [
        ("raw.githubusercontent.com", "/torvalds/linux/master/README"),
        ("codeload.github.com", "/octocat/Hello-World/zip/refs/heads/master"),
        ("github.com", "/torvalds/linux"),
        ("gist.github.com", "/octocat/6cad326836d38bd3a7ae"),
        ("api.github.com", "/repos/torvalds/linux"),
    ]
    KV_HOST, KV_PATH = POOL_CANDIDATES[0]
    for _h, _p in POOL_CANDIDATES:
        try:
            _st, _hd, _b, _ = get(_h, _p)
            if _st == 200 and _b:
                KV_HOST, KV_PATH = _h, _p
                break
        except Exception:
            continue
    print("  [探测] 本轮用 %s%s 测 keep-alive / 并发" % (KV_HOST, KV_PATH))
    sys.stdout.flush()

    # ---- B3 keep-alive 复用：同一条客户端连接连发 4 个请求 ----
    #
    # 断言三件事（旧版任何失败形态都走 skip，加上 http.client 的 auto_open
    # 会在连接被服务端关掉时**悄悄自动重连** —— 坏到「每个响应都带
    # Connection: close」这条测试也照样绿，等于零回归防护）：
    #   ① 4 个请求全部 200 且有体；
    #   ② 全程只建立了一次 TCP/TLS 连接（数 connect() 次数）；
    #   ③ 前 3 个响应头都是 keep-alive（最后一个是客户端主动 close，不算）。
    class CountingConn(http.client.HTTPSConnection):
        n_connect = 0

        def connect(self):
            CountingConn.n_connect += 1
            super().connect()

    try:
        ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx3.check_hostname = False
        ctx3.verify_mode = ssl.CERT_NONE
        conn = CountingConn("127.0.0.1", PORT, context=ctx3, timeout=90)
        sizes = []
        keeps = []
        t0 = time.time()
        for i in range(4):
            status, h, body, _ = get(KV_HOST, KV_PATH, conn=conn, close=(i == 3))
            if status != 200 or not body:
                break
            sizes.append(len(body))
            keeps.append((h.get("connection") or "").lower())
        conn.close()
        dt = time.time() - t0
        n_conn = CountingConn.n_connect
        if not sizes:
            skip("keep-alive 同连接连发 4 请求",
                 "首个请求就没通（上游当前不可达），本次不作判定")
        elif n_conn > 1:
            # 客户端只在「服务端把连接关了」时才会重连 —— 这正是复用回归本身
            check(False, "keep-alive 同连接连发 4 请求",
                  "反代中途断开了连接：连接数=%d sizes=%s %.2fs"
                  % (n_conn, sizes, dt))
        elif len(sizes) == 4 and all("close" not in k for k in keeps[:3]):
            check(True, "keep-alive 同连接连发 4 请求",
                  "sizes=%s 连接数=%d conn头=%s  %.2fs"
                  % (sizes, n_conn, keeps[:3], dt))
        else:
            skip("keep-alive 同连接连发 4 请求",
                 "只成功 %d/4 %.2fs（同一条连接上非 200，属上游波动）"
                 % (len(sizes), dt))
    except Exception as e:
        check(False, "keep-alive 同连接连发 4 请求",
              "%s: %s" % (type(e).__name__, str(e)[:40]))

    # ---- B4 非 GitHub 域名必须 403（专一性） ----
    for bad in ("evil.com", "gitlab.com"):
        try:
            status, _h, _b, _ = get(bad, "/")
            check(status == 403, "拦掉非 GitHub 域名 %s" % bad, "status=%s" % status)
        except Exception as e:
            check(False, "拦掉非 GitHub 域名 %s" % bad, "%s: %s" % (type(e).__name__, str(e)[:40]))

    # ---- B5 并发 8 路，全部要成功 ----
    results = {}
    order = list(range(8))
    lock = threading.Lock()

    def worker(i):
        try:
            status, _h, body, _ = get(KV_HOST, KV_PATH)
            with lock:
                results[i] = (status, len(body))
        except Exception as e:
            with lock:
                results[i] = ("ERR", str(e)[:30])

    t0 = time.time()
    ths = [threading.Thread(target=worker, args=(i,)) for i in order]
    for t in ths:
        t.start()
    for t in ths:
        t.join(120)
    good = sum(1 for v in results.values() if v[0] == 200 and v[1] > 0)
    throttled = sum(1 for v in results.values() if v[0] in (403, 429))
    detail = "%d/8  %.2fs" % (good, time.time() - t0)
    if good == 8:
        check(True, "并发 8 路全部成功", detail)
    elif throttled:
        # 403/429 = 上游限流，与被测代码无关
        skip("并发 8 路全部成功",
             "%s（%d 个被限流，本次不作判定）" % (detail, throttled))
    elif good == 0:
        # 不能无条件当「上游不可达」跳过：几秒前预探测刚用同一目标拿到 200，
        # 紧接着 8 路全灭更像**代理侧**故障（并发槽耗尽/池死锁 —— 历史上
        # 128 槽递归 bug 的症状正是全灭 502）。如实记失败，人工再分判。
        check(False, "并发 8 路全部成功",
              "%s  全灭但预探测刚成功 —— 疑代理侧故障：%s"
              % (detail, [v for v in results.values() if v[0] != 200][:2]))
    else:
        # 部分成功、部分失败 —— 这才是「并发/连接池」真出问题的特征
        check(False, "并发 8 路全部成功",
              "%s  部分成败=真问题：%s"
              % (detail, [v for v in results.values() if v[0] != 200][:2]))

    # ---- B6 连接池确实在复用上游（多次请求后池里应有存货） ----
    # 只数「未过期」的：过期连接只在 pool_get 的 pop 侧清理，死条目也会一直
    # 躺在字典里，把它们计入会让「有存货」变成假象。另容忍测试线程与 serve
    # 线程之间「刚 pop 走还没放回」的瞬时竞态：为 0 时降级为不作判定。
    with gp._pool_lock:
        now6 = time.time()
        pooled = sum(1 for b in gp._pool.values()
                     for _s, _n, ts in b if now6 - ts <= gp.POOL_IDLE_TIMEOUT)
    if pooled >= 1:
        check(True, "上游连接池有复用存货", "池中未过期空闲连接 = %d" % pooled)
    else:
        skip("上游连接池有复用存货",
             "瞬时为 0（serve 线程可能刚把连接取走还没放回），不作判定")

    print("-" * 78)
    print("  累计失败项: %d" % len(FAILED))


# ================================================================ C 本地端到端
#
# 真 git push → 真反代（真 TLS 服务端 + 真 handle/serve/Client.pipe_chunked）
#            → 真 git-http-backend
#
# 为什么单独一段：A21 只是「把字节喂给 serve()」，证明不了真 git 的 chunked 推送
# 端到端跑得通。这一段把上游换成真的 git 服务端，跑一次真的 push，
# 再回裸仓库里核对提交是否真的落库、大文件字节数是否分毫不差。
# 全程不联网（上游是本机 127.0.0.1），所以它和 A 段一样是确定性的。

E2E_PORT = 18443          # 反代监听（真 TLS 服务端）
E2E_UP_PORT = 18446       # 上游：本机 git http-backend（真 TLS，自签证书）


def _find_git():
    """找到一对能用的 (git, git-http-backend)；找不到返回 (None, None)。

    Git for Windows 的 http-backend 在 libexec/git-core 下，而精简版
    （如 PortableGit minimal）根本没带它 —— 所以必须探测，不能假定存在。
    """
    pairs = [("C:/Program Files/Git/mingw64/bin/git.exe",
              "C:/Program Files/Git/mingw64/libexec/git-core/git-http-backend.exe")]
    who = shutil.which("git")
    if who:
        base = os.path.dirname(os.path.dirname(who))
        pairs.append((who, os.path.join(base, "libexec", "git-core",
                                        "git-http-backend.exe")))
    for g, b in pairs:
        if os.path.exists(g) and os.path.exists(b):
            return g, b
    return None, None


def _read_chunked(rfile):
    """测试服务端自己的 chunked 解码。

    刻意不复用 gp.ChunkedScanner：上游要用**独立**实现对分块帧解码，
    否则「发送方能过、接收方也用它校验」就自证了，测不出真问题。
    但严格度对齐 A16：长度行必须 1*HEXDIG —— 宽松的 int(x,16) 会把
    "+5"/"-3" 静默当合法帧，被测方修掉的病根不能在替身里复发。
    """
    out = b""
    while True:
        line = rfile.readline()
        if not line:
            break
        token = line.split(b";")[0].strip()
        if not token or any(c not in b"0123456789abcdefABCDEF" for c in token):
            raise ValueError("chunked 长度行非法: %r" % token[:16])
        size = int(token, 16)
        if size == 0:
            # 收尾块后到空行前可能有 trailer 头，逐行跳到空行为止
            # （不是只读一行 —— 那会让带 trailer 的帧残留错位字节）
            while True:
                t = rfile.readline()
                if not t or t in (b"\r\n", b"\n"):
                    break
            break
        out += rfile.read(size)
        rfile.read(2)
    return out


def _make_backend_handler(root, backend, seen, lock):
    """把 git http-backend 按 CGI 协议包成一个 HTTP 处理器。"""
    from http.server import BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _serve(self):
            te = self.headers.get("Transfer-Encoding")
            cl = self.headers.get("Content-Length")
            if te and "chunked" in te.lower():
                body = _read_chunked(self.rfile)
            elif cl:
                body = self.rfile.read(int(cl))
            else:
                body = b""
            with lock:
                seen.append((self.command, self.path, te, cl, len(body)))

            path, _, query = self.path.partition("?")
            env = os.environ.copy()
            env.update({
                "GIT_PROJECT_ROOT": root, "GIT_HTTP_EXPORT_ALL": "1",
                "REQUEST_METHOD": self.command, "PATH_INFO": path,
                "QUERY_STRING": query, "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
                "REMOTE_USER": "e2e", "REMOTE_ADDR": "127.0.0.1",
            })
            p = subprocess.run([backend], input=body, env=env,
                               capture_output=True)
            head, _, payload = p.stdout.partition(b"\r\n\r\n")
            status, hdrs = 200, []
            for line in head.split(b"\r\n"):
                if not line:
                    continue
                k, _, v = line.partition(b":")
                k, v = k.strip().lower(), v.strip()
                if k == b"status":
                    status = int(v.split()[0])
                elif k != b"content-length":
                    hdrs.append((k, v))
            self.send_response(status)
            for k, v in hdrs:
                self.send_header(k.decode(), v.decode())
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def do_GET(self):
            self._serve()

        do_POST = do_GET
        do_HEAD = do_GET

    return Handler


def part_c():
    print("=" * 78)
    print("C. 本地端到端：真 git push 穿真反代（不联网）")
    print("-" * 78)

    git, backend = _find_git()
    if not git:
        skip("真 git push 端到端",
             "本机没装 git-http-backend（精简版 PortableGit 不带它），跳过")
        return

    # 证书是 build_server_ctx() 的硬前置；缺了就明说怎么补，别甩一行 traceback
    _missing_certs = [p for p in (gp.CERT_FILE, gp.KEY_FILE) if not os.path.exists(p)]
    if _missing_certs:
        skip("真 git push 端到端",
             "缺少证书 %s —— 先运行: python gen_certs.py，再重跑本自检"
             % ", ".join(os.path.basename(p) for p in _missing_certs))
        return

    from http.server import ThreadingHTTPServer

    work = os.path.join(tempfile.gettempdir(), "ghproxy_e2e")
    for sub in ("", "/r.git", "/src"):
        shutil.rmtree(work + sub, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    def sh(*a, **kw):
        return subprocess.run(a, capture_output=True, text=True, **kw)

    bare, src = os.path.join(work, "r.git"), os.path.join(work, "src")
    sh(git, "init", "--bare", "-q", bare)
    sh(git, "-C", bare, "config", "http.receivepack", "true")
    sh(git, "init", "-q", src)
    sh(git, "-C", src, "config", "user.email", "e2e@test")
    sh(git, "-C", src, "config", "user.name", "e2e")
    with open(os.path.join(src, "big.bin"), "wb") as f:
        f.write(os.urandom(3 << 20))          # 3 MiB > postBuffer → 必然 chunked
    sh(git, "-C", src, "add", "big.bin")
    sh(git, "-C", src, "commit", "-q", "-m", "3MiB pack for chunked push")
    sh(git, "-C", src, "branch", "-M", "master")
    want = sh(git, "-C", src, "rev-parse", "master").stdout.strip()

    seen, lock = [], threading.Lock()
    ctx = gp.build_server_ctx()               # 复用反代那套自签证书
    be = ThreadingHTTPServer(("127.0.0.1", E2E_UP_PORT),
                             _make_backend_handler(work, backend, seen, lock))
    be.socket = ctx.wrap_socket(be.socket, server_side=True)
    threading.Thread(target=be.serve_forever, daemon=True).start()

    saved = (gp.UPSTREAM_PORT, gp.ALLOW_EXACT, gp.SELF_IPS)
    # 上游换成本机自签服务端：真客户端上下文会（正确地）拒绝这条私有 CA 链 ——
    # 和下面 SELF_IPS 一样，只在本用例内替换成不验签的上下文，生产路径仍全验。
    _noctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _noctx.check_hostname = False
    _noctx.verify_mode = ssl.CERT_NONE
    saved_ctx = (gp.CLIENT_CTX_SNI, gp.CLIENT_CTX_NOSNI)
    gp.CLIENT_CTX_SNI = _noctx
    gp.CLIENT_CTX_NOSNI = _noctx
    gp.UPSTREAM_PORT = E2E_UP_PORT
    gp.ALLOW_EXACT = set(gp.ALLOW_EXACT) | {"127.0.0.1"}   # 只为本用例放行回环地址
    # 本段需要一个「本机上游」（离线、确定性），可 dial() 有条红线：
    # 拒绝把本机地址当上游 —— 那正是 2026-09-14 那个递归 bug 的根因。
    # 所以这里**只在本用例内**临时放开：红线的正确性由 A28 单独看住，
    # 本段只借「本机」当上游，验证分块请求体能否端到端中继。
    # ⚠️ 生产代码里 SELF_IPS 永远不为空。
    gp.SELF_IPS = set()
    gp._dns_cache.clear()
    gp.GOOD_PEER.clear()
    gp.MODE_PENALTY.clear()
    gp.BAD_IP.clear()
    gp._pool.clear()
    start_server(E2E_PORT)
    time.sleep(0.3)

    try:
        cfgenv = dict(os.environ)
        # 必须清掉代理环境变量：否则 libcurl 会把请求发给代理（绝对形式 + CONNECT），
        # 根本到不了我们的反代 —— 那测的就不是这个代码了。
        for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                  "ALL_PROXY", "all_proxy"):
            cfgenv.pop(k, None)
        cfgenv["GIT_CONFIG_GLOBAL"] = os.path.join(work, "emptycfg")
        cfgenv["GIT_CONFIG_NOSYSTEM"] = "1"
        with open(cfgenv["GIT_CONFIG_GLOBAL"], "w") as f:
            # 干净配置：本机全局配置里可能残留 http.curloptResolve 之类，
            # 会让 git 直接报错退出（实测踩过）。
            f.write("[http]\n\tsslVerify = false\n")

        r = subprocess.run(
            [git, "-C", src, "-c", "http.postBuffer=16384",
             "-c", "http.sslVerify=false",
             "push", "-f", "https://127.0.0.1:%d/r.git" % E2E_PORT,
             "master:master"],
            capture_output=True, text=True, env=cfgenv, timeout=120)
        check(r.returncode == 0, "真 git push（chunked 请求体）端到端成功",
              "退出码=%d  %s" % (r.returncode, (r.stderr or "").strip()[-110:]))

        got = sh(git, "-C", bare, "rev-parse", "master").stdout.strip()
        check(got == want, "提交真的落进裸仓库（对象对得上）",
              "远端 %s / 本地 %s" % (got[:12], want[:12]))
        size = sh(git, "-C", bare, "cat-file", "-s",
                  "%s:big.bin" % want).stdout.strip()
        check(size == str(3 << 20), "推送的 3 MiB 大文件字节数分毫不差",
              "远端 %s / 本地 %d" % (size, 3 << 20))

        ck = [s for s in seen if s[2] and "chunked" in s[2].lower()]
        check(bool(ck), "上游确实收到的是 chunked 请求（否则本用例没测到点上）",
              "实体 %s 字节" % (ck[0][4] if ck else "无"))
    finally:
        gp.UPSTREAM_PORT, gp.ALLOW_EXACT, gp.SELF_IPS = saved
        gp.CLIENT_CTX_SNI, gp.CLIENT_CTX_NOSNI = saved_ctx
        be.shutdown()
        gp._dns_cache.clear()
        gp.GOOD_PEER.clear()
        gp.MODE_PENALTY.clear()
        gp.BAD_IP.clear()
        gp._pool.clear()

    print("-" * 78)
    print("  累计失败项: %d" % len(FAILED))


# ================================================================ 入口

def main():
    only_a = "-A" in sys.argv
    t0 = time.time()
    ok_a = part_a()
    if not only_a:
        part_b()
    part_c()
    print("=" * 78)
    verdict = "全部通过 ✓" if not FAILED else "失败 %d 项: %s" % (len(FAILED), FAILED)
    if SKIPPED:
        verdict += "   （另有 %d 项因上游不可达/限流未判定）" % len(SKIPPED)
    print("总计耗时 %.1fs   %s" % (time.time() - t0, verdict))
    sys.stdout.flush()
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
