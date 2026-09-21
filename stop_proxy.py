# -*- coding: utf-8 -*-
"""停掉 gh-proxy 反代进程。

红线：杀之前必须核对「PID 的进程确实是 gh-proxy.py」——
      pid 文件会过期、PID 会被系统复用，盲杀会误杀别的 python 进程。
本机教训：PowerShell 在受限上下文 exit 0 无输出，所以用 iphlpapi 拿 443 属主，
再配合映像名 + pid 文件三重交叉验证。一次性脚本，可删。
"""
import ctypes
import ctypes.wintypes as w
import os
import socket
import struct
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
PIDFILE = os.path.join(BASE, "gh-proxy.pid")
PY = sys.executable          # 本脚本当前就跑在解释器里，直接复用

_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3


class _ROW(ctypes.Structure):
    _fields_ = [("dwState", w.DWORD), ("dwLocalAddr", w.DWORD),
                ("dwLocalPort", w.DWORD), ("dwRemoteAddr", w.DWORD),
                ("dwRemotePort", w.DWORD), ("dwOwningPid", w.DWORD)]


def port_owner(port):
    try:
        iphlp = ctypes.WinDLL("iphlpapi")
        size = w.DWORD(0)
        iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, _AF_INET,
                                  _TCP_TABLE_OWNER_PID_LISTENER, 0)
        buf = ctypes.create_string_buffer(size.value)
        if iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, _AF_INET,
                                     _TCP_TABLE_OWNER_PID_LISTENER, 0) != 0:
            return None
        n = struct.unpack_from("<I", buf.raw, 0)[0]
        off, sz = 4, ctypes.sizeof(_ROW)
        for _ in range(n):
            r = _ROW.from_buffer_copy(buf.raw[off:off + sz])
            off += sz
            if socket.ntohs(r.dwLocalPort & 0xFFFF) == port:
                return int(r.dwOwningPid)
    except Exception:
        return None
    return None


def image_name(pid):
    try:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k.OpenProcess(0x1000, False, int(pid))
        if not h:
            return ""
        try:
            b = ctypes.create_unicode_buffer(4096)
            n = w.DWORD(4096)
            if k.QueryFullProcessImageNameW(h, 0, b, ctypes.byref(n)):
                return os.path.basename(b.value) or ""
        finally:
            k.CloseHandle(h)
    except Exception:
        pass
    return ""


def port_open(t=1.5):
    s = socket.socket()
    s.settimeout(t)
    try:
        s.connect(("127.0.0.1", 443))
        return True
    except Exception:
        return False
    finally:
        s.close()


def main():
    owner = port_owner(443)
    pidfile = None
    try:
        pidfile = int(open(PIDFILE).read().strip())
    except Exception:
        pass
    print("443 属主 pid = %s ; pid 文件 = %s" % (owner, pidfile))

    victims = set()
    for p in (owner, pidfile):
        if not p:
            continue
        name = image_name(p)
        print("  pid %s 映像名 = %r" % (p, name))
        # 红线核对：必须是 python/pythonw 才允许杀
        if name.lower().startswith("python"):
            victims.add(p)
        else:
            print("    [跳过] 映像名不像 python，拒绝杀（防误杀）")

    # 再叠一层：443 属主是最高优先级证据
    if owner and image_name(owner).lower().startswith("python"):
        victims = {owner}

    if not victims:
        print("没有可杀的 gh-proxy 进程。")
    for p in victims:
        print("  taskkill /PID %d /F" % p)
        r = subprocess.run([r"C:\Windows\System32\taskkill.exe", "/PID", str(p), "/F"],
                           capture_output=True, timeout=20)
        print("    rc=%d %s" % (r.returncode,
                                (r.stdout or r.stderr).decode("gbk", "replace").strip()[:70]))

    time.sleep(1.2)
    print()
    print("### 停后：443 监听 = %s（期望 False）" % port_open())
    return 0


if __name__ == "__main__":
    sys.exit(main())
