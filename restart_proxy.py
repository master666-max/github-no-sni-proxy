# -*- coding: utf-8 -*-
"""一键重启反代（需管理员）：停掉旧进程 → 用新代码重新拉起。

为什么要专门写这个：
  旧进程若是**提权**启动的，普通权限（含计划任务）杀不掉它
  —— taskkill 报「拒绝访问」，OpenProcess 报错误 5。
  所以必须由管理员上下文执行。本脚本由「重启反代.bat」以 RunAs 拉起。

用法：python restart_proxy.py
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
PY = sys.executable
PYW = PY.replace("python.exe", "pythonw.exe")
if not os.path.exists(PYW):
    PYW = PY
PROXY = os.path.join(BASE, "gh-proxy.py")
PIDFILE = os.path.join(BASE, "gh-proxy.pid")
LOGFILE = os.path.join(BASE, "gh-proxy.log")

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


def is_admin():
    try:
        return ctypes.WinDLL("shell32").IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    print("=" * 62)
    print("  GitHub 反代 · 一键重启")
    print("=" * 62)
    print("  工作目录: %s" % BASE)
    print("  解释器  : %s" % PY)
    print("  管理员  : %s" % is_admin())
    print()

    # ---- 1. 停旧进程 ----
    owner = port_owner(443)
    tried = set()
    for src, p in (("443 属主", owner), ("pid 文件", None)):
        if src == "pid 文件":
            try:
                p = int(open(PIDFILE).read().strip())
            except Exception:
                p = None
        if not p or p in tried:
            continue
        tried.add(p)
        name = image_name(p)
        print("[停] pid=%s 映像=%r（证据来源：%s）" % (p, name, src))
        if not name.lower().startswith("python"):
            print("     [跳过] 不像 python，拒绝杀（防误杀）")
            continue
        r = subprocess.run([r"C:\Windows\System32\taskkill.exe", "/PID", str(p), "/F"],
                           capture_output=True, timeout=20)
        msg = (r.stdout or r.stderr).decode("gbk", "replace").strip()
        print("     %s" % msg.splitlines()[0][:70] if msg else "     (无输出)")

    # ---- 2. 等端口释放 ----
    print()
    print("[等] 443 端口释放（最多 20s）...")
    released = False
    for i in range(40):
        if not port_open():
            released = True
            print("     第 %.1fs 已释放 ✓" % ((i + 1) * 0.5))
            break
        time.sleep(0.5)
    if not released:
        print("     [!] 端口仍被占用 —— 旧进程可能权限更高，taskkill 被拒。")
        print("         请改用「启动反代.bat」并关闭旧窗口，或注销后重来。")
        return 1

    # ---- 3. 起新实例 ----
    print()
    print("[起] pythonw gh-proxy.py --port 443")
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    try:
        subprocess.Popen(
            [PYW, PROXY, "--port", "443"],
            cwd=BASE,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL)
    except Exception as e:
        print("     [x] 启动失败: %s" % e)
        return 1

    print("[等] 443 重新监听（最多 20s）...")
    up = False
    for i in range(40):
        time.sleep(0.5)
        if port_open():
            up = True
            print("     第 %.1fs 已监听 ✓" % ((i + 1) * 0.5))
            break
    if not up:
        print("     [x] 没起来。日志尾部：")
        try:
            with open(LOGFILE, "rb") as f:
                tail = f.read()[-1200:].decode("utf-8", "replace")
            for L in tail.splitlines()[-12:]:
                print("        " + L)
        except Exception:
            pass
        return 1

    # ---- 4. 报新 pid ----
    newpid = port_owner(443)
    print()
    print("=" * 62)
    print("  ✓ 重启完成")
    print("    新 443 属主 pid = %s" % newpid)
    print("    pid 文件        = %s" % PIDFILE)
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
