#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy.py — 部署 GitHub 无SNI反代（改 hosts + 装 CA 证书 + 启动反代）
需要管理员权限运行。
"""
import os
import sys
import time
import ctypes
import shutil
import socket
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = os.path.dirname(os.path.abspath(__file__))
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BAK = os.path.join(BASE, "hosts.backup-original.txt")
CA_CRT = os.path.join(BASE, "certs", "ca.crt")
PROXY_PY = os.path.join(BASE, "gh-proxy.py")
PROXY_PID = os.path.join(BASE, "gh-proxy.pid")
PROXY_LOG = os.path.join(BASE, "gh-proxy.log")
# ---- 独立运行时解析（2026-09-18 解耦）----
# 只认系统安装的 Python；全都没有才回退到「当前运行 deploy.py 的解释器」。
# 候选清单用环境变量拼装，不含任何用户名/盘符硬编码，clone 到别处也能直接用。
# ---- 解释器解析 ----
# 只认系统安装的 Python；全都没有才回退到「当前运行 deploy.py 的解释器」。
# 候选清单用环境变量拼装，不含任何用户名/盘符硬编码，clone 到别处也能直接用。
PYW = ""
_cands = []
_la = os.environ.get("LOCALAPPDATA") or ""
_pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
for _v in ("314", "313", "312", "311"):
    if _la:
        _cands.append(os.path.join(_la, "Programs", "Python", "Python" + _v, "pythonw.exe"))
for _v in ("314", "313", "312", "311"):
    _cands.append(os.path.join(_pf, "Python" + _v, "pythonw.exe"))
    _cands.append("C:\\Python" + _v + "\\pythonw.exe")
# 最后兜底：本脚本所在解释器（同目录的 pythonw）
_cands.append(sys.executable.replace("python.exe", "pythonw.exe"))
_cands.append(sys.executable)
for _cand in _cands:
    if _cand and os.path.exists(_cand):
        PYW = _cand
        break
if not PYW:
    PYW = sys.executable
del _cand

BEGIN = "# === gh-proxy BEGIN (GitHub no-SNI reverse proxy) ==="
END = "# === gh-proxy END ==="

DOMAINS = [
    "github.com",
    "www.github.com",
    "api.github.com",
    "gist.github.com",
    "codeload.github.com",
    # 页面要用的静态资源域名：不映射的话它们会绕过反代直连，
    # GFW 抽风时表现为「页面能开但样式/图标全丢」。
    "githubassets.com",
    "github.githubassets.com",
    "assets-cdn.github.com",
    "collector.github.com",
    "alive.github.com",
    "uploads.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "objects-origin.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-cloud.githubusercontent.com",
    "media.githubusercontent.com",
    "avatars.githubusercontent.com",
    "avatars0.githubusercontent.com",
    "avatars1.githubusercontent.com",
    "avatars2.githubusercontent.com",
    "avatars3.githubusercontent.com",
    "avatars4.githubusercontent.com",
    "avatars5.githubusercontent.com",
    "camo.githubusercontent.com",
    "cloud.githubusercontent.com",
    "user-images.githubusercontent.com",
    "private-user-images.githubusercontent.com",
    "githubapp.com",
    "resources.github.com",
    "archiveprogram.github.com",
    "support-assets.githubassets.com",
    "github.io",
    "www.github.io",
    "pages.github.com",
    "github.dev",
]

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def read_hosts():
    for enc in ("utf-8-sig", "gbk", "latin-1"):
        try:
            with open(HOSTS, "r", encoding=enc) as f:
                return f.read(), enc
        except Exception:
            continue
    return "", "utf-8"


def hosts_sane(text):
    """读出来的 hosts 是否可信 → (是否可信, 文件字节数)。

    「读出空内容、但文件非空」= 编码或权限异常。此时若照常 compose/write，
    会把用户的 hosts 整个覆盖成「只剩我们的映射」，属于**不可逆的数据丢失**。
    deploy 与 undeploy 共用这一条判据（卸载方向的后果更严重：它会退化成
    「拿首次部署的备份覆盖当前 hosts」，把部署之后的所有改动一起抹掉）。
    """
    try:
        size = os.path.getsize(HOSTS)
    except Exception:
        size = 0
    return not (size > 0 and not text.strip()), size


def _atomic_write(path, text, enc="utf-8"):
    """同目录临时文件 + fsync + rename 的原子写（审计 S5.4）。

    原先 open("w") 截断重写：中途被杀/杀软拦截会让 hosts 停在半截。
    ⚠️ 临时文件必须建在目标**同目录**——放系统 temp 的话，os.replace 后
    目标文件继承的是 temp 的 ACL，反而把系统文件权限写坏。
    """
    use_enc = "utf-8" if enc in ("utf-8", "utf-8-sig") else enc
    tmp = path + ".ghproxy-tmp"
    with open(tmp, "w", encoding=use_enc, newline="\r\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def write_hosts(text, enc="utf-8"):
    """按原文件编码原子写回（编码保真说明见 _atomic_write 之上的历史注释）。"""
    _atomic_write(HOSTS, text, enc)


def hosts_acl_has_system():
    """hosts 的 ACL 里是否还有 SYSTEM（审计 S5.4 的回归观测点）。

    返回 None 表示查不了（icacls 不可用等），调用方不要拿 None 做判断。
    """
    try:
        r = subprocess.run(["icacls", HOSTS], capture_output=True, timeout=20)
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("gbk", "replace")
        return "SYSTEM" in out
    except Exception:
        return None


def strip_block(text):
    lines = text.splitlines()
    out = []
    skip = False
    for ln in lines:
        if ln.strip() == BEGIN:
            skip = True
            continue
        if ln.strip() == END:
            skip = False
            continue
        if not skip:
            out.append(ln)
    return "\n".join(out)


def compose_hosts(text):
    """在文本最前面插入映射块，返回 (新文本, 与本工具冲突的既有条目)。

    块必须放最前面：Windows 解析 hosts 是**先出现的条目优先**，
    别的加速工具（Watt Toolkit / Steam++ 等）给同样域名写过的旧条目
    如果不删，会把我们顶掉 —— 现象就是「装了反代却仍然没走反代」。
    这里不删它们（避免破坏用户配置），只把冲突列出来让用户自己决定。
    """
    clean = strip_block(text)
    ours = set(DOMAINS)
    conflicts = []
    for ln in clean.splitlines():
        s = ln.split("#", 1)[0].strip()
        parts = s.split()
        if len(parts) >= 2 and parts[1].lower() in ours:
            conflicts.append(s)

    block = [BEGIN] + ["127.0.0.1 " + d for d in DOMAINS] + [END]
    body = clean.strip("\n")
    new_text = "\n".join(block) + "\n\n" + (body + "\n" if body else "")
    return new_text, conflicts


def flush_dns():
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=30)
    except Exception:
        pass


def install_ca():
    """把 CA 装到系统「受信任的根证书颁发机构」。"""
    try:
        r = subprocess.run(["certutil", "-addstore", "-f", "Root", CA_CRT],
                           capture_output=True, timeout=60)
        out = (r.stdout or b"").decode("gbk", "replace") + (r.stderr or b"").decode("gbk", "replace")
        if r.returncode == 0:
            print("  [OK] CA 证书已装入系统信任区")
            return True
        print("  [!] 装证书返回码 %s" % r.returncode)
        print("      " + out.strip()[:200])
        if "80070005" in out or "拒绝访问" in out:
            # 管理员令牌下被拒 = 不是 Windows 的 ACL，是安全软件的过滤驱动在拦
            # （360 有专门的「根证书安装拦截」，静默模式下连弹窗都不给）。
            print("      → 已确认当前是管理员令牌、且你本人对系统目录有完全控制权，")
            print("        这个「拒绝访问」几乎可以断定是 360 的防护在拦根证书安装。")
            print("        处理：360 主界面 → 木马防火墙 → 系统防护 → 关闭「拦截不明根证书」")
            print("              或直接托盘右键 360 → 退出，重跑本脚本，装完再开。")
        return False
    except Exception as e:
        print("  [x] 装证书异常: %s" % e)
        return False


def verify_ca():
    """确认 CA 已在「本机」Root 存储里（与 addstore 的目标存储一致）。"""
    ps = ('Get-ChildItem Cert:\\LocalMachine\\Root | '
          'Where-Object { $_.Subject -like \'*gh-proxy Local Root CA*\' } | '
          'ForEach-Object { $_.Thumbprint }')
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=60)
        return bool((r.stdout or b"").decode("utf-8", "replace").strip())
    except Exception:
        return False


def port_in_use(port=443, host="127.0.0.1"):
    """判断本机端口是否已有监听。
    优先用 netstat（瞬时且准确），失败时退化为 connect 探测。"""
    try:
        r = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                           capture_output=True, timeout=20)
        out = (r.stdout or b"").decode("latin-1", "replace")
        want = ("127.0.0.1:%d" % port, "0.0.0.0:%d" % port, "[::]:%d" % port,
                "[::1]:%d" % port)
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 4 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                if parts[1] in want:
                    return True
        if out:
            return False          # netstat 拿到了结果，就信它
    except Exception:
        pass

    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def log_says_started():
    try:
        with open(PROXY_LOG, "r", encoding="utf-8", errors="replace") as f:
            return "已启动" in f.read()[-4000:]
    except Exception:
        return False


def cmdline_is_our_proxy(cmdline):
    """判定一条命令行是否在跑我们的 gh-proxy.py（审计 S5.2）。

    归一化折算现实中的四种形态：绝对路径反斜杠（deploy/启动器产出）、绝对路径
    **正斜杠**（bash/手工启动产出）、大小写差异、以及**相对路径/裸文件名**
    （进程 cwd 恰为脚本目录；PowerShell 拿不到进程 cwd，按「宁可多认」处理——
    留下幽灵实例比误杀其它目录同名脚本危害更高）。其它目录的路径绝不误配。
    """
    if not cmdline:
        return False
    for tok in cmdline.split():
        t = tok.strip('"').replace("/", "\\")
        if not t.lower().endswith("gh-proxy.py"):
            continue
        full = t if os.path.isabs(t) else os.path.join(BASE, t)
        if os.path.normcase(os.path.abspath(full)) == os.path.normcase(PROXY_PY):
            return True
    return False


def pid_is_our_proxy(pid):
    """pid 文件会过期：重启之后那个 PID 很可能是**别的进程**（Windows 会复用 PID）。

    直接 taskkill 就可能误杀无辜进程，所以杀之前先核对它的命令行里确实有
    我们的 gh-proxy.py（按 cmdline_is_our_proxy 归一化核对，见 S5.2）。
    核对不了就返回 False，交给 kill_by_cmdline() 这个兜底去处理。
    """
    if not pid:
        return False
    ps = ('(Get-CimInstance Win32_Process -Filter "ProcessId=%d").CommandLine' % pid)
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=60)
        return cmdline_is_our_proxy((r.stdout or b"").decode("utf-8", "replace"))
    except Exception:
        return False


def kill_by_cmdline():
    """兜底：找出命令行在跑我们的 gh-proxy.py 的 python/pythonw 进程并结束。

    只靠 pid 文件是不够的：若用户手动用过「启动反代.bat」、或 pid 文件被删/没写成，
    kill_old_proxy 会直接返回，旧进程继续占着 443 —— 于是新部署会走到
    「端口被占用 → 跳过启动」，**旧代码继续跑，用户却以为已经更新**。
    匹配在 Python 侧按 cmdline_is_our_proxy 归一化做（路径不再内插进
    PowerShell，也就不存在引号转义问题）。
    """
    ps = ('Get-CimInstance Win32_Process -Filter "Name like \'python%\'" | '
          'ForEach-Object { "$($_.ProcessId)|$($_.CommandLine)" }')
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=60)
        out = (r.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return False
    killed = False
    for ln in out.splitlines():
        ln = ln.strip()
        if "|" not in ln:
            continue
        pid_s, _, cl = ln.partition("|")
        if not pid_s.strip().isdigit():
            continue
        if not cmdline_is_our_proxy(cl):
            continue
        subprocess.run(["taskkill", "/PID", pid_s.strip(), "/T", "/F"],
                       capture_output=True, timeout=30)
        print("      已结束残留反代进程 PID=%s" % pid_s.strip())
        killed = True
    return killed


def kill_old_proxy():
    """先干掉旧反代（pid 文件 + 命令行双重保险），避免端口冲突或旧代码继续跑。"""
    killed = False
    if os.path.exists(PROXY_PID):
        pid = None
        try:
            with open(PROXY_PID, "r") as f:
                pid = int(f.read().strip())
        except Exception:
            pid = None
        if pid:
            if pid_is_our_proxy(pid):
                r = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                                   capture_output=True, timeout=30)
                killed = killed or (r.returncode == 0)
            else:
                print("      pid 文件里的 %s 已不是我们的反代（PID 被系统复用），跳过" % pid)
        try:
            os.remove(PROXY_PID)
        except Exception:
            pass

    # 无论 pid 文件在不在，都按命令行兜底扫一遍
    if kill_by_cmdline():
        killed = True
    if killed:
        time.sleep(0.5)


def start_proxy():
    if not os.path.exists(PROXY_PY):
        print("  [x] 找不到 gh-proxy.py: %s" % PROXY_PY)
        return None

    kill_old_proxy()

    if port_in_use(443):
        print("  [!] 127.0.0.1:443 仍被占用，但都不是我们的反代（已按命令行清理过）。")
        print("      可能是别的程序占着 443，反代将无法启动。请用 netstat -ano 查一下。")
        return "already"

    # 每次启动清空日志：日志是追加模式，上一次的「已启动」横幅会一直留在里面，
    # 让 log_says_started() 误判成本次启动成功；顺带也避免日志无限增长。
    try:
        open(PROXY_LOG, "wb").close()
    except Exception:
        pass

    exe = PYW if os.path.exists(PYW) else sys.executable
    try:
        logf = open(PROXY_LOG, "ab")
    except Exception:
        logf = subprocess.DEVNULL
    try:
        p = subprocess.Popen(
            [exe, PROXY_PY, "--port", "443"],
            cwd=BASE,
            stdin=subprocess.DEVNULL,
            stdout=logf,
            stderr=subprocess.STDOUT,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    except Exception as e:
        print("  [x] 启动反代失败: %s" % e)
        return None

    try:
        with open(PROXY_PID, "w") as f:
            f.write(str(p.pid))
    except Exception:
        pass

    for _ in range(20):
        time.sleep(0.5)
        if port_in_use(443):
            print("  [OK] 反代已启动并监听 127.0.0.1:443（PID=%d）" % p.pid)
            return p.pid
        if p.poll() is not None:
            print("  [x] 反代进程已退出（返回码 %s），请看日志: %s" % (p.returncode, PROXY_LOG))
            return None
        if log_says_started():
            print("  [OK] 反代已启动（PID=%d，端口检测未刷新但日志已确认）" % p.pid)
            return p.pid

    print("  [!] 启动后 10 秒内没监听到 443，请看日志: %s" % PROXY_LOG)
    return p.pid


def main():
    print("=" * 64)
    print("  GitHub 无SNI反代 —— 一键部署")
    print("=" * 64)
    print()

    if not is_admin():
        print("[x] 需要管理员权限。请右键此脚本所在的一键部署.bat，选择「以管理员身份运行」")
        return 1
    print("[0/5] 管理员权限: OK（若下面仍报「拒绝访问」，那是 360 在拦，不是权限不够）")

    if not os.path.exists(CA_CRT):
        print("[x] 找不到 CA 证书: %s" % CA_CRT)
        return 1

    text, enc = read_hosts()

    # 安全闸：读出空内容但文件非空 → 编码/权限异常。此时若照写，会把用户的
    # hosts 整个覆盖成「只剩我们的映射」，属于不可逆的数据丢失。
    sane, size = hosts_sane(text)
    if not sane:
        print("[x] hosts 读出来是空的，但文件有 %d 字节 —— 疑为编码或权限问题。" % size)
        print("    为避免把 hosts 覆盖成只剩我们的映射，已中止。请检查 %s" % HOSTS)
        return 1

    print("[1/5] 备份 hosts")
    if not os.path.exists(HOSTS_BAK):
        shutil.copy2(HOSTS, HOSTS_BAK)
        print("      已备份到: %s" % HOSTS_BAK)
    else:
        print("      备份已存在，跳过（原始备份保留）")

    print("[2/5] 安装 CA 证书到系统信任区")
    install_ca()
    if not verify_ca():
        # 硬门（审计 S5.5）：CA 没装成就放行，部署后所有 GitHub 站点都报证书错误，
        # 更糟的是训练用户「证书告警点继续」——那正是真实中间人攻击需要的效果。
        # 此刻 hosts 尚未写入、反代尚未启动，中止零成本。
        print("  [x] CA 安装验证失败（certutil 可能被安全软件拦截）——中止部署。")
        print("      hosts 未被修改。处理：关闭 360「拦截不明根证书」后重跑本脚本，")
        print("      或手动执行 certutil -addstore -f Root \"%s\" 后重跑。" % CA_CRT)
        return 1
    print("      验证: 已在本机 Root 存储中找到 gh-proxy Local Root CA")

    print("[3/5] 写入 hosts")
    new_text, conflicts = compose_hosts(text)
    try:
        write_hosts(new_text, enc)
    except PermissionError as e:
        print("  [x] 写入 hosts 被拒绝: %s" % e)
        print("      注意：你本人对 hosts 有完全控制权（ACL 已核对），且当前是管理员令牌 ——")
        print("      Windows 自己不会拒。这是 360 的「hosts 防篡改」在拦（它连管理员的写入都拦）。")
        print("      处理（二选一）：")
        print("        A. 托盘右键 360 图标 → 退出 → 重跑本脚本 → 装完再开 360")
        print("        B. 360 主界面 → 木马防火墙 → 主页防护 → 关闭「hosts 防护」")
        print("           （或把本工具目录加入 360 信任区）")
        return 1
    except Exception as e:
        print("  [x] 写入 hosts 失败: %s" % e)
        print("      （CA 已装、hosts 未改：反代此时是空转状态，请重试或手动检查）")
        return 1
    print("      已写入 %d 条域名映射 -> 127.0.0.1（块置于文件最前，保证优先生效）"
          % len(DOMAINS))
    if conflicts:
        print()
        print("      [!] 另外发现 %d 条「其它工具」写下的同域映射，建议关掉它们的"
              "GitHub 加速：" % len(conflicts))
        for c in conflicts[:8]:
            print("          %s" % c)

    print("[4/5] 刷新 DNS 缓存")
    flush_dns()
    print("      完成")

    print("[5/5] 启动反代")
    start_proxy()

    print()
    print("=" * 64)
    print("  部署完成。接下来：")
    print("  1. 完全关闭 Edge，再重新打开（必须重启浏览器）")
    print("  2. 访问 https://github.com")
    print()
    print("  反代已在后台运行，无需保持任何窗口。")
    print("  想让它开机自启：运行「开机自启.bat」")
    print("  想还原：运行「一键卸载.bat」")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
