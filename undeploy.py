#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
undeploy.py — 卸载 GitHub 无SNI反代（停反代 + 还原 hosts + 移除 CA 证书 + 删开机自启）
需要管理员权限运行。
"""
import os
import sys
import time
import ctypes
import shutil
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE = os.path.dirname(os.path.abspath(__file__))
HOSTS = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BAK = os.path.join(BASE, "hosts.backup-original.txt")
CA_CRT = os.path.join(BASE, "certs", "ca.crt")
PROXY_PID = os.path.join(BASE, "gh-proxy.pid")
PROXY_PY = os.path.join(BASE, "gh-proxy.py")
TASK_NAME = "gh-proxy"

BEGIN = "# === gh-proxy BEGIN (GitHub no-SNI reverse proxy) ==="
END = "# === gh-proxy END ==="


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

    「读出空内容、但文件非空」= 编码或权限异常。在**还原**方向上后果尤其严重：
    has_block 会因读失败变成 False，于是退化成「拿首次部署时的备份覆盖当前 hosts」，
    把用户部署之后加的一切（别的软件、自己的映射）连同文件一起抹掉。
    hosts 是系统文件，这种覆盖不可逆，宁可中止让人看一眼。
    """
    try:
        size = os.path.getsize(HOSTS)
    except Exception:
        size = 0
    return not (size > 0 and not text.strip()), size


def strip_block(text):
    out, skip = [], False
    for ln in text.splitlines():
        s = ln.strip()
        if s == BEGIN:
            skip = True
            continue
        if s == END:
            skip = False
            continue
        if not skip:
            out.append(ln)
    return "\n".join(out)


def flush_dns():
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=30)
    except Exception:
        pass


def cmdline_is_our_proxy(cmdline):
    """判定一条命令行是否在跑我们的 gh-proxy.py（审计 S5.2，与 deploy.py 同款）。

    归一化折算绝对路径的正/反斜杠与大小写、相对路径按本脚本目录解析；
    裸文件名（cwd 恰为脚本目录）按「宁可多认」处理；其它目录绝不误配。
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
    """杀之前先核对：这个 PID 现在还是不是我们的反代。

    pid 文件会过期 —— 重启之后 Windows 会把那个 PID 复用给别的进程，
    照着旧文件 taskkill 就会误杀无辜。核对按 cmdline_is_our_proxy 归一化
    （审计 S5.2）。核对不了就交给 kill_by_cmdline() 处理。
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


def kill_by_pid_file():
    if not os.path.exists(PROXY_PID):
        return False
    try:
        with open(PROXY_PID, "r") as f:
            pid = int(f.read().strip())
    except Exception:
        pid = None
    if not pid:
        return False
    if not pid_is_our_proxy(pid):
        print("      pid 文件里的 %s 已不是我们的反代（PID 被系统复用），跳过" % pid)
        try:
            os.remove(PROXY_PID)
        except Exception:
            pass
        return False
    r = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, timeout=30)
    ok = (r.returncode == 0)
    if ok:
        print("      已结束反代进程 PID=%d" % pid)
    try:
        os.remove(PROXY_PID)
    except Exception:
        pass
    return ok


def kill_by_cmdline():
    """兜底：找出命令行在跑我们的 gh-proxy.py 的 python 进程并结束
    （匹配在 Python 侧按 cmdline_is_our_proxy 归一化，路径不再内插进 PowerShell）。"""
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


def main():
    print("=" * 64)
    print("  GitHub 无SNI反代 —— 卸载还原")
    print("=" * 64)
    print()

    if not is_admin():
        print("[x] 需要管理员权限。请右键「一键卸载.bat」→「以管理员身份运行」")
        return 1

    print("[1/4] 停止反代进程")
    kill_by_pid_file()
    # 无条件再按命令行兜底扫一遍（审计 S5.1）：双开残留的实例不会写进 pid 文件，
    # 「pid 杀成功就跳过兜底」会让它继续占着 443，而结尾还宣称「已完全还原」。
    kill_by_cmdline()
    time.sleep(0.5)
    print("      完成")

    print("[2/4] 还原 hosts")
    text, enc = read_hosts()

    # 安全闸（与 deploy.py 共用同一判据）：读出空内容但文件非空 → 编码/权限异常。
    sane, size = hosts_sane(text)
    if not sane:
        print("[x] hosts 读出来是空的，但文件有 %d 字节 —— 疑为编码或权限问题。" % size)
        print("    此时若按备份覆盖，会把部署之后的所有改动一起抹掉，已中止。")
        print("    请先手动检查 %s" % HOSTS)
        return 1

    has_block = any(ln.strip() == BEGIN for ln in text.splitlines())
    if has_block:
        # 只摘掉我们自己的块，保留部署之后 hosts 里的其它改动。
        # 直接用「首次部署时的备份」覆盖会把这些改动一起抹掉，反而更糟；
        # 备份只在「当前 hosts 里找不到我们的块」时才当兜底用。
        use_enc = "utf-8" if enc in ("utf-8", "utf-8-sig") else enc
        new_text = strip_block(text).rstrip("\n") + "\n"
        try:
            # 原子写（审计 S5.4，同 deploy._atomic_write 的说明）
            tmp = HOSTS + ".ghproxy-tmp"
            with open(tmp, "w", encoding=use_enc, newline="\r\n") as f:
                f.write(new_text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, HOSTS)
            print("      已摘除 gh-proxy 映射块（其余条目原样保留）")
        except Exception as e:
            print("      [!] 写 hosts 失败: %s" % e)
    elif os.path.exists(HOSTS_BAK):
        # 审计 S5.3：原备份是首次部署时的快照，直接覆盖会把部署之后的用户改动
        # 一起抹掉。覆盖前先把当前 hosts 落带时间戳的快照——不可逆变可逆。
        snap = os.path.join(BASE, "hosts.before-undeploy-%s.txt"
                            % time.strftime("%Y%m%d-%H%M%S"))
        try:
            shutil.copy2(HOSTS, snap)
            print("      已先把当前 hosts 快照到: %s" % snap)
        except Exception as e:
            print("      [!] 快照失败(%s)，仍按原备份还原" % str(e)[:60])
        shutil.copy2(HOSTS_BAK, HOSTS)
        print("      当前 hosts 不含我们的映射块，已从原始备份还原")
    else:
        print("      当前 hosts 不含我们的映射块，无需改动")

    print("[3/4] 移除 CA 证书 + 开机自启任务")
    if os.path.exists(CA_CRT):
        ps = ('Get-ChildItem Cert:\\LocalMachine\\Root | '
              'Where-Object { $_.Subject -like \'*gh-proxy Local Root CA*\' } | '
              'ForEach-Object { Write-Output $_.Thumbprint; Remove-Item -Path ("Cert:\\LocalMachine\\Root\\" + $_.Thumbprint) -Force }')
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, timeout=90)
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace").strip()
        if r.returncode == 0 and out:
            print("      [OK] 已移除 gh-proxy 私有 CA：%s" % out.replace("\n", ", "))
        elif r.returncode == 0:
            print("      CA 未在 Root 存储中（可能之前没装上或已被删）")
        else:
            print("      [!] 移除 CA 失败: %s" % out[:200])
    else:
        print("      找不到 ca.crt，跳过 CA")

    # 顺带体检：FastGithub 的公开 CA 私钥是随开源包分发的，留在信任区有风险
    try:
        chk = subprocess.run(["certutil", "-store", "Root"], capture_output=True, timeout=60)
        cout = (chk.stdout or b"").decode("gbk", "replace")
        if "FastGithub" in cout:
            print()
            print("      [!] 注意：发现 FastGithub 的 CA 仍在系统信任区。")
            print("          它的私钥是公开分发的，别人可以伪造任意网站证书骗过你的浏览器。")
            print("          想清掉，以管理员身份运行：")
            print("            certutil -delstore Root FastGithub")
    except Exception:
        pass

    r = subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                       capture_output=True, timeout=60)
    if r.returncode == 0:
        print("      [OK] 已删除开机自启任务 %s" % TASK_NAME)
    else:
        print("      开机自启任务不存在，跳过")

    print("[4/4] 刷新 DNS 缓存")
    flush_dns()

    print()
    print("=" * 64)
    print("  已完全还原，GitHub 恢复为直连状态。")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
