#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_certs.py — 生成私有 CA、服务器证书，以及供吊销检查用的 CRL。

为什么必须自己生成
------------------
本工具是 TLS 中间人：它要替你访问 GitHub，就必须能出示一张
「浏览器信任的、写着 github.com 的证书」。那张证书由**你自己的私有 CA** 签发。
CA 私钥 = 伪造任意网站证书的能力，所以：

  · 绝不使用别人给的 CA（等于把全部 HTTPS 流量交给对方）；
  · 绝不把 ca.key / server.key 提交到任何仓库。

为什么要生成 CRL（而不只是证书）
--------------------------------
Windows 上 curl / git 走 schannel，它**强制**做证书吊销检查。
若证书没声明任何吊销源（无 CRL Distribution Point / AIA），schannel 会报
    CRYPT_E_NO_REVOCATION_CHECK (0x80092012)
并掐断 TLS 握手 —— 表现是「curl 打不开，但浏览器和 git 有时又没事」，极难归因。

所以这里做两件事：
  1. 给**服务器证书**加 `crlDistributionPoints = http://127.0.0.1:<CRL_PORT>/ca.crl`
  2. 生成对应的 **CRL 文件** `certs/ca.crl`

反代（gh-proxy.py）会在 <CRL_PORT> 上起一个极小 HTTP 监听把这个 CRL 喂出去。
schannel 取到了 CRL → 吊销检查**真正成功** → 放行。
于是 curl / git / 任何 schannel 工具都**不需要任何开关**。

为什么不给 CA 或叶子证书加 `file://` 的 CDP
--------------------------------------------
实测（2026-09-21，ctypes 直调 crypt32 读链的 TrustStatus）：
`file://` 形式的 CDP **Windows 链引擎不读**，`REVOCATION_STATUS_UNKNOWN` 标志
依然存在 → 不起作用。只有 `http://` 才被真正取回。

用法
----
    python gen_certs.py              # 首次生成；已存在则复用 CA、重签叶子 + 重出 CRL
    python gen_certs.py --new-ca     # 连 CA 一起重做（需重新装 CA 到系统信任区）
    python gen_certs.py --force      # 不询问

⚠️ 默认**复用已有 CA**：这样就不必重新把 CA 装进系统信任区（免一次 UAC），
   客户端已建立的信任也不会断。
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE, "certs")
CA_KEY = os.path.join(CERT_DIR, "ca.key")
CA_CRT = os.path.join(CERT_DIR, "ca.crt")
CA_CNF = os.path.join(CERT_DIR, "ca.cnf")
SRV_KEY = os.path.join(CERT_DIR, "server.key")
SRV_CSR = os.path.join(CERT_DIR, "server.csr")
SRV_CRT = os.path.join(CERT_DIR, "server.crt")
SRV_CHAIN = os.path.join(CERT_DIR, "server-chain.crt")
SRV_EXT = os.path.join(CERT_DIR, "server-ext.cnf")
CA_DB = os.path.join(CERT_DIR, "ca-db")          # openssl ca 的数据库（出 CRL 用）
CA_DB_CNF = os.path.join(CA_DB, "openssl.cnf")
CA_CRL = os.path.join(CERT_DIR, "ca.crl")
CRL_PORT_FILE = os.path.join(CERT_DIR, "crl-port.txt")

DAYS_CA = 3650
DAYS_SRV = 825          # 主流浏览器/系统接受的最长有效期上限
DAYS_CRL = 3650         # CRL 有效期给足，免得频繁重出

DEFAULT_CRL_PORT = 18444


def find_openssl():
    """找一个可用的 openssl：Git for Windows 自带的最常见。"""
    cands = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Windows\System32\openssl.exe",
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    exe = shutil.which("openssl")
    return exe


def run(openssl, args, label, cwd=None):
    r = subprocess.run([openssl] + args, capture_output=True,
                       cwd=cwd or CERT_DIR)
    ok = r.returncode == 0
    print("    %s %s" % ("OK " if ok else "XX ", label))
    if not ok:
        out = (r.stdout or b"").decode("utf-8", "replace") + \
              (r.stderr or b"").decode("utf-8", "replace")
        print("        " + out.strip()[:400])
    return ok


def backup(path):
    if os.path.exists(path):
        dst = "%s.bak-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(path, dst)
        print("    已备份 %s → %s" % (os.path.basename(path), os.path.basename(dst)))


def crl_port():
    """CRL 监听端口。优先读 certs/crl-port.txt（gen_certs 写、反代读）。"""
    try:
        with open(CRL_PORT_FILE) as f:
            p = int(f.read().strip())
            if 1024 <= p <= 65535:
                return p
    except Exception:
        pass
    return DEFAULT_CRL_PORT


def port_free(port):
    s = socket.socket()
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", port)) != 0
    finally:
        s.close()


def build_ca_db_cnf():
    """写 openssl ca 的配置（绝对路径，供 gencrl / 签发共用）。"""
    os.makedirs(os.path.join(CA_DB, "newcerts"), exist_ok=True)
    idx = os.path.join(CA_DB, "index.txt")
    if not os.path.exists(idx):
        open(idx, "w").close()
    crlnum = os.path.join(CA_DB, "crlnumber")
    if not os.path.exists(crlnum):
        open(crlnum, "w").write("1000\n")
    d = CA_DB.replace("\\", "/")
    with open(CA_DB_CNF, "w", encoding="utf-8") as f:
        f.write("""# gen_certs.py 自动生成 —— openssl ca 的数据库配置（出 CRL 用）
[ca]
default_ca = CA_default
[CA_default]
dir               = %s
database          = %s/index.txt
new_certs_dir     = %s/newcerts
crlnumber         = %s/crlnumber
serial            = %s/serial
certificate       = %s
private_key       = %s
default_md        = sha256
default_crl_days  = %d
crl_extensions    = crl_ext
policy            = pol
unique_subject    = no
[pol]
commonName = supplied
[crl_ext]
authorityKeyIdentifier = keyid:always
""" % (d, d, d, d, d, CA_CRT.replace("\\", "/"), CA_KEY.replace("\\", "/"),
       DAYS_CRL))


def main():
    ap = argparse.ArgumentParser(description="生成私有 CA / 服务器证书 / CRL")
    ap.add_argument("--new-ca", action="store_true",
                    help="连 CA 一起重做（之后必须重新装 CA 到系统信任区）")
    ap.add_argument("--force", action="store_true", help="不询问")
    args = ap.parse_args()

    print("=" * 66)
    print("  生成私有 CA / 服务器证书 / CRL")
    print("=" * 66)

    openssl = find_openssl()
    if not openssl:
        print("\n  [x] 找不到 openssl。")
        print("      装一个 Git for Windows 即可（自带 openssl）：")
        print("        https://git-scm.com/download/win")
        print("      或装 OpenSSL 后把 openssl.exe 放进 PATH。")
        return 1
    print("  openssl: %s" % openssl)

    os.makedirs(CERT_DIR, exist_ok=True)
    for f, why in ((CA_CNF, "CA 配置"), (SRV_EXT, "服务器证书扩展配置")):
        if not os.path.exists(f):
            print("  [x] 缺 %s（%s）—— 请完整 clone 仓库，不要只拷 .py" % (f, why))
            return 1

    # ---- 1. CA：默认复用，避免重新装信任 ----
    have_ca = os.path.exists(CA_KEY) and os.path.exists(CA_CRT)
    print()
    if have_ca and not args.new_ca:
        print("[1/4] 复用已有 CA（不重做 → 无需重装系统信任）")
        print("      %s" % CA_CRT)
    else:
        if have_ca:
            print("[1/4] --new-ca：重做 CA（⚠ 之后要重新装进系统信任区）")
        else:
            print("[1/4] 生成 CA 私钥 + 自签证书（%d 天）" % DAYS_CA)
        backup(CA_KEY)
        backup(CA_CRT)
        if not run(openssl, ["genrsa", "-out", CA_KEY, "4096"], "genrsa ca.key"):
            return 1
        if not run(openssl, ["req", "-x509", "-new", "-nodes", "-key", CA_KEY,
                             "-sha256", "-days", str(DAYS_CA),
                             "-config", CA_CNF, "-out", CA_CRT], "自签 ca.crt"):
            return 1

    # ---- 2. CRL 端口：确认空闲后写进 crl-port.txt ----
    port = crl_port()
    if not port_free(port):
        print()
        print("  [!] 端口 %d 已被占用 —— 换一个（证书里的 CDP 会写死这个值）。" % port)
        for cand in range(port + 1, port + 30):
            if port_free(cand):
                print("      自动改用 %d" % cand)
                port = cand
                break
        else:
            print("  [x] 附近找不到空闲端口")
            return 1
    with open(CRL_PORT_FILE, "w") as f:
        f.write("%d\n" % port)
    cdp = "http://127.0.0.1:%d/ca.crl" % port
    print()
    print("[2/4] CRL 分发地址（写进证书）：%s" % cdp)

    # ---- 3. 服务器证书：加 CDP 后重签 ----
    print("[3/4] 重签服务器证书（含 CRL Distribution Point）")
    ext = os.path.join(CERT_DIR, "server-ext.cnf")
    ext_text = open(ext, encoding="utf-8").read()
    # 幂等：先摘掉旧的 CDP 行，再追加当前端口
    ext_text = "\n".join(l for l in ext_text.splitlines()
                         if not l.strip().lower().startswith("crldistributionpoints"))
    if not ext_text.endswith("\n"):
        ext_text += "\n"
    ext_text += "crlDistributionPoints=URI:%s\n" % cdp
    open(ext, "w", encoding="utf-8", newline="\n").write(ext_text)
    print("      server-ext.cnf 已更新")

    backup(SRV_KEY)
    if not run(openssl, ["genrsa", "-out", SRV_KEY, "2048"], "genrsa server.key"):
        return 1
    if not run(openssl, ["req", "-new", "-key", SRV_KEY, "-config", CA_CNF,
                         "-subj", "/CN=gh-proxy local server/O=gh-proxy/OU=local-only/C=CN",
                         "-out", SRV_CSR], "生成 server.csr"):
        return 1
    backup(SRV_CRT)
    if not run(openssl, ["x509", "-req", "-in", SRV_CSR, "-CA", CA_CRT,
                         "-CAkey", CA_KEY, "-CAcreateserial",
                         "-days", str(DAYS_SRV), "-sha256",
                         "-extfile", ext, "-out", SRV_CRT], "签发 server.crt"):
        return 1
    with open(SRV_CHAIN, "wb") as f:
        for p in (SRV_CRT, CA_CRT):
            f.write(open(p, "rb").read())
    print("    OK  合成 server-chain.crt")

    # ---- 4. CRL ----
    print("[4/4] 生成 CRL（%d 天）" % DAYS_CRL)
    build_ca_db_cnf()
    backup(CA_CRL)
    if not run(openssl, ["ca", "-config", CA_DB_CNF, "-gencrl",
                         "-out", CA_CRL], "gencrl ca.crl"):
        print("      [!] CRL 生成失败 —— 证书已声明 CDP 但取不到 CRL，")
        print("          schannel 工具（curl）仍会报 CRYPT_E_NO_REVOCATION_CHECK。")
        return 1
    print("    CRL 大小: %d B" % os.path.getsize(CA_CRL))

    # 清理中间产物
    for tmp in (SRV_CSR, os.path.join(CERT_DIR, "ca.srl")):
        try:
            os.remove(tmp)
        except OSError:
            pass

    print()
    print("=" * 66)
    print("  ✓ 完成")
    print("    证书目录 : %s" % CERT_DIR)
    print("    CRL      : %s" % CA_CRL)
    print("    CDP      : %s" % cdp)
    print()
    print("  下一步：重启反代（双击「重启反代.bat」）——")
    print("         它会在 %d 端口起一个极小 HTTP 监听把 CRL 喂出去。" % port)
    print()
    print("  ⚠ ca.key / server.key 是私钥，切勿外传、切勿提交到仓库。")
    if args.new_ca or not have_ca:
        print("  ⚠ CA 变了/是新的 → 需双击「一键部署.bat」把它装进系统信任区。")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
