#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_certs.py — 生成私有 CA 与服务器证书（TLS 中间人所需）。

为什么必须自己生成
------------------
本工具是 TLS 中间人：它要替你访问 GitHub，就必须能出示一张
「浏览器信任的、写着 github.com 的证书」。那张证书由**你自己的私有 CA** 签发。
CA 私钥 = 伪造任意网站证书的能力，所以：

  · 绝不使用别人给的 CA（等于把全部 HTTPS 流量交给对方）；
  · 绝不把 ca.key / server.key 提交到任何仓库。

每次运行都会**重新生成**一套。若已存在，会先备份成 .bak-<时间戳>。

用法
----
    python gen_certs.py            # 生成（已存在则备份后重建）
    python gen_certs.py --force    # 同上，但不问
"""
import os
import shutil
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

DAYS_CA = 3650
DAYS_SRV = 825          # 主流浏览器/系统接受的最长有效期上限


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
    # 退到 PATH
    exe = shutil.which("openssl")
    if exe:
        return exe
    return None


def run(openssl, args, label):
    r = subprocess.run([openssl] + args, capture_output=True, cwd=CERT_DIR)
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


def main():
    print("=" * 64)
    print("  生成私有 CA + 服务器证书")
    print("=" * 64)

    openssl = find_openssl()
    if not openssl:
        print()
        print("  [x] 找不到 openssl。")
        print("      装一个 Git for Windows 即可（自带 openssl）：")
        print("        https://git-scm.com/download/win")
        print("      或装 OpenSSL 后把 openssl.exe 放进 PATH。")
        return 1
    print("  openssl: %s" % openssl)

    os.makedirs(CERT_DIR, exist_ok=True)
    if not os.path.exists(CA_CNF):
        print("  [x] 缺 certs/ca.cnf —— 请从仓库完整 clone，不要只拷 .py")
        return 1
    if not os.path.exists(SRV_EXT):
        print("  [x] 缺 certs/server-ext.cnf —— 同上")
        return 1

    print()
    print("[1/4] 生成 CA 私钥（4096 位 RSA）")
    backup(CA_KEY)
    if not run(openssl, ["genrsa", "-out", CA_KEY, "4096"], "genrsa ca.key"):
        return 1

    print("[2/4] 自签 CA 证书（%d 天）" % DAYS_CA)
    backup(CA_CRT)
    if not run(openssl, ["req", "-x509", "-new", "-nodes", "-key", CA_KEY,
                         "-sha256", "-days", str(DAYS_CA),
                         "-config", CA_CNF, "-out", CA_CRT], "自签 ca.crt"):
        return 1

    print("[3/4] 生成服务器私钥 + CSR")
    backup(SRV_KEY)
    if not run(openssl, ["genrsa", "-out", SRV_KEY, "2048"], "genrsa server.key"):
        return 1
    if not run(openssl, ["req", "-new", "-key", SRV_KEY, "-config", CA_CNF,
                         "-subj", "/CN=gh-proxy local server/O=gh-proxy/OU=local-only/C=CN",
                         "-out", SRV_CSR], "生成 server.csr"):
        return 1

    print("[4/4] 用 CA 签发服务器证书（SAN 覆盖 GitHub 全域名）")
    backup(SRV_CRT)
    if not run(openssl, ["x509", "-req", "-in", SRV_CSR, "-CA", CA_CRT,
                         "-CAkey", CA_KEY, "-CAcreateserial",
                         "-days", str(DAYS_SRV), "-sha256",
                         "-extfile", SRV_EXT, "-out", SRV_CRT],
               "签发 server.crt"):
        return 1

    # 证书链 = 服务器证书 + CA 证书（反代出示这条链）
    with open(SRV_CHAIN, "wb") as f:
        for p in (SRV_CRT, CA_CRT):
            f.write(open(p, "rb").read())
    print("    OK  合成 server-chain.crt")

    # 清理中间产物：CSR 与 srl 没有保留价值
    for tmp in (SRV_CSR, os.path.join(CERT_DIR, "ca.srl")):
        try:
            os.remove(tmp)
        except OSError:
            pass

    print()
    print("=" * 64)
    print("  ✓ 完成。证书在 %s" % CERT_DIR)
    print()
    print("  ⚠ ca.key / server.key 是私钥，切勿外传、切勿提交到仓库。")
    print("  ⚠ 接下来：双击「一键部署.bat」把 CA 装进系统信任区。")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
