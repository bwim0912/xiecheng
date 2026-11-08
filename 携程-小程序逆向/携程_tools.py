"""携程逆向 —— 调试工具（抓包代理 / 系统代理 / 窗口自动化 / 会话刷新）

这些是逆向过程中用的工具，日常查价格用不到，放在单独的 携程_tools.py。

命令行:
    python 携程_tools.py capture                # 起 HTTPS 抓包代理（前台）
    python 携程_tools.py proxy on|off|show|restore
    python 携程_tools.py windows 携程            # 列出窗口
    python 携程_tools.py blue                   # 按颜色找按钮并点击
    python 携程_tools.py open                   # 自动打开携程小程序
    python 携程_tools.py refresh-session        # 从抓包日志提取新票据

依赖: requests、node
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from winreg import (HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ,
                    OpenKey, QueryValueEx, SetValueEx)

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(HERE, "js_reverse_cache")
CONFIG_FILE = os.path.join(HERE, "携程_config.json")
MITM_PORT = 9080
MITM_LOG_PATH = os.path.join(CACHE_DIR, "mitm.jsonl")

# §6 HTTPS 抓包代理   （源文件：mitm.py）
# ==========================================================================
"""极简 MITM 抓包代理（纯标准库 + openssl CLI）

用途：截获 Windows 小程序（WeChatAppEx）经系统代理发出的 HTTPS 请求，
完整记录 method / host / path / 查询参数 / 请求体 / 响应体。

TLS 证书：复用本机已受信任的 Reqable CA（cert + 私钥存放在
%APPDATA%/Reqable/certificate/capture.bin），因此无需再安装根证书。
"""


MITM_PORT = 9080
MITM_BASE = CACHE_DIR                      # 运行期产物统一放 js_reverse_cache/
CERTDIR = os.path.join(MITM_BASE, "certs")
FLOWDIR = os.path.join(MITM_BASE, "flows")
REQABLE_CA = os.path.join(os.environ["APPDATA"], "Reqable", "certificate", "capture.bin")

os.makedirs(CERTDIR, exist_ok=True)
os.makedirs(FLOWDIR, exist_ok=True)

CA_CERT = os.path.join(CERTDIR, "ca.crt")
CA_KEY = os.path.join(CERTDIR, "ca.key")
CA_SERIAL = os.path.join(CERTDIR, "ca.srl")
LEAF_KEY = os.path.join(CERTDIR, "leaf.key")

MITM_LOG_PATH = os.path.join(MITM_BASE, "mitm.jsonl")
# 需要"拦截但不转发"的路径片段：用于抢在客户端消费之前截获一次性凭证
# 例：MITM_DROP=getMKTOpenID  —— 截获 wx.login 的 code
DROP = [x for x in os.environ.get("MITM_DROP", "").split(",") if x.strip()]
_log_lock = threading.Lock()
_cert_lock = threading.Lock()
_ctx_cache = {}


def mitm_log(rec):
    with _log_lock:
        with open(MITM_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def mitm_prepare_ca():
    with open(REQABLE_CA, "r", encoding="utf-8") as f:
        ca = json.load(f)
    with open(CA_CERT, "w", encoding="utf-8") as f:
        f.write(ca["cert"])
    with open(CA_KEY, "w", encoding="utf-8") as f:
        f.write(ca["pkey"])
    if not os.path.exists(LEAF_KEY):
        subprocess.run(
            ["openssl", "genrsa", "-out", LEAF_KEY, "2048"],
            check=True, capture_output=True,
        )


def host_slug(host):
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)[:120]


def cert_for(host):
    with _cert_lock:
        slug = host_slug(host)
        crt = os.path.join(CERTDIR, slug + ".crt")
        csr = os.path.join(CERTDIR, slug + ".csr")
        if not os.path.exists(crt):
            subprocess.run(
                ["openssl", "req", "-new", "-key", LEAF_KEY, "-subj", "/CN=" + host,
                 "-addext", "subjectAltName=DNS:" + host, "-out", csr],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["openssl", "x509", "-req", "-in", csr, "-CA", CA_CERT, "-CAkey", CA_KEY,
                 "-CAserial", CA_SERIAL, "-CAcreateserial", "-days", "90",
                 "-copy_extensions", "copy", "-out", crt],
                check=True, capture_output=True,
            )
        pem = os.path.join(CERTDIR, slug + ".pem")
        if not os.path.exists(pem):
            with open(pem, "w", encoding="utf-8") as out:
                for p in (crt, LEAF_KEY):
                    with open(p, "r", encoding="utf-8") as f:
                        out.write(f.read())
        return pem


def server_ctx(host):
    pem = cert_for(host)
    with _cert_lock:
        ctx = _ctx_cache.get(pem)
        if ctx is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(pem)
            ctx.set_alpn_protocols(["http/1.1"])
            _ctx_cache[pem] = ctx
        return ctx


def upstream_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


UP_CTX = upstream_ctx()


def recv_head(sock, buf=b"", limit=1 << 22):
    """读到 \\r\\n\\r\\n 为止，返回 (header_bytes, 剩余字节, ok)"""
    marker = b"\r\n\r\n"
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return buf, b"", False
        buf += chunk
        if len(buf) > limit:
            break
    idx = buf.find(marker)
    if idx < 0:
        return buf, b"", False
    end = idx + len(marker)
    return buf[:end], buf[end:], True


def recv_exact(sock, n, buf=b""):
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf[:n], buf[n:]


def read_body(sock, headers, buf=b"", is_response=False):
    """按 Content-Length / chunked / 直到关闭 读取消息体"""
    lower = {k.lower(): v for k, v in headers.items()}
    if "chunked" in lower.get("transfer-encoding", "").lower():
        body = b""
        while True:
            line, buf = _read_line(sock, buf)
            if not line:
                return body, buf
            try:
                size = int(line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                return body, buf
            if size == 0:
                _, buf = _read_line(sock, buf)  # 尾部空行
                return body, buf
            chunk, buf = recv_exact(sock, size + 2, buf)
            body += chunk[:-2]
            if len(body) > 8 << 20:
                return body, buf
        return body, buf
    if "content-length" in lower:
        try:
            n = int(lower["content-length"])
        except ValueError:
            n = 0
        return recv_exact(sock, n, buf)
    if is_response:
        body = buf
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
            if len(body) > 8 << 20:
                break
        return body, b""
    return b"", buf


def _read_line(sock, buf=b""):
    while b"\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return b"", buf
        buf += chunk
    line, rest = buf.split(b"\r\n", 1)
    return line, rest


def parse_headers(raw):
    """raw: bytes 到 \\r\\n\\r\\n（含）"""
    text = raw.decode("latin1")
    lines = text.split("\r\n")
    start = lines[0]
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return start, headers


def preview(data, ctype=""):
    if not data:
        return ""
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        return f"<binary {len(data)} bytes>"
    if len(txt) > 400000:
        return txt[:400000] + f"...<+{len(txt) - 400000}>"
    return txt


def handle_tunnel(client, host, port):
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    if port == 443:
        ctx = server_ctx(host)
        try:
            client = ctx.wrap_socket(client, server_side=True)
        except Exception as e:
            mitm_log({"ts": time.time(), "kind": "tls_fail", "host": host, "err": str(e)})
            return
    _serve_http(client, host, port)


def _relay(a, b):
    def pipe(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

    t = threading.Thread(target=pipe, args=(b, a), daemon=True)
    t.start()
    pipe(a, b)
    t.join(timeout=5)


def _serve_http(client, host, port):
    buf = b""
    while True:
        head, buf, ok = recv_head(client, buf)
        if not ok:
            return
        try:
            start, headers = parse_headers(head)
        except Exception:
            return
        if not start.strip():
            return
        parts = start.split(" ")
        if len(parts) < 3:
            return
        method, target, version = parts[0], parts[1], parts[2]
        if target.startswith("http://") or target.startswith("https://"):
            # 绝对 URI（明文代理请求）
            u = urlsplit(target)
            host_hdr, path = u.netloc, (u.path or "/") + (("?" + u.query) if u.query else "")
        else:
            host_hdr, path = headers.get("Host", host), target
        body, buf = read_body(client, headers, buf)

        up_headers = dict(headers)
        # 去掉压缩协商，拿到明文响应，便于直接读接口内容
        for k in list(up_headers):
            if k.lower() == "accept-encoding":
                up_headers.pop(k)
        # 请求体已被解块，必须同步改写头，否则上游按 chunked 解析会挂
        if any(k.lower() == "transfer-encoding" for k in up_headers):
            up_headers = {k: v for k, v in up_headers.items() if k.lower() != "transfer-encoding"}
            up_headers["Content-Length"] = str(len(body))
        is_ws = up_headers.get("Upgrade", "").lower() == "websocket"
        req_lines = [f"{method} {path} {version}"]
        for k, v in up_headers.items():
            req_lines.append(f"{k}: {v}")
        req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("latin1") + body

        if is_ws:
            try:
                up = socket.create_connection((host_hdr.split(":")[0], port), timeout=15)
                if port == 443:
                    up = UP_CTX.wrap_socket(up, server_hostname=host_hdr.split(":")[0])
                up.sendall(req_bytes)
                resp_raw, up_buf, ok = recv_head(up)
                if ok:
                    client.sendall(resp_raw + up_buf)
                    mitm_log({"ts": time.time(), "kind": "websocket", "host": host_hdr,
                         "path": path, "status": resp_raw.split(b"\r\n")[0].decode("latin1")})
                    _relay(client, up)
                else:
                    mitm_log({"ts": time.time(), "kind": "websocket_fail", "host": host_hdr,
                         "path": path})
            except Exception as e:
                mitm_log({"ts": time.time(), "kind": "websocket_err", "host": host_hdr,
                     "path": path, "err": f"{type(e).__name__}: {e}"})
            return

        req_body_preview = preview(body, up_headers.get("Content-Type", ""))
        if any(d in path for d in DROP):
            # 拦下不转发：凭证保持未消费状态，留给我们自己用
            mitm_log({"ts": time.time(), "kind": "drop", "host": host_hdr, "method": method,
                 "path": path, "req_headers": up_headers, "req_body": req_body_preview,
                 "status": "DROPPED", "resp_headers": {}, "resp_body": ""})
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                               b"Connection: keep-alive\r\n\r\n")
            except Exception:
                pass
            continue

        rec = {
            "ts": time.time(),
            "kind": "request",
            "host": host_hdr,
            "method": method,
            "path": path,
            "req_headers": up_headers,
            "req_body": req_body_preview,
            "status": None,
            "resp_headers": {},
            "resp_body": "",
        }
        try:
            up = socket.create_connection((host_hdr.split(":")[0], port), timeout=15)
            if port == 443:
                up = UP_CTX.wrap_socket(up, server_hostname=host_hdr.split(":")[0])
            up.sendall(req_bytes)
            resp_raw, up_buf, up_ok = recv_head(up)
            if up_ok:
                r_start, r_headers = parse_headers(resp_raw)
                r_body, _ = read_body(up, r_headers, up_buf, is_response=True)
                try:
                    up.close()
                except Exception:
                    pass
                rec["status"] = r_start
                rec["resp_headers"] = r_headers
                rec["resp_body"] = preview(r_body, r_headers.get("Content-Type", ""))
                # 响应体已解块，必须重写头（去掉 Transfer-Encoding 并补 Content-Length），
                # 否则客户端按 chunked 解析会截断 —— 这是"加载失败"的真凶
                out = []
                for k, v in r_headers.items():
                    if k.lower() in ("transfer-encoding", "content-length"):
                        continue
                    out.append(f"{k}: {v}")
                out.append(f"Content-Length: {len(r_body)}")
                if not any(k.lower() == "connection" for k in r_headers):
                    out.append("Connection: keep-alive")
                client.sendall((r_start + "\r\n" + "\r\n".join(out) + "\r\n\r\n").encode("latin1") + r_body)
                mitm_log(rec)
                if "close" in r_headers.get("Connection", "").lower():
                    return
                continue
            else:
                rec["status"] = "NO_RESPONSE"
                mitm_log(rec)
                return
        except Exception as e:
            rec["status"] = f"ERR {type(e).__name__}: {e}"
            mitm_log(rec)
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
            return


def handle(client):
    try:
        client.settimeout(30)
        raw, _rest, ok = recv_head(client)
        if not ok:
            return
        start, headers = parse_headers(raw)
        parts = start.split(" ")
        if len(parts) >= 2 and parts[0].upper() == "CONNECT":
            hostport = parts[1]
            host, _, port = hostport.partition(":")
            handle_tunnel(client, host, int(port or 443))
        else:
            # 明文代理请求
            host_hdr = headers.get("Host", "")
            host, _, port = host_hdr.partition(":")
            _serve_http(client, host, int(port or 80))
    except Exception as e:
        mitm_log({"ts": time.time(), "kind": "conn_err", "err": f"{type(e).__name__}: {e}"})
    finally:
        try:
            client.close()
        except Exception:
            pass


def mitm_main():
    mitm_prepare_ca()
    open(MITM_LOG_PATH, "w").close()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", MITM_PORT))
    srv.listen(128)
    mitm_log({"ts": time.time(), "kind": "listen", "port": MITM_PORT})
    print(f"MITM listening on 127.0.0.1:{MITM_PORT}", flush=True)
    while True:
        try:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
        except KeyboardInterrupt:
            break


# ==========================================================================
# §7 系统代理开关   （源文件：proxy_set.py）
# ==========================================================================
"""读写系统代理设置（纯 winreg + ctypes，不依赖 reg.exe）

用法：
    python proxy_set.py show            # 查看当前值
    python proxy_set.py on  [port]      # 打开代理到 127.0.0.1:port（默认 9080）
    python proxy_set.py off             # 关闭代理
    python proxy_set.py restore <json>  # 按备份恢复
"""

PROXY_SUB = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def proxy_read_all():
    out = {}
    with OpenKey(HKEY_CURRENT_USER, PROXY_SUB, 0, KEY_READ) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                v, t = QueryValueEx(k, name)
                out[name] = v
            except FileNotFoundError:
                out[name] = None
    return out


def proxy_write(name, value, kind):
    with OpenKey(HKEY_CURRENT_USER, PROXY_SUB, 0, KEY_WRITE) as k:
        SetValueEx(k, name, 0, kind, value)


def proxy_refresh():
    """通知 WinINet 重新读取设置，否则已运行的程序不生效"""
    try:
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print("proxy_refresh failed:", e)


def proxy_main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    if cmd == "show":
        print(json.dumps(proxy_read_all(), ensure_ascii=False, indent=1))
    elif cmd == "on":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9080
        backup = proxy_read_all()
        with open(os.path.join(CACHE_DIR, "proxy_backup.json"), "w", encoding="utf-8") as f:
            json.dump(backup, f, ensure_ascii=False)
        proxy_write("ProxyServer", f"127.0.0.1:{port}", REG_SZ)
        proxy_write("ProxyEnable", 1, REG_DWORD)
        proxy_refresh()
        print("proxy on ->", f"127.0.0.1:{port}", "| backup:", backup)
    elif cmd == "off":
        proxy_write("ProxyEnable", 0, REG_DWORD)
        proxy_refresh()
        print("proxy off")
    elif cmd == "restore":
        with open(sys.argv[2], "r", encoding="utf-8") as f:
            b = json.load(f)
        if b.get("ProxyServer") is not None:
            proxy_write("ProxyServer", b["ProxyServer"], REG_SZ)
        if b.get("ProxyOverride") is not None:
            proxy_write("ProxyOverride", b["ProxyOverride"], REG_SZ)
        proxy_write("ProxyEnable", int(b.get("ProxyEnable") or 0), REG_DWORD)
        proxy_refresh()
        print("restored ->", b)


# ==========================================================================
# §8 窗口自动化（截图 / 点击 / 打字）   （源文件：ui.py）
# ==========================================================================
"""Windows UI 基础操作（纯 ctypes，无需编译）
- 找窗口 / 置前 / 截图 / 鼠标点击 / 键盘输入
"""

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# 让进程感知 DPI，保证 GetWindowRect / SetCursorPos / 截图 使用同一套物理像素坐标
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

SW_RESTORE = 9
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
        ("biPlanes", wt.WORD), ("biBitCount", wt.WORD), ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD), ("biXPelsPerMeter", wt.LONG),
        ("biYPelsPerMeter", wt.LONG), ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]


class _INPUTunion(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wt.DWORD), ("u", _INPUTunion)]


user32.GetDC.restype = ctypes.c_void_p
user32.GetDC.argtypes = [ctypes.c_void_p]
user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.RECT)]
gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
gdi32.SelectObject.restype = ctypes.c_void_p
gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
gdi32.BitBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                         wt.DWORD]
gdi32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.UINT, wt.UINT,
                            ctypes.c_void_p, ctypes.POINTER(BITMAPINFO), wt.UINT]
gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
gdi32.DeleteDC.argtypes = [ctypes.c_void_p]


def find_windows(keyword):
    """按标题关键字找可见窗口"""
    found = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def _cb(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n == 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        title = buf.value
        if keyword.lower() in title.lower():
            r = wt.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(r))
            found.append({"hwnd": hwnd, "title": title,
                          "rect": (r.left, r.top, r.right, r.bottom)})
        return True

    user32.EnumWindows(_cb, 0)
    return found


def activate(hwnd):
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.4)


def screenshot(rect, out_path, flip=False):
    left, top, right, bottom = rect
    w, h = right - left, bottom - top
    hdc = user32.GetDC(0)
    memdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(memdc, bmp)
    gdi32.BitBlt(memdc, 0, 0, w, h, hdc, left, top, 0x00CC0020)  # SRCCOPY
    bi = BITMAPINFO()
    bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.bmiHeader.biWidth = w
    bi.bmiHeader.biHeight = -h  # top-down
    bi.bmiHeader.biPlanes = 1
    bi.bmiHeader.biBitCount = 32
    bi.bmiHeader.biCompression = 0
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(memdc, bmp, 0, h, buf, ctypes.byref(bi), 0)

    # 写 24 位 BMP
    row_size = (w * 3 + 3) & ~3
    data_size = row_size * h
    header = ctypes.create_string_buffer(54)
    ctypes.memmove(header, b"BM", 2)
    ctypes.memmove(ctypes.byref(header, 2), ctypes.byref(ctypes.c_uint32(54 + data_size)), 4)
    ctypes.memmove(ctypes.byref(header, 10), ctypes.byref(ctypes.c_uint32(54)), 4)
    ctypes.memmove(ctypes.byref(header, 14), ctypes.byref(ctypes.c_uint32(40)), 4)
    ctypes.memmove(ctypes.byref(header, 18), ctypes.byref(ctypes.c_int32(w)), 4)
    ctypes.memmove(ctypes.byref(header, 22), ctypes.byref(ctypes.c_int32(-h)), 4)
    ctypes.memmove(ctypes.byref(header, 26), ctypes.byref(ctypes.c_uint16(1)), 2)
    ctypes.memmove(ctypes.byref(header, 28), ctypes.byref(ctypes.c_uint16(24)), 2)
    ctypes.memmove(ctypes.byref(header, 34), ctypes.byref(ctypes.c_uint32(data_size)), 4)
    rows = bytearray()
    src = buf.raw
    for y in range(h):
        base = y * w * 4
        line = bytearray()
        xs = range(w - 1, -1, -1) if flip else range(w)
        for x in xs:
            b, g, r = src[base + x * 4], src[base + x * 4 + 1], src[base + x * 4 + 2]
            line += bytes((b, g, r))
        line += b"\x00" * (row_size - w * 3)
        rows += line
    with open(out_path, "wb") as f:
        f.write(header.raw)
        f.write(bytes(rows))
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(memdc)
    user32.ReleaseDC(0, hdc)
    return out_path


def click(x, y):
    user32.SetCursorPos(int(x), int(y))
    time.sleep(0.15)
    user32.mouse_event(0x0002, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.05)
    user32.mouse_event(0x0004, 0, 0, 0, 0)  # LEFTUP
    time.sleep(0.3)


def type_text(text):
    for ch in text:
        for down in (True, False):
            inp = INPUT()
            inp.type = INPUT_KEYBOARD
            inp.u.ki.wVk = 0
            inp.u.ki.wScan = ord(ch)
            inp.u.ki.dwFlags = KEYEVENTF_UNICODE | (0 if down else KEYEVENTF_KEYUP)
            user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
            time.sleep(0.01)


def key(vk):
    for down in (True, False):
        user32.keybd_event(vk, 0, 0 if down else KEYEVENTF_KEYUP, 0)
        time.sleep(0.03)


# ==========================================================================
# §8b 按颜色定位并点击按钮   （源文件：ui_btn.py）
# ==========================================================================
"""按颜色定位并点击小程序里的蓝色主按钮（比硬编码坐标可靠）

用法：
    python ui_btn.py blue           # 找蓝色按钮并点击
    python ui_btn.py blue --dry     # 只报告位置，不点击
"""


user32 = ctypes.windll.user32


def read_bmp(path):
    raw = open(path, "rb").read()
    off = struct.unpack("<I", raw[10:14])[0]
    w, h = struct.unpack("<ii", raw[18:26])
    bpp = struct.unpack("<H", raw[28:30])[0]
    assert bpp == 24, bpp
    topdown = h < 0
    h = abs(h)
    row = (w * 3 + 3) & ~3
    px = lambda x, y: (raw[off + y * row + x * 3 + 2],
                       raw[off + y * row + x * 3 + 1],
                       raw[off + y * row + x * 3])  # (R,G,B)
    return px, w, h, topdown


def find_blue(path):
    px, w, h, _ = read_bmp(path)
    xs, ys = [], []
    for y in range(0, h, 2):
        for x in range(0, w, 2):
            r, g, b = px(x, y)
            # 携程主按钮蓝：#0086F6 / #287DFA / #1478FF
            if b > 180 and r < 90 and 90 < g < 175:
                xs.append(x)
                ys.append(y)
    if not xs:
        return None
    return min(xs), min(ys), max(xs), max(ys), len(xs)


def click_blue_main():
    dry = "--dry" in sys.argv
    ws = [x for x in find_windows("携程") if "旅行" in x["title"]]
    if not ws:
        print("NO_WINDOW")
        return 1
    w0 = ws[0]
    activate(w0["hwnd"])
    time.sleep(0.8)
    ws = [x for x in find_windows("携程") if "旅行" in x["title"]]
    l, t, r, b = ws[0]["rect"]
    screenshot((l, t, r, b), "btn_probe.bmp")
    hit = find_blue("btn_probe.bmp")
    if not hit:
        print("NO_BLUE")
        return 2
    x1, y1, x2, y2, n = hit
    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
    print(f"蓝色区域 ({x1},{y1})-({x2},{y2}) 像素数={n} 中心=({cx},{cy}) 点击坐标=({l+cx},{t+cy})")
    if dry:
        return 0
    click(l + cx, t + cy)
    print("clicked")
    return 0


# ==========================================================================
# §8c 自动打开携程小程序   （源文件：open_ctrip.py）
# ==========================================================================
"""自动打开携程小程序：点搜索框 -> 输入携程 -> 点"最近使用过的小程序"第一条"""



def open_ctrip_main():
    ws = [w for w in find_windows('微信') if w['title'] == '微信']
    if not ws:
        print('NO_WECHAT')
        return 1
    win = ws[0]
    activate(win['hwnd'])
    time.sleep(0.4)
    win = [w for w in find_windows('微信') if w['title'] == '微信'][0]
    l, t, r, b = win['rect']

    click(l + 221, t + 67)          # 搜索框
    time.sleep(0.8)
    type_text('携程')
    time.sleep(2.2)
    screenshot((l, t, r, b), 'open_search.bmp')
    click(l + 277, t + 415)         # 最近使用过的小程序 第一条
    time.sleep(3.0)

    for _ in range(10):
        hits = find_windows('携程')
        if hits:
            print('OPENED', hits[0]['title'], hits[0]['rect'])
            return 0
        time.sleep(1)
    print('NOT_OPENED')
    return 2


# ============================================================================
# §9 会话刷新：从抓包日志里提取最新的微信渠道会话
# ============================================================================

SESSION_KEYS = ("auth", "mktOpenID", "duid", "udl", "cookie", "scene", "cid", "ua")


def extract_wx_session(log_path: str | None = None) -> dict | None:
    """从 mitm.jsonl 里最后一条 fetchHotelInfoList 请求提取会话凭证。"""
    path = log_path or os.path.join(HERE, "mitm.jsonl")
    if not os.path.exists(path):
        return None
    found = None
    with io.open(path, encoding="utf-8") as f:
        for line in f:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("kind") != "request" or "HotelInfoList" not in d.get("path", ""):
                continue
            try:
                body = json.loads(d.get("req_body") or "{}")
            except ValueError:
                continue
            h = d.get("req_headers") or {}
            if not body.get("head", {}).get("auth") or not h.get("x-wx-openid"):
                continue
            m = re.search(r"servicewechat\.com/[^/]+/(\d+)/", h.get("Referer", "") or "")
            found = {
                "auth": body["head"]["auth"],
                "mktOpenID": h["x-wx-openid"],
                "duid": h.get("duid", ""),
                "udl": h.get("udl", ""),
                "cookie": h.get("Cookie", ""),
                "scene": (body["head"].get("extension") or [{}, {}])[1].get("value", "1005"),
                "cid": body["head"].get("cid", ""),
                "ua": h.get("User-Agent", ""),
                "appVersion": m.group(1) if m else "1077",
            }
    return found


def refresh_session(log_path: str | None = None) -> dict | None:
    """从抓包日志提取微信渠道票据，写回 携程_config.json 的 wx 段。"""
    sess = extract_wx_session(log_path)
    if not sess:
        return None
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with io.open(CONFIG_FILE, encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            cfg = {}
    cfg["wx"] = sess
    with io.open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    return sess


# ============================================================================


def _cmd_proxy(args: list[str]) -> None:
    cmd = args[0] if args else "show"
    if cmd == "on":
        port = int(args[1]) if len(args) > 1 else MITM_PORT
        backup = proxy_read_all()
        with io.open(os.path.join(CACHE_DIR, "proxy_backup.json"), "w", encoding="utf-8") as f:
            json.dump(backup, f, ensure_ascii=False)
        proxy_write("ProxyServer", f"127.0.0.1:{port}", REG_SZ)
        proxy_write("ProxyEnable", 1, REG_DWORD)
        proxy_refresh()
        print("代理已开 ->", f"127.0.0.1:{port}", "| 原值:", backup)
    elif cmd == "off":
        proxy_write("ProxyEnable", 0, REG_DWORD)
        proxy_refresh()
        print("代理已关")
    elif cmd == "restore":
        path = args[1] if len(args) > 1 else os.path.join(CACHE_DIR, "proxy_backup.json")
        with io.open(path, encoding="utf-8") as f:
            b = json.load(f)
        if b.get("ProxyServer") is not None:
            proxy_write("ProxyServer", b["ProxyServer"], REG_SZ)
        if b.get("ProxyOverride") is not None:
            proxy_write("ProxyOverride", b["ProxyOverride"], REG_SZ)
        proxy_write("ProxyEnable", int(b.get("ProxyEnable") or 0), REG_DWORD)
        proxy_refresh()
        print("已还原 ->", b)
    else:
        print(json.dumps(proxy_read_all(), ensure_ascii=False, indent=1))



# ==========================================================================
# 命令行
# ==========================================================================

def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, args = argv[0], argv[1:]
    if cmd == "capture":
        mitm_main()
    elif cmd == "proxy":
        _cmd_proxy(args)
    elif cmd == "windows":
        for w in find_windows(args[0] if args else ""):
            print(w)
    elif cmd == "blue":
        click_blue_main()
    elif cmd == "open":
        open_ctrip_main()
    elif cmd == "refresh-session":
        path = next((a for a in args if not a.startswith("-")), None)
        dry = "--dry" in args
        s = refresh_session(path)
        if not s:
            print("没有可用的抓包记录")
        else:
            if dry:
                print(json.dumps(s, ensure_ascii=False, indent=1))
            else:
                print("会话已更新:", json.dumps(s, ensure_ascii=False)[:300])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
