"""
AP server 轉發程式(只轉發,不放任何金鑰)
==========================================
用途:架構是
    電視牆瀏覽器  ->  AP server(這支程式,有 NAT IP)  ->  DB server(收集程式 + 大螢幕資料伺服器,內網)
這支程式只做一件事:把電視牆的請求原封不動轉給 DB server 上的 dashboard_server.py。

為什麼這樣設計
--------------
- API Key、OpManager / NFA 的連線,全部只留在內網的 DB server。
  AP server 對外開放(有 NAT IP),就算它被入侵,也拿不到 Key、連不到 OpManager。
- 只用 Python 內建模組,不需要安裝 IIS / nginx,也不用 pip install。

安全設計
--------
- 只轉發 GET,而且只轉發白名單網址:網頁本身、/api/summary、/api/topn、/api/meraki_plan、/api/meraki_find、/api/meraki_diag、/favicon.ico、/healthz(本機回應)。
  其他網址(例如 /api/nat_map)一律 404,不會轉給後端。
- /api/topn 的參數只接受英數字與 = &,避免有人塞奇怪的字元進去。
- --allow-client 可限制只有指定 IP / 網段能連。注意:經過 NAT 之後,這裡看到的來源 IP 可能是 NAT 設備的 IP,
  不是電視牆本身;被拒絕時畫面會印出「被拒絕的來源 IP」,照著填即可。
- 頁面本身沒有帳號驗證,請再搭配防火牆規則,只讓電視牆的網段連到這個埠。

HTTPS(自簽憑證)
-----------------
電視牆到 AP server 這一段可以改用 HTTPS(AP server 到 DB server 仍是內網 HTTP)。
1. 產生自簽憑證(只要做一次;需要 pip install cryptography):
     python ap_proxy.py --make-cert --cert-names 10.9.9.9,ap-server
   --cert-names 填「電視牆瀏覽器網址列會打的 IP 或主機名稱」(可多個,逗號分隔),
   會寫出 ap_proxy_cert.crt(憑證)與 ap_proxy_key.pem(私鑰,請勿外流)。
2. 啟動時加上 --cert 與 --key 就會改成 HTTPS:
     python ap_proxy.py --upstream http://10.1.1.20:8080 --cert ap_proxy_cert.crt --key ap_proxy_key.pem
3. 自簽憑證瀏覽器會顯示「不安全」。要消除警告:把 ap_proxy_cert.crt 匯入電視牆那台電腦的
   「受信任的根憑證授權單位」(雙擊 .crt → 安裝憑證 → 本機電腦 → 受信任的根憑證授權單位),
   而且網址要用 --cert-names 裡有的 IP / 名稱。不匯入也能用,只是第一次要按「進階 → 繼續前往」。
   也可以改用公司內部 CA 簽發的憑證:把 --cert / --key 換成那份檔案即可。
   憑證預設 5 年有效;到期前重新執行 --make-cert 並再匯入一次。

用法
----
python ap_proxy.py --upstream http://10.1.1.20:8080 --port 8080 --allow-client 10.9.0.0/24
    --upstream      DB server 上 dashboard_server.py 的網址(正式執行時必填)
    --port          這台 AP server 對電視牆開放的埠(預設 8080)
    --host          監聽的網卡位址(預設 0.0.0.0)
    --allow-client  只允許這些來源 IP / 網段(逗號分隔);不填 = 不限制(會提醒)
    --cert / --key  PEM 格式的憑證與私鑰;兩個都給就改用 HTTPS(只開 HTTPS,同一個埠不再提供 HTTP)
    --make-cert     產生自簽憑證後結束(搭配 --cert-names,可選 --cert / --key / --cert-days)
開機自動執行請用 noc_service.ps1 -Role Proxy。檢查是否通:瀏覽器開 http://AP-server-IP:8080/healthz
"""

import argparse
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAGE_PATHS = {"/", "/index.html", "/dashboard.html"}
API_PATHS = {"/api/summary", "/api/topn", "/api/meraki_plan", "/api/meraki_find", "/api/meraki_diag"}
QUERY_OK = re.compile(r"^[A-Za-z0-9=&_.]{0,200}$")
FIND_RAW_OK = re.compile(r"^q=[A-Za-z0-9%_.~+\-]{1,300}$")      # /api/meraki_find 的原始查詢字串(中文會被編碼成 %XX)
FIND_Q_OK = re.compile(r"^[\w .:@\-]{3,40}$")                  # 解碼後的搜尋字串:3~40 字,只允許文字、數字、空白與 . : @ -
DIAG_OK = re.compile(r"^mac=[0-9A-Fa-f]{2}(?:(?:%3[Aa]|:|-)[0-9A-Fa-f]{2}){5}&h=(?:1|2|4|24)\Z")   # /api/meraki_diag:只收完整 MAC + 1/2/4/24 小時
MAX_BODY = 8 * 1024 * 1024          # 後端回應超過 8 MB 就不轉(正常 dashboard.html 約 0.3 MB)

CONFIG = {"up_host": "", "up_port": 80, "allowed": []}
_last_deny_log: dict = {}


def parse_allow_list(text: str) -> list:
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def client_allowed(ip: str) -> bool:
    if not CONFIG["allowed"]:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or any(addr in net for net in CONFIG["allowed"])


def fetch_upstream(path_and_query: str, timeout: float) -> tuple:
    """向 DB server 要資料,回傳 (狀態碼, Content-Type, 內容)。"""
    conn = http.client.HTTPConnection(CONFIG["up_host"], CONFIG["up_port"], timeout=timeout)
    try:
        conn.request("GET", path_and_query, headers={"Accept": "*/*", "Connection": "close", "User-Agent": "noc-ap-proxy/1.0"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("後端回應過大")
        return resp.status, resp.getheader("Content-Type") or "application/octet-stream", body
    finally:
        conn.close()


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CERT = os.path.join(SCRIPT_DIR, "ap_proxy_cert.crt")
DEFAULT_KEY = os.path.join(SCRIPT_DIR, "ap_proxy_key.pem")


def make_self_signed_cert(names_text: str, cert_path: str, key_path: str, days: int) -> None:
    """產生自簽憑證(RSA 2048、SHA-256),SAN 包含 --cert-names 裡的每個 IP / 名稱,以及 localhost / 127.0.0.1。"""
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        sys.exit("產生憑證需要 cryptography 套件,請先執行:pip install cryptography")

    names = [n.strip() for n in (names_text or "").split(",") if n.strip()]
    if not names:
        sys.exit("--cert-names 請填電視牆瀏覽器會用的 IP 或主機名稱,例如 --cert-names 10.9.9.9,ap-server")
    san, seen = [], set()
    for n in names + ["localhost", "127.0.0.1"]:
        if n in seen:
            continue
        seen.add(n)
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NOC Dashboard")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(key_path, 0o600)       # Linux 上限制只有擁有者可讀;Windows 的權限由 noc_service.ps1 設定
    except OSError:
        pass
    print(f"已產生憑證:{cert_path}\n私鑰:{key_path}(請勿外流)")
    print(f"憑證涵蓋:{', '.join(seen)}")
    print(f"到期日:{(now + datetime.timedelta(days=days)).date()}")


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        # 瀏覽器因為「不信任自簽憑證」中斷連線、掃描程式亂連…都是正常現象,不要印整串錯誤訊息
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = "NocApProxy/1.0"
    sys_version = ""
    timeout = 30                     # 讀取逾時:避免有人連上來卻不送資料,把執行緒卡住

    def _send(self, status: int, body: bytes, content_type: str, cache: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        ip = self.client_address[0]
        if not client_allowed(ip):
            now = time.time()
            if now - _last_deny_log.get(ip, 0) > 60:           # 同一個來源 1 分鐘只印一次,避免洗版
                _last_deny_log[ip] = now
                print(f"[拒絕] 來源 IP {ip} 不在 --allow-client 名單內")
            self._json({"error": {"message": "forbidden"}}, 403)
            return

        parsed = urlparse(self.path)
        path, query = parsed.path, parsed.query

        if path == "/healthz":
            try:
                status, _, _ = fetch_upstream("/api/summary", 5)
                upstream = "ok" if status == 200 else f"HTTP {status}"
            except Exception as exc:  # noqa: BLE001
                upstream = f"unreachable ({type(exc).__name__})"
            self._json({"proxy": "ok", "upstream": upstream})
            return

        if path not in PAGE_PATHS and path not in API_PATHS and path != "/favicon.ico":
            self._json({"error": {"message": "not found"}}, 404)
            return
        if path == "/api/meraki_find":
            q = (parse_qs(query).get("q") or [""])[0]
            if not (FIND_RAW_OK.match(query) and FIND_Q_OK.match(q)):
                self._json({"error": {"message": "搜尋字串不正確(3~40 個字,只能用文字、數字、空白與 . : @ -)"}}, 400)
                return
        elif path == "/api/meraki_diag":
            if not DIAG_OK.match(query):
                self._json({"error": {"message": "參數不正確"}}, 400)
                return
        elif not QUERY_OK.match(query):
            self._json({"error": {"message": "bad request"}}, 400)
            return

        target = path + (("?" + query) if query else "")
        timeout = 45 if path in ("/api/topn", "/api/meraki_find", "/api/meraki_diag") else 10        # Top N 要即時問 NFA,可能比較久
        try:
            status, ctype, body = fetch_upstream(target, timeout)
        except Exception as exc:  # noqa: BLE001 - 後端連不上、逾時…都轉成 502 給畫面顯示
            print(f"[錯誤] 連不到 DB server({type(exc).__name__}):{exc}")
            msg = "AP server 連不到資料來源(DB server),請檢查 DB server 上的服務與防火牆"
            if path in API_PATHS:
                self._json({"error": {"message": msg}}, 502)
            else:
                self._send(502, msg.encode("utf-8"), "text/plain; charset=utf-8")
            return
        # 平面圖(圖片)可以快取 1 小時,不用每次打開彈窗都重新抓;其他資料一律不快取
        self._send(status, body, ctype, "public, max-age=3600" if path == "/api/meraki_plan" and status == 200 else "no-store")

    # 其他方法一律不支援
    def _deny(self) -> None:
        self._json({"error": {"message": "method not allowed"}}, 405)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _deny

    def log_message(self, fmt: str, *args) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="NOC 大螢幕 AP server 轉發程式")
    parser.add_argument("--upstream", default=None, help="DB server 上 dashboard_server 的網址,例如 http://10.1.1.20:8080")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--allow-client", default="", help="只允許這些來源 IP/網段(逗號分隔)")
    parser.add_argument("--cert", default=None, help="HTTPS 憑證(PEM)")
    parser.add_argument("--key", default=None, help="HTTPS 私鑰(PEM)")
    parser.add_argument("--make-cert", action="store_true", help="產生自簽憑證後結束(搭配 --cert-names)")
    parser.add_argument("--cert-names", default="", help="憑證涵蓋的 IP / 主機名稱(逗號分隔),例如 10.9.9.9,ap-server")
    parser.add_argument("--cert-days", type=int, default=1825, help="自簽憑證有效天數(預設 1825 = 5 年)")
    args = parser.parse_args()

    if args.make_cert:
        make_self_signed_cert(args.cert_names, args.cert or DEFAULT_CERT, args.key or DEFAULT_KEY, args.cert_days)
        return
    use_https = bool(args.cert or args.key)
    if use_https and not (args.cert and args.key):
        sys.exit("HTTPS 需要同時指定 --cert 與 --key。")

    if not args.upstream:
        sys.exit("請用 --upstream 指定 DB server 上 dashboard_server 的網址,例如 --upstream http://10.1.1.20:8080")
    up = urlparse(args.upstream)
    if up.scheme != "http" or not up.hostname:
        sys.exit("--upstream 請填 http://IP:埠,例如 http://10.1.1.20:8080(內網段不加密)")
    CONFIG["up_host"], CONFIG["up_port"] = up.hostname, up.port or 80
    try:
        CONFIG["allowed"] = parse_allow_list(args.allow_client)
    except ValueError as exc:
        sys.exit(f"--allow-client 格式不正確:{exc}")

    if CONFIG["allowed"]:
        print(f"只允許這些來源連線:{', '.join(str(n) for n in CONFIG['allowed'])}(本機一律允許)")
    else:
        print("[警告] 沒有設定 --allow-client:任何連得到這個埠的人都能看到大螢幕,請至少用防火牆限制來源。")

    server = QuietServer((args.host, args.port), Handler)
    scheme = "http"
    if use_https:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(args.cert, args.key)
        except (OSError, ssl.SSLError) as exc:
            sys.exit(f"載入憑證失敗:{exc}")
        # 握手延到各連線自己的執行緒做,一個卡住的連線不會擋住其他人
        server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        scheme = "https"
    print(f"AP 轉發已啟動:{scheme.upper()} 監聽 {args.host}:{args.port}  →  {up.hostname}:{CONFIG['up_port']}")
    print("按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


if __name__ == "__main__":
    main()
