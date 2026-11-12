"""
NOC 大螢幕 — 本機資料伺服器
==============================
用途:把前面幾支輪詢腳本產生的資料檔,整合成一份 JSON 給大螢幕網頁(dashboard.html)讀取,
     並提供「Top N 彈窗」需要的即時查詢。

它做三件事
----------
1. 提供網頁:瀏覽器開 http://127.0.0.1:8080/ 就是大螢幕畫面(dashboard.html)。
2. /api/summary:讀這四份資料檔,合併後回傳(每份附上「多久沒更新」):
     latest.json               <- netflow_poll_poc.py    (5 條線路使用率)
     fw_health_latest.json     <- fw_health_poll.py      (兩台防火牆健康度)
     availability_latest.json  <- availability_poll.py   (核心設備存活率)
     threat_map.json           <- threat_map_data.py     (國別流量)
   另外 /api/nat_map 回傳 nat_map.json(nat_infer.py 的推算結果,目前畫面不用)。
3. /api/topn:使用者點線路或線路超標時,即時去 NetFlow Analyzer 查 Top N 連線
   (呼叫 fetch_topn.py 的函式),結果快取 60 秒,避免一直打 OpManager。

安全設計(重要)
--------------
- API Key 只留在這支伺服器的環境變數裡,不會傳給瀏覽器、也不會寫進網頁。
- 預設只綁 127.0.0.1(只有這台電腦自己能連)。如果大螢幕要用「另一台電腦」開網頁,
  才需要加 --host 0.0.0.0,而且這個頁面沒有帳號驗證,請只放在內部網段、不要對外。
- 只提供 dashboard.html 和 /api/*,不會把資料夾裡的其他檔案(history.csv 等)公開出去。
- /api/topn 只接受白名單內的線路 ID 和 in/out,不會把使用者輸入直接拿去組網址。

使用前準備
----------
1. pip install requests
2. 設定環境變數 NFA_API_KEY(給 Top N 查詢用;沒設也能開,只是點線路看不到 Top N)。
3. 先讓輪詢腳本各自跑起來(各開一個 PowerShell 視窗):
     python netflow_poll_poc.py / python fw_health_poll.py / python availability_poll.py
   threat_map.json 這支伺服器會自動每 30 分鐘更新(需要 dbip-country-lite.mmdb 和 NFA_API_KEY)。
   nat_map.json(NAT 前內部 IP 推算)也由這支伺服器每 30 分鐘更新,目前只產生資料、畫面不顯示。

用法
----
python dashboard_server.py                    # 預設 127.0.0.1:8080
python dashboard_server.py --demo             # 示範模式:不連任何設備,顯示模擬資料(見 demo/)
python dashboard_server.py --port 9000
python dashboard_server.py --host 0.0.0.0     # 讓區網其他電腦也能開(無驗證,請小心)
python dashboard_server.py --host 0.0.0.0 --allow-from 10.1.1.5   # 只讓指定 IP(例如 AP server)連進來
python dashboard_server.py --no-threat-refresh  # 不自動更新威脅地圖資料
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

HTML_FILE = os.path.join(SCRIPT_DIR, "dashboard.html")

# demo 模式(--demo):不連任何真實設備、不讀寫資料檔,所有資料由 demo/demo_data.py 即時算出來。
# 用來展示畫面或開發前端;正式環境不要加這個參數。
DEMO = None        # 啟用時會是 demo_data 模組

# 資料來源名稱 -> (檔名, 超過幾秒沒更新就視為「資料過期」)
SOURCES = {
    "netflow": ("latest.json", 300),
    "firewall": ("fw_health_latest.json", 300),
    "availability": ("availability_latest.json", 300),
    "threat_map": ("threat_map.json", 7200),
    "nat_map": ("nat_map.json", 7200),   # NAT 前內部 IP 推算(背景資料;Top N 視窗另外即時推算)
    "meraki": ("meraki_latest.json", 600),   # Meraki 大樓 AP(meraki_poll.py 每分鐘更新;超過 10 分鐘視為過期)
    "risk_hits": ("risk_hits.json", 900),   # 高風險 IP 命中(risk_ip_match.py 每 5 分鐘更新;超過 15 分鐘視為過期)
}
SUMMARY_SOURCES = ["netflow", "firewall", "availability", "threat_map", "risk_hits", "meraki"]   # 給大螢幕畫面用的資料

# 各來源該執行哪支腳本(資料檔不存在時,提示使用者要跑哪一支)
SOURCE_HINT = {
    "netflow": "netflow_poll_poc.py",
    "firewall": "fw_health_poll.py",
    "availability": "availability_poll.py",
    "threat_map": "threat_map_data.py",
    "nat_map": "nat_infer.py",
    "risk_hits": "risk_ip_match.py",
    "meraki": "meraki_poll.py(先執行 --set-key 設定金鑰)",
}

# 只允許哪些來源 IP 連進來(--allow-from 設定;沒設定 = 不限制)。本機(127.0.0.1)一律允許,方便自己檢查。
ALLOWED_CLIENTS: list = []


def parse_allow_list(text: str) -> list:
    """'10.1.1.5, 10.2.0.0/24' -> [ip_network, ...]"""
    nets = []
    for part in (text or "").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def client_allowed(ip: str) -> bool:
    if not ALLOWED_CLIENTS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or any(addr in net for net in ALLOWED_CLIENTS)


RISK_REFRESH_MIN = 5    # 高風險 IP 比對多久跑一次(分鐘)
MERAKI_REFRESH_MIN = 1  # Meraki 大樓 AP 狀態多久更新一次(分鐘)
PLANS_DIR = os.path.join(SCRIPT_DIR, "meraki_plans")
PLAN_NAME_OK = re.compile(r"^[A-Za-z0-9_.-]{1,120}\.(png|jpg|jpeg|gif)$")
PLAN_TYPES = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif"}
_find_last = 0.0      # 上一次搜尋的時間(限流用)
TOPN_CACHE_SEC = 60
TOPN_MAX_ROWS = 50
THREAT_REFRESH_MIN = 30

_topn_cache: dict = {}
_topn_lock = threading.Lock()


def read_source(name: str) -> dict:
    """讀一份資料檔。回傳 {available, age_sec, stale, data 或 reason}。"""
    filename, stale_after = SOURCES[name]
    path = os.path.join(SCRIPT_DIR, filename)
    if not os.path.isfile(path):
        return {
            "available": False,
            "reason": f"找不到 {filename},請先執行 {SOURCE_HINT[name]}",
        }
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "reason": f"{filename} 讀取失敗:{exc}"}

    age = max(0, int(time.time() - os.path.getmtime(path)))
    return {"available": True, "age_sec": age, "stale": age > stale_after, "data": data}


def build_summary() -> dict:
    if DEMO:
        return DEMO.summary()
    return {
        "server_time": time.time(),
        "topn_enabled": bool(os.environ.get("NFA_API_KEY")),
        **{name: read_source(name) for name in SUMMARY_SOURCES},
    }


def get_topn(line_id: str, direction: str, rows: int) -> dict:
    """查 Top N。延遲匯入 fetch_topn,這樣沒設 NFA_API_KEY 時其他功能不受影響。"""
    if DEMO:
        return DEMO.topn(line_id, direction, rows)
    if not os.environ.get("NFA_API_KEY"):
        return {"error": {"message": "伺服器沒有設定 NFA_API_KEY,無法查詢 Top N"}}

    key = (line_id, direction, rows)
    now = time.time()
    with _topn_lock:
        hit = _topn_cache.get(key)
        if hit and now - hit[0] < TOPN_CACHE_SEC:
            return hit[1]

    try:
        import fetch_topn  # noqa: WPS433 - 需要 NFA_API_KEY 已設好才能匯入
    except SystemExit as exc:
        return {"error": {"message": f"fetch_topn 載入失敗:{exc}"}}
    except ImportError as exc:
        return {"error": {"message": f"找不到 fetch_topn.py:{exc}"}}

    if line_id not in fetch_topn.LINE_LABELS:
        return {"error": {"message": "不認得這個線路 ID"}}

    try:
        result = fetch_topn.build_records(line_id, direction, rows=rows)
    except Exception as exc:  # noqa: BLE001 - 網路或 API 錯誤都回給前端顯示
        return {"error": {"message": f"查詢失敗:{exc}"}}

    if "error" not in result:
        # 補上「NAT 前內部 IP(推算)」。推算失敗不能影響 Top N 本身,所以任何錯誤都只記在 result["nat"]
        try:
            import nat_infer  # noqa: WPS433
            nat_infer.enrich_topn(result, os.environ["NFA_API_KEY"])
        except Exception as exc:  # noqa: BLE001
            result["nat"] = {"status": "error", "message": f"{type(exc).__name__}: {exc}"}
        with _topn_lock:
            _topn_cache[key] = (now, result)
    return result


def refresh_loop(script_name: str, target_name: str, log_name: str, interval_min: int, extra_args=()) -> None:
    """背景執行緒:定期重跑一支腳本,更新它產生的資料檔(threat_map.json、nat_map.json 都用這個)。"""
    script = os.path.join(SCRIPT_DIR, script_name)
    log_path = os.path.join(SCRIPT_DIR, log_name)
    target = os.path.join(SCRIPT_DIR, target_name)

    while True:
        need_run = (not os.path.isfile(target)) or (time.time() - os.path.getmtime(target) > interval_min * 60)
        if need_run and os.path.isfile(script):
            try:
                with open(log_path, "w", encoding="utf-8") as log:
                    subprocess.run(
                        [sys.executable, script, *extra_args], cwd=SCRIPT_DIR, stdout=log,
                        stderr=subprocess.STDOUT, timeout=300, check=False,
                    )
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"[{script_name}] 背景更新失敗:{exc}")
        time.sleep(60)


class Handler(BaseHTTPRequestHandler):
    server_version = "NocDashboard/1.0"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - http.server 規定的方法名稱
        if not client_allowed(self.client_address[0]):
            self._json({"error": {"message": "forbidden"}}, 403)
            return
        parsed = urlparse(self.path)

        if parsed.path in ("/", "/index.html", "/dashboard.html"):
            try:
                with open(HTML_FILE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(404, "找不到 dashboard.html(要跟這支程式放同一個資料夾)".encode("utf-8"),
                           "text/plain; charset=utf-8")
            return

        if parsed.path == "/api/summary":
            self._json(build_summary())
            return

        if parsed.path == "/api/topn":
            qs = parse_qs(parsed.query)
            line_id = (qs.get("line") or [""])[0]
            direction = (qs.get("dir") or [""])[0].lower()
            try:
                rows = int((qs.get("rows") or ["10"])[0])
            except ValueError:
                rows = 10
            rows = max(1, min(TOPN_MAX_ROWS, rows))

            if direction not in ("in", "out") or not line_id.isdigit():
                self._json({"error": {"message": "參數錯誤"}}, 400)
                return
            self._json(get_topn(line_id, direction, rows))
            return

        if parsed.path == "/api/meraki_plan":   # Meraki 樓層平面圖(由 meraki_poll.py 下載到 meraki_plans 資料夾)
            name = (parse_qs(parsed.query).get("f") or [""])[0]
            path = os.path.join(DEMO.PLANS_DIR if DEMO else PLANS_DIR, name)
            if not PLAN_NAME_OK.match(name) or not os.path.isfile(path):   # 只允許單純檔名,擋掉 ../ 之類的路徑
                self._json({"error": {"message": "not found"}}, 404)
                return
            with open(path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", PLAN_TYPES[name.rsplit(".", 1)[1].lower()])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=3600")    # 圖幾乎不變;網址帶 v=md5,圖更新時網址會跟著變
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/meraki_find":   # 搜尋裝置/使用者連在哪支 AP(不記錄搜尋字串,也不把結果寫到任何檔案)
            self._meraki_find((parse_qs(parsed.query).get("q") or [""])[0])
            return

        if parsed.path == "/api/meraki_diag":   # 單一用戶連線品質診斷(同樣不記錄 MAC、不寫檔)
            qs = parse_qs(parsed.query)
            self._meraki_diag((qs.get("mac") or [""])[0], (qs.get("h") or ["2"])[0])
            return

        if parsed.path == "/api/nat_map":   # NAT 推算結果(之後要在畫面顯示時使用;現在只是讀檔)
            self._json(read_source("nat_map"))
            return

        if parsed.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return

        self._json({"error": {"message": "not found"}}, 404)

    def _meraki_find(self, q: str) -> None:
        global _find_last
        now = time.time()
        if now - _find_last < 0.5:                       # 全站每 0.5 秒最多一次搜尋,避免有人狂按把 Meraki 的呼叫額度用完
            self._json({"error": {"message": "搜尋太頻繁,請稍後再試"}}, 429)
            return
        _find_last = now
        try:
            if DEMO:
                self._json(DEMO.find(q))
                return
            import meraki_poll  # noqa: WPS433
            if not meraki_poll.has_key():
                self._json({"error": {"message": "Meraki 金鑰尚未設定"}}, 503)
                return
            self._json(meraki_poll.find_clients(q))
        except ValueError:
            self._json({"error": {"message": "搜尋字串不正確(3~40 個字,只能用文字、數字、空白與 . : @ -)"}}, 400)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": {"message": f"Meraki 查詢失敗:{str(exc)[:120]}"}}, 502)

    def _meraki_diag(self, mac: str, hours: str) -> None:
        global _find_last
        now = time.time()
        if now - _find_last < 0.5:                       # 和搜尋共用限流:全站每 0.5 秒最多一次,保護 Meraki 呼叫額度
            self._json({"error": {"message": "查詢太頻繁,請稍後再試"}}, 429)
            return
        _find_last = now
        try:
            if DEMO:
                self._json(DEMO.diag(mac, int(hours)))
                return
            import meraki_poll  # noqa: WPS433
            if not meraki_poll.has_key():
                self._json({"error": {"message": "Meraki 金鑰尚未設定"}}, 503)
                return
            self._json(meraki_poll.diagnose_client(mac, int(hours)))
        except ValueError:
            self._json({"error": {"message": "參數不正確(需要完整 MAC,時間範圍只能 1、2、4、24 小時)"}}, 400)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": {"message": f"Meraki 查詢失敗:{str(exc)[:120]}"}}, 502)

    def log_message(self, fmt: str, *args) -> None:  # 安靜一點,不要每個請求都印
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="NOC 大螢幕本機資料伺服器")
    parser.add_argument("--host", default="127.0.0.1", help="預設 127.0.0.1(只有本機能連)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--risk-dir", default=None, help="高風險 IP 清單資料夾(簽核系統每日放 txt 的地方);不指定就用 risk_ip_match.py 內建的預設路徑")
    parser.add_argument("--no-threat-refresh", action="store_true", help="不自動更新威脅地圖資料")
    parser.add_argument("--allow-from", default="", help="只允許這些來源 IP 連進來(逗號分隔,可用網段,例如 10.1.1.5,10.2.0.0/24);"
                                                          "AP server 與 DB server 分開時,填 AP server 的 IP")
    parser.add_argument("--demo", action="store_true", help="示範模式:不連任何真實設備,畫面顯示模擬資料(demo/demo_data.py)")
    args = parser.parse_args()
    global ALLOWED_CLIENTS, DEMO
    try:
        ALLOWED_CLIENTS = parse_allow_list(args.allow_from)
    except ValueError as exc:
        sys.exit(f"--allow-from 格式不正確:{exc}")

    if not os.path.isfile(HTML_FILE):
        sys.exit(f"找不到 {HTML_FILE},dashboard.html 要跟這支程式放同一個資料夾。")

    if args.demo:
        sys.path.insert(0, os.path.join(SCRIPT_DIR, "demo"))
        import demo_data  # noqa: WPS433
        DEMO = demo_data
        print("[示範模式] 畫面上的資料全部是模擬的,不會連到任何設備,也不會讀寫資料檔。")
    elif not os.environ.get("NFA_API_KEY"):
        print("[提醒] 沒有設定 NFA_API_KEY:大螢幕可以開,但點線路看不到 Top N,威脅地圖也不會自動更新。")
    elif not args.no_threat_refresh:
        threading.Thread(target=refresh_loop, args=("threat_map_data.py", "threat_map.json", "threat_map_refresh.log", THREAT_REFRESH_MIN), daemon=True).start()
        threading.Thread(target=refresh_loop, args=("nat_infer.py", "nat_map.json", "nat_map_refresh.log", THREAT_REFRESH_MIN, ("--quiet",)), daemon=True).start()
        # 高風險 IP 比對:每 5 分鐘一次(讀簽核系統清單 + 查各線路 OUT 方向的 Top 連線)
        if args.risk_dir:
            os.environ["NOC_RISK_DIR"] = args.risk_dir      # 背景子程序會繼承這個環境變數
        threading.Thread(target=refresh_loop, args=("risk_ip_match.py", "risk_hits.json", "risk_refresh.log", RISK_REFRESH_MIN, ("--quiet",)), daemon=True).start()

    # Meraki 大樓 AP:有金鑰才啟動(沒設金鑰就完全不影響原本畫面,「核心設備」表格照常顯示)
    try:
        if DEMO:
            raise ImportError("示範模式不啟動背景更新")
        import meraki_poll  # noqa: WPS433
        if os.path.isfile(os.path.join(SCRIPT_DIR, "meraki_poll.py")) and meraki_poll.has_key():
            threading.Thread(target=refresh_loop, args=("meraki_poll.py", "meraki_latest.json", "meraki_refresh.log", MERAKI_REFRESH_MIN, ("--quiet",)), daemon=True).start()
            print("已啟動 Meraki 大樓 AP 背景更新(每分鐘)。")
        else:
            print("[提醒] 沒有 Meraki API Key(meraki_poll.py --set-key),大樓 AP 區塊不啟用,畫面維持原本的「核心設備」表格。")
    except ImportError as exc:
        if not DEMO:
            print(f"[提醒] Meraki 功能未啟用:{exc}")

    if ALLOWED_CLIENTS:
        print(f"只允許這些來源連線:{', '.join(str(n) for n in ALLOWED_CLIENTS)}(本機一律允許)")
    elif args.host != "127.0.0.1":
        print("[警告] 你讓區網其他電腦也能連這個頁面,但它沒有帳號驗證,而且沒有設定 --allow-from,請只放在內部網段。")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"大螢幕已啟動:http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}/")
    print("按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")


if __name__ == "__main__":
    main()
