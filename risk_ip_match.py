"""
高風險 IP 比對器(內部主機連往高風險 IP 的偵測)
================================================
用途:把「威脅情資簽核系統」每日發佈的高風險 IP / 網段清單(txt),拿來比對各 WAN 線路
     「OUT 方向」(我方連出去)的 Top 連線。只要外部對象 IP 落在清單內,就記錄一筆「命中」,
     寫進 risk_hits.json,由大螢幕畫面讀取:自動彈出平面地圖、用紅色標出「台灣 → 該國」的連線,
     並列出命中的 IP、清單項目、線路、流量,以及(推算的)內部主機。

為什麼只看 OUT:IN(外部連進來)的高風險來源已由防火牆阻擋,OUT 才是「內部主機主動連到壞 IP」,
     可能代表主機已中毒或被控制,風險更高、也更需要馬上找出是哪一台。

資料來源(清單)
---------------
資料夾預設:C:\\noc\\risk_lists   (簽核系統每日放 txt 的地方)
- 以「最新那一批」檔案為準:取修改時間最新的 .txt,再加上「與它相差 6 小時內」的其他 .txt
  (同一次發佈產生的檔案會被一起讀,舊日期的檔案不會被讀到,避免已移除的 IP 還在比對)。
- 每行:IP 或 CIDR 網段(例如 203.0.113.5 或 198.51.100.0/24)。以 # 或 ; 開頭的是註解。
  行內如果還有其他欄位(用空白、逗號、Tab、| 分隔),第一欄當 IP,其餘當成「備註」顯示在畫面上。
- 網域(例如 evil.example.com)NetFlow 看不到,會略過,只在統計裡計數。
- 預設「只有命中『確切的單一 IP』才會彈窗/亮徽章」(ALERT_ON_CIDR = False)。
  命中「網段」(含過大網段,前綴 < /16,例如 198.18.0.0/15)範圍太廣,容易誤判:
  仍會比對、會記錄到 risk_hits_log.csv,但「不彈窗、不亮徽章」,只在高風險視窗底下低調顯示筆數。
  想恢復「一般網段也彈窗」:把 ALERT_ON_CIDR 改成 True,或設環境變數 NOC_RISK_ALERT_CIDR=1,
  或執行時加 --include-cidr(過大網段永遠不彈窗)。
改資料夾或檔名規則:
  - 環境變數 NOC_RISK_DIR / NOC_RISK_GLOB,或  python risk_ip_match.py --dir "D:\\xxx" --glob "*.txt"

限制(請務必知道)
-----------------
- NetFlow Analyzer 最細是「每小時」彙總,而且只取每條線路 OUT 方向的 Top N 連線(預設最多 300 筆)。
  流量很小的連線可能沒進 Top N,就偵測不到。它能抓到「量大的」,抓不到「低調的」。
  要更完整,要靠防火牆(Palo Alto)的流量日誌。
- 命中代表「有連到清單裡的 IP」,不等於一定中毒;請搭配「內部主機(推算)」與防火牆紀錄確認。

用法
----
python risk_ip_match.py            # 抓資料、比對、寫 risk_hits.json,並在畫面印出摘要
python risk_ip_match.py --quiet    # 只寫檔(給 dashboard_server 背景每 5 分鐘執行用)
python risk_ip_match.py --check    # 只檢查清單檔案讀得到幾筆,不連 NetFlow(第一次設定時用來確認格式)

使用前準備:pip install requests maxminddb;環境變數 NFA_API_KEY(跟其他腳本一樣)。
"""

import argparse
import csv
import glob
import ipaddress
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
VERIFY_SSL = False
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "risk_hits.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "risk_hits_log.csv")        # 每次「新出現」的命中都會追加一筆,方便事後追查
GEOIP_DB_FILE = os.path.join(SCRIPT_DIR, "dbip-country-lite.mmdb")

DEFAULT_RISK_DIR = r"C:\noc\risk_lists"
# 命中「網段」(CIDR)是否也要彈窗/亮徽章?False = 只有確切單一 IP 才告警(範圍太廣的網段容易誤判)
ALERT_ON_CIDR = os.environ.get("NOC_RISK_ALERT_CIDR", "").strip().lower() in ("1", "true", "yes")
DEFAULT_GLOB = "*.txt"
SAME_BATCH_HOURS = 6          # 與最新檔案相差幾小時內的 .txt 視為同一批一起讀

OVERSIZED_PREFIX_V4 = 16      # IPv4 前綴小於這個(/12、/14、/15…)= 過大網段,不觸發彈窗
OVERSIZED_PREFIX_V6 = 32

TIMEFRAME = "hourly"
ROWS_TRY = (300, 100, 50)     # 每條線路 OUT 方向抓幾筆連線;NFA 不接受就依序退回較小的
MAX_HITS_KEPT = 200

# 要檢查的 WAN 線路(沿用 nat_infer 的設定,新增/更換線路只需改那邊)
try:
    import nat_infer
    WAN_LINES = nat_infer.WAN_LINES
except Exception:  # noqa: BLE001
    nat_infer = None
    WAN_LINES = {}

_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
_SIZE_PATTERN = re.compile(r"([\d.]+)\s*([A-Za-z]+)")


def parse_size_to_bytes(text) -> float:
    m = _SIZE_PATTERN.match(str(text or "").strip())
    if not m:
        return 0.0
    return float(m.group(1)) * _SIZE_UNITS.get(m.group(2).upper(), 1)


# ─────────────────────────── 清單讀取與比對(純運算,不需要連網) ───────────────────────────
class RiskList:
    """高風險 IP / 網段清單。查詢方式:對每種「前綴長度」各做一次集合比對,最具體(前綴最長)的優先。"""

    def __init__(self):
        self.by_prefix = {}            # (版本, 前綴長度) -> {網路位址整數: (清單項目文字, 備註)}
        self.counts = {"ip": 0, "cidr": 0, "oversized": 0, "domain_ignored": 0, "invalid": 0}
        self.files = []

    def add(self, token: str, note: str = "") -> None:
        try:
            net = ipaddress.ip_network(token, strict=False)   # 允許寫成 1.2.3.4/24 這種「帶主機位元」的寫法
        except ValueError:
            # 長得像網域就略過(NetFlow 只有 IP);其他格式怪異的算 invalid
            if re.fullmatch(r"[A-Za-z0-9.\-_]+\.[A-Za-z]{2,}", token or ""):
                self.counts["domain_ignored"] += 1
            else:
                self.counts["invalid"] += 1
            return
        key = (net.version, net.prefixlen)
        slot = self.by_prefix.setdefault(key, {})
        if int(net.network_address) in slot:
            return                     # 同一項重複出現,只算一次
        text = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)   # /32 顯示成單純的 IP
        slot[int(net.network_address)] = (text, note.lstrip("#; ").strip())
        if net.prefixlen == net.max_prefixlen:
            self.counts["ip"] += 1
        else:
            self.counts["cidr"] += 1
            if self.is_oversized(net.version, net.prefixlen):
                self.counts["oversized"] += 1

    @staticmethod
    def is_oversized(version: int, prefixlen: int) -> bool:
        return prefixlen < (OVERSIZED_PREFIX_V4 if version == 4 else OVERSIZED_PREFIX_V6)

    def lookup(self, ip_text: str):
        """回傳 {"entry","note","oversized","match"} 或 None。最具體的命中優先。"""
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        bits = ip.max_prefixlen
        value = int(ip)
        for (ver, plen) in sorted((k for k in self.by_prefix if k[0] == ip.version), key=lambda k: -k[1]):
            masked = value & (((1 << bits) - 1) ^ ((1 << (bits - plen)) - 1))
            hit = self.by_prefix[(ver, plen)].get(masked)
            if hit:
                return {"entry": hit[0], "note": hit[1], "oversized": self.is_oversized(ver, plen),
                        "match": "ip" if plen == bits else "cidr"}
        return None


_TOKEN_SPLIT = re.compile(r"[\s,;|\t]+")


def parse_list_text(text: str, rl: RiskList) -> None:
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line[0] in "#;" or line.startswith("//"):
            continue
        parts = [p for p in _TOKEN_SPLIT.split(line) if p]
        if not parts:
            continue
        rl.add(parts[0].strip("[]\"'"), " ".join(parts[1:])[:120])


def find_list_files(directory: str, pattern: str) -> list:
    """找「最新那一批」清單檔:最新的 .txt,加上與它修改時間相差 SAME_BATCH_HOURS 小時內的其他 .txt。"""
    files = [f for f in glob.glob(os.path.join(directory, pattern)) if os.path.isfile(f)]
    if not files:
        return []
    files.sort(key=os.path.getmtime, reverse=True)
    newest = os.path.getmtime(files[0])
    return [f for f in files if newest - os.path.getmtime(f) <= SAME_BATCH_HOURS * 3600]


def load_risk_list(directory: str, pattern: str) -> RiskList:
    rl = RiskList()
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"找不到清單資料夾:{directory}")
    files = find_list_files(directory, pattern)
    if not files:
        raise FileNotFoundError(f"清單資料夾 {directory} 裡沒有符合 {pattern} 的檔案")
    for f in files:
        for enc in ("utf-8-sig", "utf-16", "cp950"):       # 常見的幾種存檔編碼依序試
            try:
                with open(f, "r", encoding=enc) as fh:
                    text = fh.read()
                break
            except (UnicodeError, UnicodeDecodeError):
                continue
        else:
            continue
        parse_list_text(text, rl)
        rl.files.append({"name": os.path.basename(f), "mtime": datetime.fromtimestamp(os.path.getmtime(f), timezone.utc).isoformat(timespec="seconds")})
    if rl.counts["ip"] + rl.counts["cidr"] == 0:
        raise ValueError("讀到的清單檔內沒有任何 IP / 網段:" + "、".join(x["name"] for x in rl.files)
                         + "(檔案格式可能不是每行一個 IP 或 CIDR,請用 --check 檢查)")
    return rl


def match_rows(rl: RiskList, rows_by_line: dict, country_of=lambda ip: (None, None)) -> list:
    """
    rows_by_line: {線路ID: [getConvData 的連線列(OUT 方向)]}
    回傳命中清單(同一條線路、同一個外部 IP 合併成一筆;可能含「過大網段」命中,由 oversized 欄位區分)。
    OUT 方向:src = 我方(NAT 後公網 IP 或內部 IP)、dst = 外部對象。
    """
    hits = {}
    for line, rows in rows_by_line.items():
        for r in rows:
            peer = r.get("dst")
            if not peer:
                continue
            try:
                if not ipaddress.ip_address(peer).is_global:
                    continue
            except ValueError:
                continue
            m = rl.lookup(peer)
            if not m:
                continue
            size = parse_size_to_bytes(r.get("traffic"))
            key = (line, peer)
            h = hits.get(key)
            if h is None:
                iso, cname = country_of(peer)
                h = hits[key] = {
                    "line": line, "line_label": WAN_LINES.get(line, line), "peer_ip": peer, "iso": iso, "country": cname,
                    "match": m["match"], "entry": m["entry"], "note": m["note"], "oversized": m["oversized"],
                    "bytes": 0.0, "port": r.get("dstport") or r.get("port"), "protocol": r.get("prot"), "app": r.get("app"),
                    "local_ip": r.get("src"), "_src": r.get("src"), "_dst": peer,
                }
            h["bytes"] += size
    out = sorted(hits.values(), key=lambda x: x["bytes"], reverse=True)
    for h in out:
        h["gb"] = round(h["bytes"] / 1024 ** 3, 4)
        h["traffic"] = f"{h['bytes'] / 1024 ** 3:.2f} GB" if h["bytes"] >= 1024 ** 3 else f"{h['bytes'] / 1024 ** 2:.1f} MB"
    return out


# ─────────────────────────── 連網抓資料 ───────────────────────────
def fetch_out_rows(api_key: str, line_id: str) -> list:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    last = None
    with requests.Session() as session:
        for rows in ROWS_TRY:
            params = {"apiKey": api_key, "DeviceID": line_id, "rows": rows, "TimeFrame": TIMEFRAME,
                      "pageCount": 1, "tablegridviewtype": "Grid", "Data": "OUT"}
            try:
                resp = session.get(f"{BASE_URL}/api/json/nfadevice/getConvData", params=params, verify=VERIFY_SSL, timeout=90)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:  # noqa: BLE001 - 網路錯誤或回應不是 JSON,換較小的筆數再試
                last = str(exc)
                continue
            if isinstance(data, dict) and "error" in data:
                last = str(data["error"])
                continue
            return data.get("Data", [])
    raise RuntimeError(f"線路 {line_id} 查詢失敗:{last}")


def make_country_lookup():
    try:
        import maxminddb
    except ImportError:
        return lambda ip: (None, None), (lambda: None)
    if not os.path.isfile(GEOIP_DB_FILE):
        return lambda ip: (None, None), (lambda: None)
    reader = maxminddb.open_database(GEOIP_DB_FILE)

    def lookup(ip: str):
        rec = reader.get(ip) or {}
        c = rec.get("country") or {}
        return c.get("iso_code"), (c.get("names") or {}).get("en")
    return lookup, reader.close


def write_output(payload: dict) -> None:
    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, OUTPUT_FILE)    # 先寫暫存檔再取代,避免大螢幕剛好讀到寫一半的檔案


def previous_keys() -> set:
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            old = json.load(f)
        return {(h["line"], h["peer_ip"]) for k in ("hits", "cidr_hits", "oversized_hits") for h in old.get(k, [])}
    except (OSError, ValueError, KeyError):
        return set()


def _hit_type(h: dict) -> str:
    """記錄檔用:這筆命中是哪一類(單一 IP 會告警;網段/過大網段只記錄)。"""
    if h["oversized"]:
        return "過大網段(不告警)"
    return "單一 IP" if h["match"] == "ip" else "網段"


def append_log(new_hits: list, now_iso: str) -> None:
    if not new_hits:
        return
    exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["發現時間(UTC)", "線路", "外部 IP", "國家", "命中的清單項目", "備註", "流量", "我方 IP(NAT)", "推算內部主機", "可信度", "命中類型"])
        for h in new_hits:
            n = h.get("nat") or {}
            w.writerow([now_iso, h["line_label"], h["peer_ip"], h.get("iso") or "", h["entry"], h["note"], h["traffic"],
                        h.get("local_ip") or "", n.get("ip") or "", n.get("confidence") or "", _hit_type(h)])


def main() -> None:
    ap = argparse.ArgumentParser(description="高風險 IP 比對器")
    ap.add_argument("--dir", default=os.environ.get("NOC_RISK_DIR", DEFAULT_RISK_DIR), help="清單資料夾")
    ap.add_argument("--glob", default=os.environ.get("NOC_RISK_GLOB", DEFAULT_GLOB), help="清單檔名規則")
    ap.add_argument("--include-cidr", action="store_true", help="一般網段(非過大)命中也彈窗;預設只有單一 IP 才彈窗")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--check", action="store_true", help="只檢查清單檔案,不連 NetFlow")
    args = ap.parse_args()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def fail(msg: str) -> None:
        # 把錯誤寫進輸出檔,大螢幕才會顯示「高風險偵測異常」,而不是靜靜地失靈
        write_output({"generated_at": now_iso, "status": "error", "message": msg, "hits": [], "cidr_hits": [], "oversized_hits": []})
        print(f"[錯誤] {msg}")
        sys.exit(1)

    try:
        rl = load_risk_list(args.dir, args.glob)
    except (OSError, ValueError) as exc:
        if args.check:
            sys.exit(f"[錯誤] {exc}")
        fail(str(exc))
    c = rl.counts
    alert_cidr = ALERT_ON_CIDR or args.include_cidr
    if not args.quiet or args.check:
        print(f"清單檔案:{'、'.join(f['name'] for f in rl.files)}")
        print(f"  單一 IP {c['ip']} 筆、網段 {c['cidr']} 筆(其中過大網段 {c['oversized']} 筆);"
              f"{'網段命中也會彈窗' if alert_cidr else '只有單一 IP 命中才會彈窗,網段只記錄不告警'}。"
              f"網域 {c['domain_ignored']} 筆(略過)、格式無法辨識 {c['invalid']} 筆")
    if args.check:
        return

    api_key = os.environ.get("NFA_API_KEY") or os.environ.get("OPM_API_KEY")
    if not api_key:
        fail("找不到環境變數 NFA_API_KEY")
    if not WAN_LINES:
        fail("找不到 WAN 線路設定(nat_infer.py 需要放在同一個資料夾)")

    rows_by_line, errors = {}, []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {line: ex.submit(fetch_out_rows, api_key, line) for line in WAN_LINES}
        for line, fut in futures.items():
            try:
                rows_by_line[line] = fut.result()
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
    if not rows_by_line:
        fail("所有線路都查不到連線資料:" + ";".join(errors[:2]))

    country_of, close_geo = make_country_lookup()
    try:
        all_hits = match_rows(rl, rows_by_line, country_of)
    finally:
        close_geo()

    # 對「會彈窗」的命中補上推算的內部主機(沿用 NAT 推算,失敗不影響命中本身)
    # 告警條件:過大網段永遠不告警;一般網段預設也不告警(alert_cidr=False),只有確切單一 IP 才告警
    alert_hits = [h for h in all_hits if not h["oversized"] and (alert_cidr or h["match"] == "ip")][:MAX_HITS_KEPT]
    alert_ids = {id(h) for h in alert_hits}
    oversized_hits = [h for h in all_hits if h["oversized"]]
    cidr_hits = [h for h in all_hits if not h["oversized"] and id(h) not in alert_ids]   # 一般網段命中,只記錄
    if nat_infer is not None:
        for line in {h["line"] for h in alert_hits}:
            group = [h for h in alert_hits if h["line"] == line]
            fake = {"line_id": line, "direction": "out",
                    "records": [{"src": h["_src"], "dst": h["_dst"], "port": h["port"]} for h in group]}
            try:
                nat_infer.enrich_topn(fake, api_key, wan_rows=rows_by_line.get(line, []))
                for h, r in zip(group, fake["records"]):
                    h["nat"] = r.get("nat")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"NAT 推算失敗:{exc}")
    for h in all_hits:
        h.pop("_src", None); h.pop("_dst", None); h.pop("bytes", None)

    old = previous_keys()
    append_log([h for h in alert_hits + cidr_hits + oversized_hits if (h["line"], h["peer_ip"]) not in old], now_iso)
    payload = {
        "generated_at": now_iso, "status": "ok", "timeframe": TIMEFRAME,
        "list_files": rl.files, "list_counts": c,
        "lines_checked": len(rows_by_line), "lines_total": len(WAN_LINES),
        "rows_checked": sum(len(v) for v in rows_by_line.values()),
        "warnings": errors[:5],
        "hits": alert_hits,
        "alert_cidr": alert_cidr,
        "cidr_hits": cidr_hits[:50],
        "oversized_hits": oversized_hits[:50],
        "note": "依外部對象 IP 與簽核系統清單比對(NetFlow 每小時彙總、只含 Top N 連線)。命中不等於一定中毒,請搭配防火牆紀錄確認。",
    }
    write_output(payload)
    if not args.quiet:
        print(f"\n檢查了 {payload['lines_checked']}/{payload['lines_total']} 條線路、{payload['rows_checked']} 筆 OUT 連線。")
        print(f"單一 IP 命中 {len(alert_hits)} 筆(會彈窗)、網段命中 {len(cidr_hits)} 筆、過大網段命中 {len(oversized_hits)} 筆(網段只記錄、不彈窗)。")
        for h in alert_hits[:15]:
            n = h.get("nat") or {}
            print(f"  {h['peer_ip']:<16}{(h.get('iso') or '--'):<4}{h['entry']:<20}{h['traffic']:>10}  {h['line_label'][:22]:<24}"
                  f"內部:{n.get('ip') or '-'}({n.get('confidence') or '-'})")
        if errors:
            print("警告:" + ";".join(errors[:3]))
        print(f"已寫出:{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
