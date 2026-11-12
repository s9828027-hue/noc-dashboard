"""
威脅地圖資料產生器(離線 GeoIP 版)
======================================
用途:從 NetFlow Analyzer 的 getConvData 抓出各線路的連線明細,挑出「外部
     公網 IP」,用本機離線的 GeoIP 資料庫查出國別,彙總成「每個國家的流量」,
     寫進 threat_map.json,供地圖視覺化使用。

為什麼用離線資料庫:
  不需要把任何 IP 送到第三方網站查詢,也不需要額外對外連線,符合「盡量
  不外露」的原則。資料庫用 DB-IP 的免費 Lite 版(免註冊)或 MaxMind GeoLite2
  (免費,需註冊)皆可,兩者格式相容。

使用前準備
----------
1. pip install requests maxminddb
2. 下載離線國別資料庫(.mmdb),任選一種,放在這支腳本旁邊:
   - DB-IP Lite「IP to Country」:https://db-ip.com/db/download/ip-to-country-lite
     (免註冊,CC BY 4.0,使用時需標註來源;解壓縮後是 .mmdb 檔)
   - 或 MaxMind GeoLite2-Country(需免費註冊帳號下載)
   然後把下面 GEOIP_DB_FILE 改成你的檔名。
   資料庫需要定期更新(每月一次)才會準確。
3. (建議)再下載 DB-IP 的「IP to ASN Lite」.mmdb,放在同一個資料夾,檔名 dbip-asn-lite.mmdb:
   https://download.db-ip.com/free/dbip-asn-lite-2026-09.mmdb.gz(解壓方式同上,月份請換成當月)
   有了它,每個 IP 會多顯示「所屬單位」(例如 CLOUDFLARENET、GOOGLE),
   並且把 Cloudflare / Google / Microsoft 這類 CDN 與雲端的 IP 分開標示。
   為什麼需要:CDN/雲端用的是「任播」IP,國別資料庫常把它標成奇怪的國家(例如 Cloudflare
   被標成加拿大),單看國別會誤判成「非預期國家」。沒有這個檔案,程式也能跑,只是少了這項標示。
4. 設定環境變數 NFA_API_KEY(同 netflow_poll_poc.py)。

用法
----
python threat_map_data.py
"""

import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

import requests
import urllib3

try:
    import maxminddb
except ImportError:
    sys.exit("請先安裝:pip install maxminddb")

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
API_KEY = os.environ.get("NFA_API_KEY")
VERIFY_SSL = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB_FILE = os.path.join(SCRIPT_DIR, "dbip-country-lite.mmdb")  # 改成你下載的檔名
ASN_DB_FILE = os.path.join(SCRIPT_DIR, "dbip-asn-lite.mmdb")     # 選用:沒有這個檔案就略過
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "threat_map.json")

# 所屬單位名稱含有這些關鍵字(不分大小寫)的 IP,視為「CDN / 大型雲端」
CDN_CLOUD_KEYWORDS = (
    "cloudflare", "google", "microsoft", "amazon", "akamai", "fastly", "oracle",
)
# 一個國家的流量有超過這個比例來自 CDN/雲端,就不當成「非預期國家」告警,只標示提醒
CDN_MOSTLY_PCT = 80

ROWS = 50            # 每條線路每個方向抓幾筆連線(越多,地圖越完整,API 也越慢)
TIMEFRAME = "hourly"

# 要納入統計的線路。只放四條對外 WAN 線路。
# F5-內網-2(5000106)不放:它是「所有流量」都經過的內網端口,跟 WAN 線路看到的是
# 同一批外部流量,一起加總會重複計算(GB 灌水約一倍)。要單獨看它時再另外處理。
LINES = {
    "5000095": "ISP-A 主線 1G/600M",
    "5000107": "ISP-B 備援 1G/600M",
    "5000097": "ISP-C 專線 300M/300M",
    "5000108": "ISP-D 網際網路 1G/600M(Edge-FW WAN2)",
    # "5000106": "F5-內網-2",   # 會重複計算,預設關閉
}

# ── 由你依實際業務情況調整 ──────────────────────────────────────
# 正常會往來的國家(ISO 兩碼)。不在這份清單、且流量不小的國家會被標成
# 「非預期」,這就是「異常流量從非業務相關國家湧入」的判斷依據。
EXPECTED_COUNTRIES = {"TW", "US", "JP", "SG", "HK", "IE", "DE", "NL", "GB"}
# 你想特別標註的高風險地區(預設留空,請依公司資安政策自行填入)
HIGH_RISK_COUNTRIES: set = set()

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit("找不到環境變數 NFA_API_KEY。請先設定:$env:NFA_API_KEY = \"你的APIKey\"")

_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
_SIZE_PATTERN = re.compile(r"([\d.]+)\s*([A-Za-z]+)")


def parse_size_to_bytes(text: str) -> float:
    """'15.075 GB' -> bytes"""
    m = _SIZE_PATTERN.match((text or "").strip())
    if not m:
        return 0.0
    value, unit = m.groups()
    return float(value) * _SIZE_UNITS.get(unit.upper(), 1)


def is_public(ip: str) -> bool:
    """只保留公網 IP;私有網段、保留位址、'Others' 之類都排除。"""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def fetch_conversations(device_id: str, direction: str) -> list:
    params = {
        "apiKey": API_KEY, "DeviceID": device_id, "rows": ROWS,
        "TimeFrame": TIMEFRAME, "pageCount": 1,
        "tablegridviewtype": "Grid", "Data": direction.upper(),
    }
    resp = requests.get(
        f"{BASE_URL}/api/json/nfadevice/getConvData",
        params=params, verify=VERIFY_SSL, timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        print(f"  [警告] {device_id}/{direction}:{data['error']}")
        return []
    return data.get("Data", [])


def main() -> None:
    if not os.path.isfile(GEOIP_DB_FILE):
        sys.exit(f"找不到 GeoIP 資料庫:{GEOIP_DB_FILE}\n請依檔案開頭說明下載 .mmdb 並修改 GEOIP_DB_FILE。")

    reader = maxminddb.open_database(GEOIP_DB_FILE)
    asn_reader = maxminddb.open_database(ASN_DB_FILE) if os.path.isfile(ASN_DB_FILE) else None
    if asn_reader is None:
        print("(提示)找不到 dbip-asn-lite.mmdb,略過「所屬單位 / CDN 標示」。")

    org_cache: dict = {}

    def org_of(ip: str) -> str:
        """查這個 IP 屬於哪個單位;沒有 ASN 資料庫或查不到就回傳空字串。"""
        if asn_reader is None:
            return ""
        if ip not in org_cache:
            rec = asn_reader.get(ip) or {}
            org_cache[ip] = str(
                rec.get("autonomous_system_organization") or rec.get("organization") or ""
            )
        return org_cache[ip]

    def is_cdn(org: str) -> bool:
        return any(k in org.lower() for k in CDN_CLOUD_KEYWORDS)

    # direction -> country -> 彙總
    stats = {
        "in": defaultdict(lambda: {"bytes": 0.0, "cdn_bytes": 0.0, "ips": defaultdict(float)}),
        "out": defaultdict(lambda: {"bytes": 0.0, "cdn_bytes": 0.0, "ips": defaultdict(float)}),
    }
    country_names: dict = {}
    unknown_bytes = {"in": 0.0, "out": 0.0}

    for device_id, label in LINES.items():
        for direction in ("in", "out"):
            rows = fetch_conversations(device_id, direction)
            print(f"{label:<28}{direction.upper():<4} 取得 {len(rows)} 筆連線")
            for row in rows:
                # 外部那一側:IN 方向是「來源」,OUT 方向是「目的地」
                external_ip = row.get("src") if direction == "in" else row.get("dst")
                if not external_ip or not is_public(external_ip):
                    continue
                size = parse_size_to_bytes(row.get("traffic", "0"))

                record = reader.get(external_ip) or {}
                country = record.get("country") or {}
                iso = country.get("iso_code")
                if not iso:
                    unknown_bytes[direction] += size
                    continue
                country_names[iso] = (country.get("names") or {}).get("en", iso)
                stats[direction][iso]["bytes"] += size
                if is_cdn(org_of(external_ip)):
                    stats[direction][iso]["cdn_bytes"] += size
                stats[direction][iso]["ips"][external_ip] += size

    reader.close()
    if asn_reader is not None:
        asn_reader.close()

    def build(direction: str) -> list:
        total = sum(v["bytes"] for v in stats[direction].values()) or 1.0
        result = []
        for iso, v in stats[direction].items():
            top_ips = sorted(v["ips"].items(), key=lambda kv: kv[1], reverse=True)[:3]
            cdn_pct = round(v["cdn_bytes"] / v["bytes"] * 100, 1) if v["bytes"] else 0.0
            result.append({
                "iso": iso,
                "name": country_names.get(iso, iso),
                "gb": round(v["bytes"] / 1024 ** 3, 3),
                "pct": round(v["bytes"] / total * 100, 2),
                "ip_count": len(v["ips"]),
                "top_ips": [{"ip": ip, "org": org_of(ip), "gb": round(b / 1024 ** 3, 3)}
                            for ip, b in top_ips],
                "cdn_pct": cdn_pct,                       # 這個國家的流量有幾 % 來自 CDN/雲端
                "cdn_mostly": cdn_pct >= CDN_MOSTLY_PCT,   # 大部分是 CDN/雲端 → 國別不可靠
                "unexpected": iso not in EXPECTED_COUNTRIES,
                "high_risk": iso in HIGH_RISK_COUNTRIES,
            })
        result.sort(key=lambda r: r["gb"], reverse=True)
        return result

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "timeframe": TIMEFRAME,
        "note": "只統計各線路 Top 連線中的外部公網 IP,不含未進入排行的小流量連線。",
        "in": build("in"),
        "out": build("out"),
        "unknown_gb": {k: round(v / 1024 ** 3, 3) for k, v in unknown_bytes.items()},
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n已寫入 {OUTPUT_FILE}\n")
    for direction in ("in", "out"):
        print(f"── {direction.upper()} 方向 Top 國家 ──")
        for c in output[direction][:8]:
            if c["unexpected"] and c["cdn_mostly"]:
                flag = " ℹ非預期國別,但多為 CDN/雲端(國別不可靠)"
            else:
                flag = " ⚠非預期" if c["unexpected"] else ""
            flag += " 🔴高風險" if c["high_risk"] else ""
            print(f"  {c['iso']} {c['name']:<18}{c['gb']:>9.2f} GB {c['pct']:>6.1f}%  ({c['ip_count']} IPs){flag}")
            if c["unexpected"] or c["high_risk"]:
                for t in c["top_ips"]:
                    org = f"  [{t['org']}]" if t["org"] else ""
                    print(f"       {t['ip']:<18}{t['gb']:>8.2f} GB{org}")


if __name__ == "__main__":
    main()
