"""
Top N 連線查詢工具(告警彈窗用)— Conversation 版
=====================================================
用途:給定一條線路的 Interface ID 跟方向(IN/OUT),打 getConvData 抓出
     「來源IP / 目的IP / 服務埠 / 流量」這種完整連線紀錄,並額外打一次
     getSourceData(IN) 或 getDstData(OUT)算出這條線路的總流量,拿來換算
     每筆連線佔比 %。

方向對應(實測驗證過):
  IN  (下載) -> getConvData(Data=IN)  + getSourceData(Data=IN) 的 Total 當分母
  OUT (上傳) -> getConvData(Data=OUT) + getDstData(Data=OUT)   的 Total 當分母

注意事項
--------
1. 「日期時間」欄位是整個查詢時間區間(例如 14:54~15:54),不是單筆連線的
   精確時間戳記——NetFlow Analyzer 這支 API 最細只能設定到 TimeFrame=hourly
   的彙總資料,沒有秒級/分鐘級的精確時間點。
2. F5 NAT 的關係,IN 方向的「目的IP」、OUT 方向的「來源IP」在這個監控點
   會永遠是 F5 的對外公網 IP(203.0.113.10 這類),不是真正的內部主機
   ——這是已知限制,不是程式錯誤,設計稿的告警彈窗要標註「內部主機請對照
   F5 連線紀錄」。
3. `getConvData` 的 `Data=OUT` 尚未實測過,先假設欄位結構跟 IN 方向對稱;
   如果實測發現欄位不同,要回來調整 build_records()。

使用前準備
----------
1. pip install requests
2. 設定環境變數 NFA_API_KEY(同 netflow_poll_poc.py)

用法
----
python fetch_topn.py <DeviceID> <in|out> [rows]
"""

import os
import re
import sys

import requests
import urllib3

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
API_KEY = os.environ.get("NFA_API_KEY")
VERIFY_SSL = False

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit(
        "找不到環境變數 NFA_API_KEY。\n"
        "請先設定:  $env:NFA_API_KEY = \"你的APIKey\"  (PowerShell)\n"
    )

LINE_LABELS = {
    "5000095": "ISP-A 主線 1G/600M",
    "5000107": "ISP-B 備援 1G/600M",
    "5000097": "ISP-C 專線 300M/300M",
    "5000108": "ISP-D 網際網路 1G/600M",
    "5000105": "F5-內網-1",
    "5000106": "F5-內網-2",
}

# direction -> (Total 分母要打的端點, Data 參數)
TOTAL_SOURCE = {
    "in": {"endpoint": "getSourceData", "data": "IN"},
    "out": {"endpoint": "getDstData", "data": "OUT"},
}

_SIZE_UNITS = {
    "B": 1,
    "KB": 1024,
    "MB": 1024 ** 2,
    "GB": 1024 ** 3,
    "TB": 1024 ** 4,
}
_SIZE_PATTERN = re.compile(r"([\d.]+)\s*([A-Za-z]+)")


def parse_size_to_bytes(text: str) -> float:
    """把 '15.075 GB' 這種字串轉成 bytes 數字,方便算百分比。"""
    if not text:
        return 0.0
    m = _SIZE_PATTERN.match(text.strip())
    if not m:
        return 0.0
    value, unit = m.groups()
    unit = unit.upper()
    return float(value) * _SIZE_UNITS.get(unit, 1)


def _request(endpoint: str, params: dict) -> dict:
    resp = requests.get(
        f"{BASE_URL}/api/json/nfadevice/{endpoint}",
        params=params,
        verify=VERIFY_SSL,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_conversations(device_id: str, direction: str, rows: int = 10, timeframe: str = "hourly") -> dict:
    params = {
        "apiKey": API_KEY,
        "DeviceID": device_id,
        "rows": rows,
        "TimeFrame": timeframe,
        "pageCount": 1,
        "tablegridviewtype": "Grid",
        "Data": direction.upper(),
    }
    return _request("getConvData", params)


def fetch_total_bytes(device_id: str, direction: str, timeframe: str = "hourly") -> float:
    """打 getSourceData(IN) 或 getDstData(OUT),只為了拿 devDetails.Total 當分母。"""
    cfg = TOTAL_SOURCE[direction]
    params = {
        "apiKey": API_KEY,
        "DeviceID": device_id,
        "rows": 1,
        "TimeFrame": timeframe,
        "pageCount": 1,
        "tablegridviewtype": "Grid",
        "isNetwork": "false",
        "isLocation": "false",
        "ResolveDNS": "false",
        "Data": cfg["data"],
    }
    raw = _request(cfg["endpoint"], params)
    total_text = raw.get("devDetails", {}).get("Total", "0")
    return parse_size_to_bytes(total_text)


def build_records(device_id: str, direction: str, rows: int = 10) -> dict:
    conv_raw = fetch_conversations(device_id, direction, rows=rows)
    if "error" in conv_raw:
        return {"error": conv_raw["error"]}

    total_bytes = fetch_total_bytes(device_id, direction)

    records = []
    for row in conv_raw.get("Data", []):
        row_bytes = parse_size_to_bytes(row.get("traffic", "0"))
        pct = (row_bytes / total_bytes * 100) if total_bytes else 0.0
        records.append({
            "src": row.get("src"),
            "dst": row.get("dst"),
            "port": row.get("dstport") or row.get("port"),
            "protocol": row.get("prot"),
            "app": row.get("app"),
            "traffic": row.get("traffic"),
            "pct": round(pct, 2),
        })

    return {
        "line_id": device_id,
        "line_label": LINE_LABELS.get(device_id, device_id),
        "direction": direction,
        "time_range": f"{conv_raw.get('startTime')} ~ {conv_raw.get('endTime')}",
        "total_bytes_readable": None,  # 若需要可自行用 total_bytes 換算回可讀字串
        "records": records,
    }


def print_records(result: dict) -> None:
    if "error" in result:
        print(f"[錯誤] {result['error'].get('message')}")
        return

    print(f"\n{result['line_label']}({result['line_id']}) — 方向:{result['direction'].upper()}")
    print(f"時間區間:{result['time_range']}")
    print(f"{'來源IP':<18}{'目的IP':<18}{'服務(Port)':<20}{'流量':>10}{'佔比':>8}")
    print("-" * 76)
    for rec in result["records"]:
        service = f"{rec['app']} ({rec['port']}/{rec['protocol']})"
        print(f"{rec['src']:<18}{rec['dst']:<18}{service:<20}{rec['traffic']:>10}{rec['pct']:>7.2f}%")


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit("用法:python fetch_topn.py <DeviceID> <in|out> [rows]")

    device_id = sys.argv[1]
    direction = sys.argv[2].lower()
    rows = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    result = build_records(device_id, direction, rows=rows)
    print_records(result)


if __name__ == "__main__":
    main()
