"""
核心設備存活率輪詢(回應時間 / 丟包率 / 是否可 ping)
======================================================
用途:定期從 OpManager 讀取幾台核心設備的:
       - 回應時間(ms)
       - 丟包率(%)
       - 是否可 ping 通
       - OpManager 判定的狀態(Clear / Attention / Trouble / Critical ...)
     持續記錄到 availability_history.csv,並寫一份 availability_latest.json。

資料來源:OpManager REST API 的 device/getDeviceSummary(唯讀查詢)。

注意
----
這些數值是 OpManager 自己 ping/輪詢的結果,量測位置是「OpManager 主機到該設備」,
不是「你這台電腦到該設備」。數值更新頻率取決於 OpManager 的狀態輪詢間隔。

「OpManager 判定的狀態」跟「能不能 ping 通」是兩回事:設備可能 ping 得通、延遲正常,
但因為某個告警(例如 HA 狀態、某項門檻)被標成 Critical。所以兩個都會顯示。

使用前準備
----------
1. pip install requests
2. 設定環境變數 OPM_API_KEY(或沿用 NFA_API_KEY):
   PowerShell:  $env:OPM_API_KEY = "你的APIKey"
3. 用法:python availability_poll.py
"""

import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
API_KEY = os.environ.get("OPM_API_KEY") or os.environ.get("NFA_API_KEY")
POLL_INTERVAL_SEC = 60
VERIFY_SSL = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(SCRIPT_DIR, "availability_history.csv")
LATEST_FILE = os.path.join(SCRIPT_DIR, "availability_latest.json")

# 要監控的核心設備。names 是「依序嘗試」的名稱清單:OpManager 的 name 參數
# 只認特定格式,同一台設備用 IP 或 deviceName 可能一個成功一個失敗,
# 所以第一個被 API 接受的名稱會被記住,之後都用它。
DEVICES = [
    # names:OpManager 裡這台設備可能用的名稱(管理 IP 或主機名稱),會依序嘗試
    {"label": "Core-SW-1", "names": ["10.0.0.254", "core-sw-1.example.com"]},
    {"label": "Core-SW-2", "names": ["10.0.1.254", "Core-SW-2"]},
    {"label": "FW-A", "names": ["10.0.0.252", "FW-A"]},
    {"label": "FW-B", "names": ["10.0.0.253", "FW-B"]},
]

# 告警門檻。None = 只顯示、不告警(先觀察,之後再填)。
# 「無法 ping 通」不需要門檻,一律告警。
THRESHOLDS = {
    "response_ms": None,   # 回應時間超過幾毫秒,例如 50
    "packet_loss_pct": None,  # 丟包率超過幾 %,例如 1
}

HISTORY_FIELDS = [
    "timestamp_utc", "label", "response_ms", "packet_loss_pct",
    "pingable", "status_text",
]

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit("找不到環境變數 OPM_API_KEY(或 NFA_API_KEY)。請先設定:$env:OPM_API_KEY = \"你的APIKey\"")

# 記住每台設備最後成功的名稱
_working_name: dict = {}


def to_number(text):
    """'001ms' -> 1.0、'0' -> 0.0、'12.5 ms' -> 12.5;解析不出來回傳 None。"""
    if text is None:
        return None
    match = re.search(r"[\d.]+", str(text))
    return float(match.group()) if match else None


def to_bool(value):
    """'true' / True -> True;'false' / False -> False;其他 -> None。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def find_key(node, wanted: str):
    """在巢狀 JSON 裡找第一個叫 wanted 的欄位(不分大小寫)。"""
    if isinstance(node, dict):
        for key, val in node.items():
            if key.lower() == wanted.lower():
                return val
        for val in node.values():
            found = find_key(val, wanted)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = find_key(item, wanted)
            if found is not None:
                return found
    return None


def fetch_summary(device: dict) -> dict:
    """依序嘗試候選名稱,回傳 getDeviceSummary 的原始 JSON。"""
    label = device["label"]
    names = device["names"]
    if label in _working_name:
        names = [_working_name[label]]

    last_error = None
    for name in names:
        resp = requests.get(
            f"{BASE_URL}/api/json/device/getDeviceSummary",
            params={"apiKey": API_KEY, "name": name},
            verify=VERIFY_SSL, timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and "error" in data:
            last_error = data["error"]
            continue
        # NFA 專用條目(managed = false)只有流量資料,沒有 ping / 狀態輪詢,不能用來量存活率
        if str(data.get("managed", "true")).lower() == "false":
            last_error = f"「{name}」是 NFA 專用條目(未被 OpManager 管理),略過"
            continue
        _working_name[label] = name
        print(f"  (提示){label} 使用名稱:{name}")
        return data
    raise RuntimeError(f"{label}:所有候選名稱都被 API 拒絕(最後錯誤:{last_error})")


def parse_summary(label: str, data: dict) -> dict:
    return {
        "label": label,
        "response_ms": to_number(find_key(data, "responseTime")),
        "packet_loss_pct": to_number(find_key(data, "packetLoss")),
        "pingable": to_bool(find_key(data, "isDevicePingable")),
        "status_text": find_key(data, "statusStr") or find_key(data, "status"),
    }


def check_alerts(row: dict) -> list:
    alerts = []
    if row["pingable"] is False:
        alerts.append("無法 ping 通")
    if THRESHOLDS["response_ms"] is not None and row["response_ms"] is not None \
            and row["response_ms"] >= THRESHOLDS["response_ms"]:
        alerts.append(f"回應時間 {row['response_ms']}ms(門檻 {THRESHOLDS['response_ms']})")
    if THRESHOLDS["packet_loss_pct"] is not None and row["packet_loss_pct"] is not None \
            and row["packet_loss_pct"] >= THRESHOLDS["packet_loss_pct"]:
        alerts.append(f"丟包率 {row['packet_loss_pct']}%(門檻 {THRESHOLDS['packet_loss_pct']})")
    return alerts


def append_history(now_iso: str, rows: list) -> None:
    file_exists = os.path.isfile(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HISTORY_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({"timestamp_utc": now_iso, **row})


def main() -> None:
    print(f"開始輪詢核心設備存活率,每 {POLL_INTERVAL_SEC} 秒一次。按 Ctrl+C 停止。")
    print(f"歷史紀錄:{HISTORY_FILE}\n")

    while True:
        now_iso = datetime.now(timezone.utc).isoformat()
        rows = []
        print(f"[{now_iso}]")
        for device in DEVICES:
            try:
                row = parse_summary(device["label"], fetch_summary(device))
            except requests.exceptions.RequestException as exc:
                print(f"  {device['label']:<16}[錯誤] API 呼叫失敗:{exc}")
                continue
            except Exception as exc:  # noqa: BLE001
                print(f"  {device['label']:<16}[錯誤] {exc}")
                continue

            row["alerts"] = check_alerts(row)
            rows.append(row)

            rt = f"{row['response_ms']:.0f}ms" if row["response_ms"] is not None else "-"
            loss = f"{row['packet_loss_pct']:.0f}%" if row["packet_loss_pct"] is not None else "-"
            ping = {True: "可 ping", False: "無法 ping", None: "未知"}[row["pingable"]]
            print(f"  {row['label']:<16}回應 {rt:<7}丟包 {loss:<6}{ping:<8}OpManager 狀態:{row['status_text']}")
            for alert in row["alerts"]:
                print(f"    ⚠ {alert}")

        if rows:
            append_history(now_iso, rows)
            with open(LATEST_FILE, "w", encoding="utf-8") as f:
                json.dump({"generated_at": now_iso, "devices": rows}, f, ensure_ascii=False, indent=2)

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
