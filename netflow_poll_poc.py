"""
NetFlow Analyzer (OpManager) 輪詢 POC — 門檻改成從設定檔讀取版
====================================================================
用途:每隔固定秒數打一次 getIndexInterfaceData(DeviceID=-1,一次拿全部介面),
     在本地端過濾出我們關心的 5 條線路,把 IN / OUT 使用率分開記錄下來
     (寫進 history.csv,持續累積,不會覆蓋),同時寫一份 latest.json
     當作目前狀態快照。

     門檻:目前採「固定門檻」——使用率 >= 70%(WARN_PCT)大螢幕顯示黃色,
     >= 90%(CRIT_PCT)顯示紅色並自動跳出 Top N。要改數字,改下面的
     WARN_PCT / CRIT_PCT;單一線路想用不同數字,在 LINE_MAP 該線路加
     "warn_pct" / "crit_pct"。(舊的 thresholds.json / review_thresholds.py
     流程暫時不使用,等累積到足夠基準資料再決定要不要改回「依歷史自動建議」。)

使用前準備
----------
1. pip install requests
2. 設定環境變數 NFA_API_KEY(不要把 Key 寫死在程式碼或 commit 進版控):

   Windows PowerShell:
       $env:NFA_API_KEY = "你的APIKey"
   Linux / macOS:
       export NFA_API_KEY="你的APIKey"

3. 建議用背景/常駐的方式跑,中間不要中斷太久,不然某些時段的資料會有缺口。
4. 若你的內部憑證是自簽的,VERIFY_SSL 先保持 False(等同於 curl -k)。

完整流程(三支腳本怎麼串起來)
--------------------------------
  netflow_poll_poc.py (這支,持續跑)
        │  持續寫 history.csv
        ▼
  monthly_threshold_review.py (定期手動或排程跑一次,例如每月初)
        │  讀 history.csv,算出建議門檻,寫 pending_review.json
        ▼
  review_thresholds.py (你人工跑,一條一條確認)
        │  你按 y 同意的,才會寫進 thresholds.json
        ▼
  thresholds.json 更新 → 下一次 netflow_poll_poc.py 輪詢時自動讀到新門檻
"""

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

# ── 基本設定 ────────────────────────────────────────────────────────────
BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
ENDPOINT = "/api/json/nfadevice/getIndexInterfaceData"
API_KEY = os.environ.get("NFA_API_KEY")

TIMEFRAME = "hourly"          # hourly / 6hour / Daily / today / yesterday / Weekly / Monthly
POLL_INTERVAL_SEC = 60        # 幾秒鐘輪詢一次
VERIFY_SSL = False            # 內部自簽憑證先關閉驗證;之後建議改 True

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LATEST_FILE = os.path.join(SCRIPT_DIR, "latest.json")
HISTORY_FILE = os.path.join(SCRIPT_DIR, "history.csv")
THRESHOLDS_FILE = os.path.join(SCRIPT_DIR, "thresholds.json")
PENDING_REVIEW_FILE = os.path.join(SCRIPT_DIR, "pending_review.json")
# 選用(擴充點):線路流量改用 SNMP 直接量測(由另一台主機上的量測服務提供 JSON;公開版未附該服務,格式見 README「擴充性」)。
# 沒有這個設定檔 = 完全不啟用,行為和以前一模一樣。範例見 snmp_source.sample.json。
SNMP_SOURCE_FILE = os.path.join(SCRIPT_DIR, "snmp_source.json")

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit(
        "找不到環境變數 NFA_API_KEY。\n"
        "請先設定:\n"
        "  Windows PowerShell:  $env:NFA_API_KEY = \"你的APIKey\"\n"
        "  Linux / macOS:       export NFA_API_KEY=\"你的APIKey\"\n"
    )

# ── 線路使用率分級(固定門檻)──
# 使用率 >= WARN_PCT:大螢幕該方向顯示黃色(警示)
# 使用率 >= CRIT_PCT:顯示紅色(嚴重),並自動跳出該線路的 Top N 視窗
# 想讓某條線路用不同門檻,在 LINE_MAP 那條線路加上 "warn_pct": 60, "crit_pct": 85 即可。
WARN_PCT = 70
CRIT_PCT = 90

# ── 監控線路(只留顯示用的基本資料)──
# capacity_in_mbps / capacity_out_mbps:這條線路「合約頻寬」(下載 IN / 上傳 OUT)。
#   有填的話,使用率 % 就用「目前流量 ÷ 這個頻寬」自己算,不受 OpManager/NFA 介面頻寬設定影響
#   (例如實體埠是 10G,但合約只有 1G/600M)。沒填就沿用 NFA 回傳的使用率與頻寬。
# 前 4 條會顯示在大螢幕「線路使用率」;F5 兩條不顯示,只在背景給 NAT 推算使用。
LINE_MAP = {
    "5000095": {"label": "ISP-A 主線 1G/600M", "device": "Core-SW-1", "interface": "Uplink-1",
                "capacity_in_mbps": 1000, "capacity_out_mbps": 600},
    "5000107": {"label": "ISP-B 備援 1G/600M", "device": "Core-SW-1", "interface": "Uplink-2",
                "capacity_in_mbps": 1000, "capacity_out_mbps": 600},
    "5000097": {"label": "ISP-C 專線 300M/300M", "device": "Core-SW-1", "interface": "Uplink-3",
                "capacity_in_mbps": 300, "capacity_out_mbps": 300},
    "5000108": {"label": "ISP-D 網際網路 1G/600M", "device": "Edge-FW", "interface": "WAN2",
                "capacity_in_mbps": 1000, "capacity_out_mbps": 600},
    "5000105": {"label": "F5-內網-1", "device": "Core-SW-1", "interface": "LB-Inside-1"},
    "5000106": {"label": "F5-內網-2", "device": "Core-SW-1", "interface": "LB-Inside-2"},
}

HISTORY_FIELDS = [
    "timestamp_utc", "id", "label", "device", "interface",
    "util_in_pct", "util_out_pct",
    "current_in_mbps", "current_out_mbps",
    "link_up", "status_text",
]


def load_thresholds() -> dict:
    """讀 thresholds.json。檔案不存在的話,建立一份全部是 null 的預設檔。"""
    if not os.path.isfile(THRESHOLDS_FILE):
        default = {
            line_id: {"threshold_in_pct": None, "threshold_out_pct": None}
            for line_id in LINE_MAP
        }
        with open(THRESHOLDS_FILE, "w", encoding="utf-8") as f:
            json.dump(default, f, ensure_ascii=False, indent=2)
        return default

    with open(THRESHOLDS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def count_pending_reviews() -> int:
    """檢查 pending_review.json 裡還有幾筆 status 是 'pending' 的建議。"""
    if not os.path.isfile(PENDING_REVIEW_FILE):
        return 0
    try:
        with open(PENDING_REVIEW_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return 0
    return sum(1 for item in data.get("items", []) if item.get("status") == "pending")


def fetch_all_interfaces() -> dict:
    """呼叫 getIndexInterfaceData(DeviceID=-1),回傳原始 JSON。"""
    params = {
        "apiKey": API_KEY,
        "TimeFrame": TIMEFRAME,
        "DeviceID": -1,
    }
    resp = requests.get(
        f"{BASE_URL}{ENDPOINT}",
        params=params,
        verify=VERIFY_SSL,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def bps_to_mbps(bps) -> float:
    try:
        return round(float(bps) / 1_000_000, 2)
    except (TypeError, ValueError):
        return 0.0


def level_of(util_pct, warn_pct: float, crit_pct: float) -> str:
    """依使用率回傳分級:ok(正常)/ warn(警示,黃)/ crit(嚴重,紅 + 自動跳出 Top N)。"""
    if util_pct >= crit_pct:
        return "crit"
    if util_pct >= warn_pct:
        return "warn"
    return "ok"


def build_records(raw: dict, now_iso: str) -> list[dict]:
    """把 API 原始資料過濾/轉換成每條線路一筆的精簡紀錄(IN/OUT 分開)。"""
    if "data" not in raw:
        # 回應裡沒有 data 欄位,通常代表這其實是一包錯誤訊息(例如 apiKey
        # 失效、被限流等),雖然 HTTP 狀態可能還是 200。先把完整內容印出來
        # 方便診斷,再照舊回傳「全部查無資料」讓程式不會整個中斷。
        print(f"[警告] 回應裡沒有 'data' 欄位,原始內容如下:\n{json.dumps(raw, ensure_ascii=False, indent=2)}")

    by_id = {str(item.get("ID")): item for item in raw.get("data", [])}
    records = []

    for line_id, cfg in LINE_MAP.items():
        item = by_id.get(line_id)
        if item is None:
            records.append({
                "id": line_id,
                "label": cfg["label"],
                "device": cfg["device"],
                "interface": cfg["interface"],
                "status": "missing",
                "note": "本次回應找不到這個介面 ID,請確認是否仍在監控中",
            })
            continue

        util_in = item.get("UtilIN", 0) or 0
        util_out = item.get("UtilOUT", 0) or 0
        # 注意:欄位名稱雖然叫 INTrafficByte,實測數值已經是「每秒位元數 (bps)」,
        # 不能再乘 8(之前乘了 8,導致 Mbps 被放大 8 倍;使用率 % 是 API 直接給的,不受影響)。
        in_traffic_bps = item.get("INTrafficByte", 0) or 0
        out_traffic_bps = item.get("OUTTrafficByte", 0) or 0

        current_in_mbps = bps_to_mbps(in_traffic_bps)
        current_out_mbps = bps_to_mbps(out_traffic_bps)
        # 有指定合約頻寬:使用率改用「目前流量 ÷ 合約頻寬」自己算
        cap_in = cfg.get("capacity_in_mbps") or bps_to_mbps(item.get("Speed", 0) or 0)
        cap_out = cfg.get("capacity_out_mbps") or bps_to_mbps(item.get("outSpeed", 0) or 0)
        if cfg.get("capacity_in_mbps"):
            util_in = round(current_in_mbps / cap_in * 100)
        if cfg.get("capacity_out_mbps"):
            util_out = round(current_out_mbps / cap_out * 100)

        warn_pct = cfg.get("warn_pct", WARN_PCT)
        crit_pct = cfg.get("crit_pct", CRIT_PCT)

        records.append({
            "id": line_id,
            "label": cfg["label"],
            "device": item.get("rName") or cfg["device"],
            "interface": item.get("Name") or cfg["interface"],
            "status_text": item.get("StatusTxt"),
            "link_up": item.get("statuscode") == 0,
            "capacity_in_mbps": cap_in,
            "capacity_out_mbps": cap_out,
            "current_in_mbps": current_in_mbps,
            "current_out_mbps": current_out_mbps,
            "util_in_pct": util_in,
            "util_out_pct": util_out,
            "warn_pct": warn_pct,
            "crit_pct": crit_pct,
            "level_in": level_of(util_in, warn_pct, crit_pct),
            "level_out": level_of(util_out, warn_pct, crit_pct),
            "timestamp_utc": now_iso,
        })

    return records


_snmp_state = {"last": None}      # 記住上次狀態,只有狀態改變才印訊息,避免每分鐘洗版


def _snmp_note(ok: bool, msg: str) -> None:
    if _snmp_state["last"] != ok:
        _snmp_state["last"] = ok
        print(msg)


def load_snmp_overlay() -> tuple[dict, dict]:
    """
    向外部的 SNMP 量測服務取各線路的實測流量。回傳 ({線路ID: 資料}, 說明)。
    取不到、過期、或沒有設定檔時回傳空的對照表,程式就照舊使用 NetFlow API 的數字(自動退回)。
    """
    if not os.path.isfile(SNMP_SOURCE_FILE):
        return {}, {"active": False}
    try:
        with open(SNMP_SOURCE_FILE, "r", encoding="utf-8") as f:
            conf = json.load(f)
        url = conf.get("url")
        if not url or conf.get("enabled", True) is False:
            return {}, {"active": False}
        resp = requests.get(url, timeout=float(conf.get("timeout_sec", 5)))
        resp.raise_for_status()
        data = resp.json()
        gen = datetime.fromisoformat(str(data["generated_at"]))
        age = time.time() - gen.timestamp()
        if age > float(conf.get("max_age_sec", 180)):
            raise ValueError(f"SNMP 量測資料已 {age:.0f} 秒沒有更新")
        overlay = {str(l["id"]): l for l in data.get("lines", [])
                   if l.get("valid") and l.get("current_in_mbps") is not None}
        _snmp_note(True, f"[資訊] 線路流量使用 SNMP 實測資料({len(overlay)} 條)。")
        return overlay, {"active": True, "source_generated_at": data["generated_at"], "line_ids": sorted(overlay)}
    except Exception as exc:  # noqa: BLE001 - 任何失敗都退回 NetFlow,不能讓整個輪詢中斷
        _snmp_note(False, f"[警告] 取不到有效的 SNMP 量測資料({exc}),線路流量暫時改用 NetFlow API 的數字。")
        return {}, {"active": False, "error": str(exc)}


def apply_snmp_overlay(records: list[dict], overlay: dict, now_iso: str) -> list[dict]:
    """把 SNMP 實測的流量蓋到對應線路的紀錄上(使用率仍用合約頻寬重算)。NetFlow 沒資料的線路也會被補成完整紀錄。"""
    for i, rec in enumerate(records):
        o = overlay.get(rec["id"])
        cfg = LINE_MAP.get(rec["id"])
        if not o or not cfg:
            continue
        if rec.get("status") == "missing":
            rec = {"id": rec["id"], "label": cfg["label"], "device": cfg["device"],
                   "interface": cfg["interface"], "status_text": "SNMP"}
            records[i] = rec
        cap_in = cfg.get("capacity_in_mbps") or rec.get("capacity_in_mbps") or 0
        cap_out = cfg.get("capacity_out_mbps") or rec.get("capacity_out_mbps") or 0
        cur_in, cur_out = float(o["current_in_mbps"]), float(o["current_out_mbps"])
        util_in = round(cur_in / cap_in * 100) if cap_in else 0
        util_out = round(cur_out / cap_out * 100) if cap_out else 0
        warn_pct, crit_pct = cfg.get("warn_pct", WARN_PCT), cfg.get("crit_pct", CRIT_PCT)
        rec.update({
            "link_up": bool(o.get("link_up", True)),
            "capacity_in_mbps": cap_in, "capacity_out_mbps": cap_out,
            "current_in_mbps": round(cur_in, 2), "current_out_mbps": round(cur_out, 2),
            "inst_in_mbps": o.get("inst_in_mbps"), "inst_out_mbps": o.get("inst_out_mbps"),   # 1 分鐘瞬間值(給需要快速反應的下游程式用)
            "util_in_pct": util_in, "util_out_pct": util_out,
            "warn_pct": warn_pct, "crit_pct": crit_pct,
            "level_in": level_of(util_in, warn_pct, crit_pct), "level_out": level_of(util_out, warn_pct, crit_pct),
            "timestamp_utc": now_iso, "data_source": "snmp",
        })
    return records


def append_history(records: list[dict]) -> None:
    """把這次輪詢結果 append 進 history.csv,供之後算基線用。"""
    file_exists = os.path.isfile(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HISTORY_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        for rec in records:
            if rec.get("status") == "missing":
                continue
            writer.writerow(rec)


def print_snapshot(records: list[dict], now_iso: str) -> None:
    print(f"\n[{now_iso}] 目前 {len(records)} 條線路狀態:")
    for rec in records:
        if rec.get("status") == "missing":
            print(f"  ⚠ {rec['label']}: 查無資料(ID={rec['id']})")
            continue

        tag = {"ok": "", "warn": " ⚠警示", "crit": " 🔴嚴重"}
        print(
            f"  {rec['label']:<28} "
            f"IN {rec['util_in_pct']:>3}% ({rec['current_in_mbps']:.1f}Mbps){tag[rec['level_in']]}"
            f"  OUT {rec['util_out_pct']:>3}% ({rec['current_out_mbps']:.1f}Mbps){tag[rec['level_out']]}"
        )


def main() -> None:
    print(f"開始輪詢 {BASE_URL}{ENDPOINT},每 {POLL_INTERVAL_SEC} 秒一次。按 Ctrl+C 停止。")
    print(f"每次讀數會 append 進:{HISTORY_FILE}")
    print(f"固定門檻:使用率 >= {WARN_PCT}% 警示(黃)、>= {CRIT_PCT}% 嚴重(紅,自動跳出 Top N)。\n")

    while True:
        try:
            now_iso = datetime.now(timezone.utc).isoformat()

            overlay, overlay_meta = load_snmp_overlay()
            try:
                raw = fetch_all_interfaces()
            except requests.exceptions.RequestException as exc:
                if not overlay:
                    raise
                # NetFlow API 暫時不通,但 SNMP 資料正常:線路使用率照常更新(Top N 與 F5 內網資料暫缺)
                print(f"[警告] NetFlow API 呼叫失敗({exc}),先以 SNMP 資料更新線路使用率。")
                raw = {"data": []}
            records = build_records(raw, now_iso)
            if overlay:
                records = apply_snmp_overlay(records, overlay, now_iso)

            print_snapshot(records, now_iso)
            append_history(records)

            with open(LATEST_FILE, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "generated_at": now_iso,
                        "lines": records,
                        "warn_pct": WARN_PCT,
                        "crit_pct": CRIT_PCT,
                        "snmp_overlay": overlay_meta,
                    },
                    f, ensure_ascii=False, indent=2,
                )

        except requests.exceptions.RequestException as exc:
            print(f"[錯誤] API 呼叫失敗:{exc}")
        except Exception as exc:  # noqa: BLE001 - POC 階段先全部印出來方便除錯
            print(f"[錯誤] 未預期的例外:{exc}")

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
