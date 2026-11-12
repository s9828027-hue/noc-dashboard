"""
Palo Alto 防火牆健康度輪詢(FW-A / FW-B 雙台,透過 OpManager 的 SNMP 監控資料)
====================================================================================
用途:定期從 OpManager 讀取兩台防火牆的 Session 數、Session 使用率、CPU、記憶體,
     持續記錄到 fw_health_history.csv,並偵測:
       1) Session 突然暴漲(倍率 = 目前連線數 ÷ 最近中位數)
       2) 主用防火牆換人(failover):用「誰在扛連線」推斷,見下方說明

資料來源:OpManager REST API 的 device/getAssociatedMonitors。
         這是唯讀查詢,不會直接連到防火牆本體,也不需要防火牆 API 權限。

為什麼要看兩台、怎麼判斷 failover
----------------------------------
兩台 Palo Alto 防火牆是 HA(一台 active、一台 passive/standby)。
- 注意:HA 有開 Session 同步時,passive 那台的 Session 表也會被複製一份,
  所以「Session 數」兩台看起來幾乎一樣,不能用來分辨誰是主用(這是實測後發現的)。
  「暴漲倍率」因此是每台各自跟「自己」的歷史比。
- OpManager 的「Current HA State」是文字型監控項目,API 讀不到它的值,所以改用推斷:
  passive 沒有在轉發封包,Dataplane CPU 會接近 0;active 則明顯較高。
  1) 兩台 Dataplane CPU 差距 >= CPU_MARGIN,CPU 較高的那台視為主用。
  2) 差距不夠時,改比 SSL Proxy Sessions(passive 通常只有很少)。
  3) 還是分不出來,這一輪就「不判斷」,維持上次的結果,不會亂報。
  主用換人(例如 FW-A → FW-B)就代表發生了 failover,直接告警(不需要門檻)。
- 為避免 SNMP 數值剛好在切換瞬間不同步造成誤報,新狀態要「連續兩輪一致」才確認並告警。
- 這是推斷,不是讀到真正的 HA 狀態;告警時請到防火牆確認實際情況。

注意:這些數值是 OpManager 用 SNMP 輪詢後的「最近一次結果」,更新頻率取決於
     OpManager 那邊設定的輪詢間隔(常見是 5 分鐘)。本腳本每 60 秒問一次只是
     確保不漏掉更新,同一個數值連續出現多次是正常的。

使用前準備
----------
1. pip install requests
2. 設定環境變數 OPM_API_KEY(或沿用 NFA_API_KEY,兩者是同一把 OpManager Key):
   PowerShell:  $env:OPM_API_KEY = "你的APIKey"
3. 用法:python fw_health_poll.py
"""

import csv
import json
import os
import statistics
import sys
import time
from collections import deque
from datetime import datetime, timezone

import requests
import urllib3

# ── 基本設定 ────────────────────────────────────────────────────────────
BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
API_KEY = os.environ.get("OPM_API_KEY") or os.environ.get("NFA_API_KEY")
POLL_INTERVAL_SEC = 60
VERIFY_SSL = False

# 要監控的防火牆(name 用 IP,已實測 API 接受)
FIREWALLS = [
    {"label": "FW-A", "name": "10.0.0.252"},
    {"label": "FW-B", "name": "10.0.0.253"},
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(SCRIPT_DIR, "fw_health_history.csv")
LATEST_FILE = os.path.join(SCRIPT_DIR, "fw_health_latest.json")

# 暴漲偵測用的取樣窗口與最少樣本數
SURGE_WINDOW = 60          # 用最近 60 筆當基準
SURGE_MIN_SAMPLES = 10     # 至少累積 10 筆才開始算倍率
SURGE_MIN_BASELINE = 1000  # 基準連線數低於這個值(例如 passive 那台)就不算倍率,避免小數字亂跳
CPU_MARGIN = 2             # 兩台 Dataplane CPU 至少差這麼多(百分點),才用 CPU 判斷主用
SSL_RATIO = 3              # CPU 分不出來時:SSL Proxy Sessions 至少差這麼多倍,才用它判斷
SSL_MIN_DIFF = 100         # ……而且至少差這麼多筆(避免兩邊都很小時亂判)
CONFIRM_ROUNDS = 2         # 新的主用狀態要連續幾輪一致才確認(防止數值不同步誤報)

# 告警門檻。None = 只顯示、不告警(先觀察,之後再填)。
THRESHOLDS = {
    "session_util_pct": None,   # Session 使用率 %,例如 70
    "dataplane_cpu_pct": None,  # 資料平面 CPU %,例如 80
    "mgmt_cpu_pct": None,       # 管理平面 CPU %
    "memory_util_pct": None,    # 記憶體 %,例如 85
    "surge_ratio": None,        # Session 暴漲倍率,例如 1.5
}

# OpManager 的 policyName -> (我們自己用的欄位名, 顯示名稱)
METRICS = {
    "panSessionUtilization": ("session_util_pct", "Session 使用率(%)"),
    "panSessionActive": ("active_sessions", "Active Sessions"),
    "panSessionActiveTcp": ("tcp_sessions", "TCP Sessions"),
    "panSessionActiveUdp": ("udp_sessions", "UDP Sessions"),
    "panSessionActiveICMP": ("icmp_sessions", "ICMP Sessions"),
    "panSessionActiveSslProxy": ("ssl_proxy_sessions", "SSL Proxy Sessions"),
    "hrProcessorLoad.2": ("dataplane_cpu_pct", "Dataplane CPU(%)"),
    "panmgmpCPUUtilization": ("mgmt_cpu_pct", "管理平面 CPU(%)"),
    "panAllStorageUtilization": ("memory_util_pct", "記憶體(%)"),
}

# role 是程式推斷出來的:active(主用)/ standby(備援)/ 空白(無法判斷)
HISTORY_FIELDS = ["timestamp_utc", "device"] + [key for key, _ in METRICS.values()] + ["surge_ratio", "role"]

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit("找不到環境變數 OPM_API_KEY(或 NFA_API_KEY)。請先設定:$env:OPM_API_KEY = \"你的APIKey\"")


def first_numeric_value(node):
    """在一個監控項目底下,找出第一個數值型的 value。"""
    if isinstance(node, dict):
        for key, val in node.items():
            if key.lower() == "value" and isinstance(val, (int, float, str)):
                try:
                    return float(val)
                except (TypeError, ValueError):
                    pass
        for val in node.values():
            found = first_numeric_value(val)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = first_numeric_value(item)
            if found is not None:
                return found
    return None


def extract_metrics(data) -> dict:
    """從 getAssociatedMonitors 回應裡,依 policyName 抓出我們要的指標。"""
    found: dict = {}

    def visit(node):
        if isinstance(node, dict):
            lowered = {k.lower(): k for k in node.keys()}
            if "policyname" in lowered:
                policy = str(node[lowered["policyname"]])
                if policy in METRICS:
                    key, _ = METRICS[policy]
                    value = first_numeric_value(node)
                    if value is not None:
                        found[key] = value
            for val in node.values():
                visit(val)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(data)
    return found


def fetch_metrics(device_name: str) -> dict:
    resp = requests.get(
        f"{BASE_URL}/api/json/device/getAssociatedMonitors",
        params={"apiKey": API_KEY, "name": device_name},
        verify=VERIFY_SSL, timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(f"OpManager 回傳錯誤:{data['error']}")
    return extract_metrics(data)


def prepare_history_file() -> None:
    """
    歷史檔欄位跟目前版本不同(例如舊版沒有 device 或 role 欄位)時,把舊檔改名備份,
    另開新檔,避免兩種格式混在一起造成之後分析出錯。
    """
    if not os.path.isfile(HISTORY_FILE):
        return
    with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
        header = next(csv.reader(f), [])
    if header != HISTORY_FIELDS:
        backup = HISTORY_FILE.replace(".csv", f"_old_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")
        os.rename(HISTORY_FILE, backup)
        print(f"偵測到舊格式的歷史檔,已備份為:{backup}\n")


def load_recent_sessions(label: str) -> deque:
    """啟動時,從歷史檔預載該台最近的 Active Sessions,避免每次重啟都要重新暖機。"""
    window: deque = deque(maxlen=SURGE_WINDOW)
    if not os.path.isfile(HISTORY_FILE):
        return window
    with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("device") != label:
                continue
            try:
                window.append(float(row["active_sessions"]))
            except (KeyError, ValueError):
                continue
    return window


def load_last_cluster_state():
    """啟動時,從歷史檔讀出「最近一次能判斷出來的主用」,這樣重啟後也能偵測到停機期間發生的切換。"""
    if not os.path.isfile(HISTORY_FILE):
        return None
    last_known = None          # 最近一次「剛好只有一台主用」的結果
    current_ts, actives = None, []

    def close_group():
        nonlocal last_known
        if len(actives) == 1:
            last_known = actives[0]

    with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("timestamp_utc") != current_ts:
                close_group()
                current_ts, actives = row.get("timestamp_utc"), []
            if row.get("role") == "active":
                actives.append(row.get("device"))
    close_group()
    return last_known


def compute_surge_ratio(current: float, window: deque):
    """目前值 ÷ 過去窗口的中位數。樣本不足、或基準太小(例如 passive 那台)時回傳 None。"""
    if len(window) < SURGE_MIN_SAMPLES:
        return None
    baseline = statistics.median(window)
    if baseline < SURGE_MIN_BASELINE:
        return None
    return round(current / baseline, 2)


def check_alerts(metrics: dict, surge_ratio) -> list:
    """對照門檻,回傳超標的訊息清單(門檻是 None 的項目不判斷)。"""
    alerts = []
    for key, limit in THRESHOLDS.items():
        if limit is None:
            continue
        value = surge_ratio if key == "surge_ratio" else metrics.get(key)
        if value is not None and value >= limit:
            alerts.append(f"{key} = {value}(門檻 {limit})")
    return alerts


# ── 主用 / 備援 推斷 ────────────────────────────────────────────────────
def infer_active(readings: list):
    """
    從兩台的讀數推斷「誰是主用」,回傳主用的 label;分不出來回傳 None。
    先比 Dataplane CPU(passive 幾乎不轉發封包,接近 0),差距不夠再比 SSL Proxy Sessions。
    """
    if len(readings) != 2:
        return None
    a, b = readings
    cpu_a = a["metrics"].get("dataplane_cpu_pct")
    cpu_b = b["metrics"].get("dataplane_cpu_pct")
    if cpu_a is not None and cpu_b is not None and abs(cpu_a - cpu_b) >= CPU_MARGIN:
        return a["label"] if cpu_a > cpu_b else b["label"]

    ssl_a = a["metrics"].get("ssl_proxy_sessions")
    ssl_b = b["metrics"].get("ssl_proxy_sessions")
    if ssl_a is not None and ssl_b is not None and abs(ssl_a - ssl_b) >= SSL_MIN_DIFF:
        high, low = (ssl_a, ssl_b) if ssl_a > ssl_b else (ssl_b, ssl_a)
        if high >= max(low, 1) * SSL_RATIO:
            return a["label"] if ssl_a > ssl_b else b["label"]
    return None


class ClusterTracker:
    """
    追蹤「主用是誰」。新的狀態要連續 CONFIRM_ROUNDS 輪都一致才算數,
    避免兩台的 SNMP 數值剛好在不同時間點更新,造成單輪誤報。
    """

    def __init__(self, confirmed):
        self.confirmed = confirmed   # 已確認的狀態(第一輪沒有歷史時是 None)
        self.pending = None          # 正在觀察、還沒確認的新狀態
        self.pending_count = 0

    def update(self, observed: str):
        """回傳「狀態已確認變更」的告警訊息;沒變更回傳 None。"""
        if self.confirmed is None:          # 第一次:只記錄,不告警
            self.confirmed = observed
            return None
        if observed == self.confirmed:      # 跟已確認的一樣,清掉觀察中的新狀態
            self.pending, self.pending_count = None, 0
            return None

        if observed == self.pending:
            self.pending_count += 1
        else:
            self.pending, self.pending_count = observed, 1

        if self.pending_count >= CONFIRM_ROUNDS:
            old, self.confirmed = self.confirmed, observed
            self.pending, self.pending_count = None, 0
            return f"主用防火牆變更:{old} → {observed}(可能發生 failover 切換,請到防火牆確認 HA 狀態)"
        return None


def append_history(now_iso: str, label: str, metrics: dict, surge_ratio, role) -> None:
    file_exists = os.path.isfile(HISTORY_FILE)
    row = {"timestamp_utc": now_iso, "device": label, "surge_ratio": surge_ratio,
           "role": role or "", **metrics}
    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HISTORY_FIELDS, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def print_device(label: str, metrics: dict, surge_ratio, role, alerts: list) -> None:
    role_text = {"active": "主用", "standby": "備援", None: "未知"}[role]
    print(f"  【{label}】(推斷角色:{role_text})")
    for key, text in METRICS.values():
        if key not in metrics:
            continue
        value = metrics[key]
        if isinstance(value, float):
            print(f"    {text:<22}{value:>12,.1f}")
        else:
            print(f"    {text:<22}{value:>12,}")
    ratio_text = f"{surge_ratio}" if surge_ratio is not None else "不計算(樣本不足或基準過小)"
    print(f"    {'Session 暴漲倍率':<20}{ratio_text:>14}")
    for alert in alerts:
        print(f"    ⚠ {alert}")


def main() -> None:
    labels = " / ".join(fw["label"] for fw in FIREWALLS)
    print(f"開始輪詢防火牆健康度({labels}),每 {POLL_INTERVAL_SEC} 秒一次。按 Ctrl+C 停止。")
    print(f"歷史紀錄:{HISTORY_FILE}\n")

    prepare_history_file()
    windows = {fw["label"]: load_recent_sessions(fw["label"]) for fw in FIREWALLS}
    tracker = ClusterTracker(load_last_cluster_state())

    while True:
        now_iso = datetime.now(timezone.utc).isoformat()
        print(f"[{now_iso}]")
        readings = []   # 這一輪成功讀到的每台資料

        for fw in FIREWALLS:
            label = fw["label"]
            try:
                metrics = fetch_metrics(fw["name"])
            except requests.exceptions.RequestException as exc:
                print(f"  【{label}】[錯誤] API 呼叫失敗:{exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - 先全部印出來方便除錯
                print(f"  【{label}】[錯誤] {exc}")
                continue

            missing = [text for key, text in METRICS.values() if key not in metrics]
            if missing:
                print(f"  【{label}】[警告] 這次沒抓到:{', '.join(missing)}")

            surge_ratio = None
            if "active_sessions" in metrics:
                surge_ratio = compute_surge_ratio(metrics["active_sessions"], windows[label])
                windows[label].append(metrics["active_sessions"])

            readings.append({
                "label": label, "device": fw["name"], "metrics": metrics,
                "surge_ratio": surge_ratio, "role": None,
                "alerts": check_alerts(metrics, surge_ratio),
            })

        # 兩台都有讀到才判斷「誰是主用」;缺一台就跳過這一輪
        cluster_alert_list: list = []
        active_label = infer_active(readings) if len(readings) == len(FIREWALLS) else None
        for r in readings:
            r["role"] = None if active_label is None else ("active" if r["label"] == active_label else "standby")

        if len(readings) < len(FIREWALLS):
            cluster_note = "本輪有防火牆沒讀到資料,略過主用判斷"
        elif active_label is None:
            cluster_note = f"目前主用:{tracker.confirmed or '未知'}(本輪兩台指標差異不夠,無法判斷,維持上次結果)"
        else:
            change = tracker.update(active_label)
            if change:
                cluster_alert_list.append(change)
            cluster_note = f"目前主用:{tracker.confirmed}"
            if active_label != tracker.confirmed:
                cluster_note += f"(觀察到 {active_label},待確認 {tracker.pending_count}/{CONFIRM_ROUNDS})"

        for r in readings:
            print_device(r["label"], r["metrics"], r["surge_ratio"], r["role"], r["alerts"])
            append_history(now_iso, r["label"], r["metrics"], r["surge_ratio"], r["role"])
        print(f"  ▶ {cluster_note}")
        for alert in cluster_alert_list:
            print(f"    ⚠ {alert}")

        if readings:
            with open(LATEST_FILE, "w", encoding="utf-8") as f:
                json.dump(
                    {"generated_at": now_iso, "active_firewall": tracker.confirmed,
                     "cluster_alerts": cluster_alert_list, "firewalls": readings},
                    f, ensure_ascii=False, indent=2,
                )

        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    main()
