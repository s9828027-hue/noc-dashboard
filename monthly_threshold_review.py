"""
門檻建議產生器(月結批次)
================================
用途:讀 history.csv 裡累積的 IN/OUT 使用率紀錄,幫每條線路算出建議門檻,
     寫進 pending_review.json——這支程式只「建議」,不會直接改動正式生效
     的 thresholds.json。要讓建議生效,必須執行 review_thresholds.py
     人工逐條確認。

建議的統計邏輯(避免被單一異常月份污染)
------------------------------------------
1. 用 p95(而不是 max)當基準——單一次性尖峰不會直接拉爆門檻。
2. 在 p95 上加一層緩衝(預設 +10%),避免門檻卡得剛剛好、稍微正常波動
   就誤觸發。
3. 如果這條線路之前已經有生效中的門檻(thresholds.json 裡不是 null),
   新建議值會被限制在「舊門檻 ±20%」的範圍內,避免單次調整跳動過大;
   如果是第一次設定(舊門檻是 null),則不設限,直接採用算出來的值。
4. 只用「最近 N 天」的資料(預設 30 天,模擬月結),避免用到過舊、可能
   已經不具參考價值的資料。

用法
----
python monthly_threshold_review.py [window_days]

範例:
python monthly_threshold_review.py        # 預設抓最近 30 天
python monthly_threshold_review.py 7      # 只抓最近 7 天(資料還不夠一個月時先試跑用)
"""

import csv
import json
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(SCRIPT_DIR, "history.csv")
THRESHOLDS_FILE = os.path.join(SCRIPT_DIR, "thresholds.json")
PENDING_REVIEW_FILE = os.path.join(SCRIPT_DIR, "pending_review.json")

P95_BUFFER = 1.10       # p95 * 1.10 = 建議值(多留 10% 緩衝)
MAX_CHANGE_RATIO = 0.20  # 相對舊門檻,單次最多調整 ±20%
MIN_SAMPLES = 30         # 樣本數太少(例如剛跑沒幾小時)就不给建議,避免統計沒意義


def percentile(sorted_values: list, pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    d0 = sorted_values[f] * (c - k)
    d1 = sorted_values[c] * (k - f)
    return d0 + d1


def load_thresholds() -> dict:
    if not os.path.isfile(THRESHOLDS_FILE):
        return {}
    with open(THRESHOLDS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_recent_history(window_days: int) -> dict:
    """讀 history.csv,只保留最近 window_days 天的資料,依 (id, 方向) 分組。"""
    if not os.path.isfile(HISTORY_FILE):
        sys.exit(f"找不到 {HISTORY_FILE}。請先確認 netflow_poll_poc.py 已經跑過一段時間。")

    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    by_line = defaultdict(lambda: {"label": None, "in": [], "out": []})

    with open(HISTORY_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.fromisoformat(row["timestamp_utc"])
            except (KeyError, ValueError):
                continue
            if ts < cutoff:
                continue

            line_id = row["id"]
            by_line[line_id]["label"] = row["label"]
            try:
                by_line[line_id]["in"].append(float(row["util_in_pct"]))
                by_line[line_id]["out"].append(float(row["util_out_pct"]))
            except (KeyError, ValueError):
                continue

    return by_line


def suggest_threshold(values: list, current: float | None) -> tuple:
    """回傳 (建議值, 統計摘要dict)。樣本太少回傳 (None, 摘要)。"""
    if len(values) < MIN_SAMPLES:
        return None, {"mean": None, "p95": None, "max": None, "samples": len(values)}

    values_sorted = sorted(values)
    mean = round(statistics.mean(values), 1)
    p95 = round(percentile(values_sorted, 95), 1)
    peak = round(max(values), 1)

    raw_suggestion = round(p95 * P95_BUFFER, 1)
    raw_suggestion = min(raw_suggestion, 100.0)  # 使用率邏輯上不超過 100%

    if current is not None:
        lower = current * (1 - MAX_CHANGE_RATIO)
        upper = current * (1 + MAX_CHANGE_RATIO)
        suggestion = max(lower, min(upper, raw_suggestion))
        suggestion = round(suggestion, 1)
    else:
        suggestion = raw_suggestion

    return suggestion, {"mean": mean, "p95": p95, "max": peak, "samples": len(values)}


def main() -> None:
    window_days = int(sys.argv[1]) if len(sys.argv) > 1 else 30

    thresholds = load_thresholds()
    by_line = load_recent_history(window_days)

    if not by_line:
        sys.exit(f"最近 {window_days} 天沒有任何資料,無法產生建議。")

    items = []
    print(f"分析最近 {window_days} 天的資料(至少需要 {MIN_SAMPLES} 筆樣本才會給建議)...\n")
    print(f"{'線路':<28}{'方向':<5}{'目前門檻':>8}{'建議門檻':>8}{'p95':>7}{'平均':>7}{'尖峰':>7}{'樣本數':>7}")
    print("-" * 82)

    for line_id, data in by_line.items():
        line_th = thresholds.get(line_id, {})
        for direction, values in (("in", data["in"]), ("out", data["out"])):
            key = f"threshold_{direction}_pct"
            current = line_th.get(key)
            suggestion, stats = suggest_threshold(values, current)

            current_text = f"{current}%" if current is not None else "未設定"
            suggestion_text = f"{suggestion}%" if suggestion is not None else "樣本不足"
            p95_text = f"{stats['p95']}%" if stats["p95"] is not None else "-"
            mean_text = f"{stats['mean']}%" if stats["mean"] is not None else "-"
            max_text = f"{stats['max']}%" if stats["max"] is not None else "-"

            print(
                f"{data['label']:<28}{direction.upper():<5}"
                f"{current_text:>8}{suggestion_text:>8}{p95_text:>7}{mean_text:>7}{max_text:>7}{stats['samples']:>7}"
            )

            if suggestion is None:
                continue
            # 建議值跟目前生效值一樣的話,不用產生待確認項目
            if current is not None and abs(current - suggestion) < 0.05:
                continue

            items.append({
                "line_id": line_id,
                "label": data["label"],
                "direction": direction,
                "current_threshold_pct": current,
                "suggested_threshold_pct": suggestion,
                "basis": {**stats, "window_days": window_days},
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "status": "pending",
            })

    with open(PENDING_REVIEW_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": datetime.now(timezone.utc).isoformat(), "items": items},
            f, ensure_ascii=False, indent=2,
        )

    print(f"\n產生了 {len(items)} 筆待確認的門檻建議,已寫入 {PENDING_REVIEW_FILE}")
    print("請執行 `python review_thresholds.py` 逐條確認是否套用。")


if __name__ == "__main__":
    main()
