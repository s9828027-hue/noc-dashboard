"""
基線分析工具 — 讀 history.csv,算出每條線路 IN/OUT 的使用率統計
====================================================================
用途:netflow_poll_poc.py 連續跑一段時間(建議至少一週,涵蓋到平日/
     假日、上下班尖峰)之後,用這支腳本讀累積下來的 history.csv,
     算出每條線路 IN、OUT 各自的平均值、尖峰值(max)、以及 95th
     百分位(p95,排除掉偶發的極端尖峰,比 max 更適合當門檻參考)。

     跑完之後,建議把每條線路的門檻抓在「p95 到 max 之間」,
     依你們的容忍度決定要不要留緩衝(例如 p95 是 78%,想抓寬一點就用
     85%,想抓緊一點就直接用 p95)。算完之後把 threshold_in_pct /
     threshold_out_pct 填回 netflow_poll_poc.py 的 LINE_MAP 裡,
     之後才會真的開始判斷 over_threshold。

用法
----
python analyze_baseline.py
(預設讀同一個資料夾裡的 history.csv;也可以用
 python analyze_baseline.py /path/to/history.csv 指定路徑)
"""

import csv
import os
import statistics
import sys
from collections import defaultdict


def percentile(sorted_values: list[float], pct: float) -> float:
    """簡易百分位計算(不依賴 numpy)。"""
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


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    history_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(script_dir, "history.csv")

    if not os.path.isfile(history_file):
        sys.exit(f"找不到 {history_file}。請先確認 netflow_poll_poc.py 已經跑過一段時間並產生 history.csv。")

    by_line = defaultdict(lambda: {"label": None, "in": [], "out": []})

    with open(history_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        row_count = 0
        for row in reader:
            row_count += 1
            line_id = row["id"]
            by_line[line_id]["label"] = row["label"]
            try:
                by_line[line_id]["in"].append(float(row["util_in_pct"]))
                by_line[line_id]["out"].append(float(row["util_out_pct"]))
            except (KeyError, ValueError):
                continue

    if row_count == 0:
        sys.exit("history.csv 是空的,還沒有累積到資料。")

    print(f"讀取了 {row_count} 筆紀錄,涵蓋 {len(by_line)} 條線路。\n")
    print(f"{'線路':<28} {'方向':<5} {'平均':>6} {'p95':>6} {'尖峰(max)':>10} {'樣本數':>6}")
    print("-" * 70)

    for line_id, data in by_line.items():
        for direction, values in (("IN", data["in"]), ("OUT", data["out"])):
            if not values:
                continue
            values_sorted = sorted(values)
            avg = statistics.mean(values)
            p95 = percentile(values_sorted, 95)
            peak = max(values)
            print(
                f"{data['label']:<28} {direction:<5} "
                f"{avg:>5.1f}% {p95:>5.1f}% {peak:>9.1f}% {len(values):>6}"
            )

    print("\n建議:把每條線路 IN/OUT 的門檻設在 p95 ~ max 之間,")
    print("依風險容忍度取捨後,填回 netflow_poll_poc.py 的 LINE_MAP。")


if __name__ == "__main__":
    main()
