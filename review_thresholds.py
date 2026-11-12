"""
門檻建議 人工確認工具
============================
用途:讀 monthly_threshold_review.py 產生的 pending_review.json,一條一條
     顯示建議門檻給你看,你決定要不要套用:

     y = 同意,套用這個建議值,寫進 thresholds.json(下次輪詢就會生效)
     n = 不套用,維持目前的門檻(這筆從待確認清單移除,不會再提醒,
         下次月結重跑才會重新評估)
     s = 先跳過,下次執行這支工具時還會再問一次(保留在待確認清單)
     q = 結束,尚未處理的項目維持待確認狀態

用法
----
python review_thresholds.py
"""

import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
THRESHOLDS_FILE = os.path.join(SCRIPT_DIR, "thresholds.json")
PENDING_REVIEW_FILE = os.path.join(SCRIPT_DIR, "pending_review.json")


def load_json(path: str, default):
    if not os.path.isfile(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> None:
    pending = load_json(PENDING_REVIEW_FILE, {"items": []})
    thresholds = load_json(THRESHOLDS_FILE, {})

    todo = [item for item in pending.get("items", []) if item.get("status") == "pending"]

    if not todo:
        print("目前沒有待確認的門檻建議。請先執行 monthly_threshold_review.py 產生建議。")
        return

    print(f"共有 {len(todo)} 筆待確認的門檻建議。\n")

    remaining_items = list(pending.get("items", []))

    for item in todo:
        basis = item["basis"]
        print("-" * 60)
        print(f"線路:{item['label']}  方向:{item['direction'].upper()}")
        print(f"目前門檻:{item['current_threshold_pct']}   建議門檻:{item['suggested_threshold_pct']}")
        print(
            f"依據(最近 {basis['window_days']} 天):"
            f" 平均 {basis['mean']}%  p95 {basis['p95']}%  尖峰 {basis['max']}%  樣本數 {basis['samples']}"
        )

        while True:
            choice = input("套用這個建議嗎?[y]同意 / [n]不套用 / [s]跳過 / [q]結束 : ").strip().lower()
            if choice in ("y", "n", "s", "q"):
                break
            print("請輸入 y、n、s 或 q。")

        if choice == "q":
            print("\n結束,尚未處理的項目維持待確認狀態。")
            break

        if choice == "y":
            line_id = item["line_id"]
            direction = item["direction"]
            key = f"threshold_{direction}_pct"
            thresholds.setdefault(line_id, {})[key] = item["suggested_threshold_pct"]
            item["status"] = "approved"
            print(f"✅ 已套用:{item['label']} {direction.upper()} 門檻設為 {item['suggested_threshold_pct']}%")

        elif choice == "n":
            item["status"] = "rejected"
            print("已標記為不套用,維持目前門檻。")

        elif choice == "s":
            print("已跳過,下次執行時還會再問一次。")
            continue  # 狀態保持 pending,不動

    save_json(THRESHOLDS_FILE, thresholds)
    save_json(PENDING_REVIEW_FILE, {**pending, "items": remaining_items})

    print(f"\n已更新:{THRESHOLDS_FILE}")
    print("下次 netflow_poll_poc.py 輪詢時會自動讀到最新門檻,不需要重啟。"
          "\n(其實會在下一次迴圈讀取設定檔時生效,如果程式正在睡眠中,最多等一個輪詢週期。)")


if __name__ == "__main__":
    main()
