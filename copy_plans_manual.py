# -*- coding: utf-8 -*-
"""把 meraki_discover.py 之前下載的平面圖,依樓層名稱改名,放進 meraki_plans_manual 資料夾。

用法(在你自己的電腦,meraki_probe 資料夾的上一層執行):
  python copy_plans_manual.py                       # 預設讀 .\\meraki_probe,輸出到 .\\meraki_plans_manual
  python copy_plans_manual.py --probe D:\\probe --out D:\\out

做完後,把輸出資料夾「meraki_plans_manual」整個複製到 DB server 的 meraki_poll.py 旁邊即可。
原理:meraki_probe\\floorplans_raw.json 記錄了「樓層名稱 ↔ 平面圖 ID」,
圖片檔名是「網路ID_平面圖ID.png」,這支程式幫你對起來並改名成「樓層名稱.png」(例如 05F.png)。
"""
import argparse
import json
import os
import re
import shutil

HQ_NET_ID = "N_000000000000000000"      # HQ 網路的 ID(--dry 的警告訊息裡看到的那一個)
WANT = ["B1F", "01F", "02F", "03F", "04F", "05F", "06F", "07F"]     # 只要這幾層


def norm(name):
    return re.sub(r"\s+", "", str(name)).upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default="meraki_probe", help="meraki_discover.py 的輸出資料夾")
    ap.add_argument("--out", default="meraki_plans_manual", help="要產生的資料夾")
    ap.add_argument("--net", default=HQ_NET_ID, help="網路 ID(預設 HQ)")
    a = ap.parse_args()

    with open(os.path.join(a.probe, "floorplans_raw.json"), encoding="utf-8") as f:
        raw = json.load(f)
    plans = raw.get(a.net)
    if plans is None:
        print("找不到這個網路 ID,檔案裡有:", ", ".join(raw.keys()))
        return
    os.makedirs(a.out, exist_ok=True)
    got = set()
    for p in plans:
        name = norm(p.get("name", ""))
        if name not in WANT:
            continue
        ext = (p.get("imageExtension") or "png").lower()
        src = os.path.join(a.probe, f"{a.net}_{p['floorPlanId']}.{ext}".replace("/", "_"))
        if not os.path.isfile(src):
            print(f"  [缺] {name}:找不到 {os.path.basename(src)}")
            continue
        dst = os.path.join(a.out, f"{name}.{ext}")
        shutil.copyfile(src, dst)
        got.add(name)
        print(f"  {os.path.basename(src)}  →  {dst}")
    miss = [n for n in WANT if n not in got]
    print("\n完成。" + (f"還缺:{', '.join(miss)}" if miss else "8 層都有了。"))


if __name__ == "__main__":
    main()
