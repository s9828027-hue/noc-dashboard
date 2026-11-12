#!/usr/bin/env python3
"""
產生 GitHub Pages 用的靜態展示頁(docs/)
=========================================
做什麼:
  把 dashboard.html 加上「瀏覽器端的模擬資料」,輸出成 docs/index.html。
  這樣別人不用安裝任何東西,點網址就能看到會動的大螢幕。

  docs/index.html     大螢幕本體(和根目錄的 dashboard.html 相同,只多載入下面兩支 script)
  docs/demo-data.js   預先算好的模擬資料(由 demo_data.py 產生)
  docs/demo-shim.js   攔截 /api/* 請求、改回傳模擬資料的小程式
  docs/plans/*.png    假的樓層平面圖

用法(改過 dashboard.html 或 demo_data.py 之後重跑一次):
    python demo/build_static.py
"""
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = os.path.join(ROOT, "docs")
sys.path.insert(0, HERE)
import demo_data  # noqa: E402

PLAN_URL_OLD = "`/api/meraki_plan?f=${encodeURIComponent(f.plan_file)}&v=${encodeURIComponent(f.plan_md5 || \"0\")}`"
PLAN_URL_NEW = "`plans/${encodeURIComponent(f.plan_file)}`"


def main() -> None:
    os.makedirs(os.path.join(DOCS, "plans"), exist_ok=True)
    cycle = demo_data.BUSY_CYCLE_SEC
    t0 = float(int(time.time()) // cycle * cycle)          # 對齊到一個週期的開頭

    # 每分鐘一格,涵蓋一整個週期(含一次線路超標)
    frames = []
    for k in range(cycle // 60):
        t = t0 + k * 60
        frames.append({"netflow": demo_data.netflow(t), "firewall": demo_data.firewall(t), "availability": demo_data.availability(t)})
    fixed = {"threat_map": demo_data.threat_map(t0), "risk_hits": demo_data.risk_hits(t0), "meraki": demo_data.meraki(t0)}

    topn = {f"{lid}|{d}": demo_data.topn(lid, d, 10, t0) for lid in demo_data.LINE_LABELS for d in ("in", "out")}
    find_all = demo_data.find("02:00:5e", t0)
    diag, profile = {}, {}
    for row in find_all["results"]:
        mac = row["mac"]
        probe = demo_data.diag(mac, 2, t0)
        key = next(m for m in ("02:00:5e:10:00:01", "02:00:5e:10:00:03", "02:00:5e:10:00:02")
                   if demo_data.diag(m, 2, t0)["verdict"] == probe["verdict"] and demo_data.diag(m, 2, t0)["findings"] == probe["findings"])
        profile[mac] = key
    for key in sorted(set(profile.values())):
        for h in (1, 2, 4, 24):
            diag[f"{key}|{h}"] = demo_data.diag(key, h, t0)

    data = {"t0": t0, "cycle": cycle, "frames": frames, "fixed": fixed, "topn": topn, "find": find_all,
            "diag": diag, "diagProfile": profile, "diagDefault": "02:00:5e:10:00:02"}
    with open(os.path.join(DOCS, "demo-data.js"), "w", encoding="utf-8") as f:
        f.write("/* 由 demo/build_static.py 產生,請勿手動修改。內容全部是模擬資料。 */\nwindow.NOC_DEMO = ")
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        f.write(";\n")

    shutil.copyfile(os.path.join(HERE, "demo_shim.js"), os.path.join(DOCS, "demo-shim.js"))
    for name in os.listdir(demo_data.PLANS_DIR):
        if name.lower().endswith(".png"):
            shutil.copyfile(os.path.join(demo_data.PLANS_DIR, name), os.path.join(DOCS, "plans", name))

    with open(os.path.join(ROOT, "dashboard.html"), "r", encoding="utf-8") as f:
        html = f.read()
    if PLAN_URL_OLD not in html:
        sys.exit("dashboard.html 裡找不到平面圖網址那一行,請更新 build_static.py 的 PLAN_URL_OLD。")
    html = html.replace(PLAN_URL_OLD, PLAN_URL_NEW)
    marker = "<script>"
    idx = html.index(marker)                                   # 在大螢幕自己的 script 之前載入模擬資料
    html = html[:idx] + '<script src="demo-data.js"></script>\n<script src="demo-shim.js"></script>\n' + html[idx:]
    with open(os.path.join(DOCS, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)
    with open(os.path.join(DOCS, ".nojekyll"), "w") as f:      # 告訴 GitHub Pages 不要用 Jekyll 處理
        f.write("")

    size = os.path.getsize(os.path.join(DOCS, "demo-data.js")) // 1024
    print(f"已產生 docs/index.html、docs/demo-data.js({size} KB)、docs/demo-shim.js、docs/plans/")
    print("本機預覽:python -m http.server 8090 --directory docs  然後開 http://127.0.0.1:8090/")


if __name__ == "__main__":
    main()
