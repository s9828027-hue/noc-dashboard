#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Meraki 探測腳本(唯讀,不會改動任何 Meraki 設定)
================================================
用途:第一次接 Meraki 前,先確認「抓得到什麼」。它會:
  1. 列出你的組織(Organization)與網路(Network)
  2. 列出每個網路的樓層平面圖(Floor plan):樓層名稱、AP 數量
  3. 抓設備狀態,算出每一層的 AP 正常/警告/離線數
  4. 把「AP 在平面圖上的位置」從經緯度換算成百分比(之後畫燈號用)
  5. 下載每層平面圖到 meraki_probe 資料夾,並產生 preview.html,
     可以直接用瀏覽器看「你們實際的 1:200 平面圖」變成透明線稿、疊上 AP 燈號的樣子

使用前準備
----------
  pip install requests
  環境變數 MERAKI_DASHBOARD_API_KEY 放你的 Meraki 唯讀 API Key
    (PowerShell:  $env:MERAKI_DASHBOARD_API_KEY = "貼上金鑰" )
  DB server 要連得到 https://api.meraki.com (HTTPS 443)。
  金鑰在 Dashboard:Organization > Configure > API & Webhooks > API keys and access
  (只有組織管理員看得到;建議用唯讀帳號產生的金鑰)

用法
----
  python meraki_discover.py                 # 掃描全部組織
  python meraki_discover.py --org 123456    # 只看指定組織 ID
  python meraki_discover.py --out D:\\probe  # 指定輸出資料夾(預設 .\\meraki_probe)

區域網址:中國 api.meraki.cn、加拿大 api.meraki.ca、印度 api.meraki.in、政府 api.gov-meraki.com
  可用環境變數 MERAKI_BASE_URL 覆蓋,例如  https://api.meraki.ca/api/v1

安全提醒:API Key 只送到 Meraki 的網址;下載平面圖時「不會」帶金鑰。
"""

import argparse
import html
import json
import math
import os
import re
import sys
import time

try:
    import requests
except ImportError:
    sys.exit("缺少 requests:請先執行  pip install requests")

BASE_URL = os.environ.get("MERAKI_BASE_URL", "https://api.meraki.com/api/v1").rstrip("/")
TIMEOUT = 30
PAUSE = 0.15   # 每次呼叫之間稍微停一下,遠低於「每組織每秒 10 次」的上限


class Meraki:
    """很薄的 API 包裝:自動換頁、遇到 429(太快)就依 Retry-After 等待再試。"""

    def __init__(self, key: str):
        self.s = requests.Session()
        # 用自訂標頭帶金鑰:Meraki 常回 308 轉址到別的主機,Authorization 標頭在跨主機轉址時會被 requests 丟掉,自訂標頭不會
        self.s.headers.update({"X-Cisco-Meraki-API-Key": key, "Accept": "application/json"})

    def get(self, path: str, params: dict | None = None):
        url = path if path.startswith("http") else BASE_URL + path
        for attempt in range(5):
            r = self.s.get(url, params=params, timeout=TIMEOUT)
            if r.status_code == 429:
                wait = float(r.headers.get("Retry-After", "1"))
                time.sleep(min(wait, 30))
                continue
            time.sleep(PAUSE)
            return r
        raise RuntimeError(f"一直被限流(429):{path}")

    def get_json(self, path: str, params: dict | None = None):
        r = self.get(path, params)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} {path}:{r.text[:200]}")
        return r.json()

    def get_all(self, path: str, params: dict | None = None) -> list:
        """會換頁的清單端點:跟著 Link 標頭的 next 一頁頁抓。"""
        out, url, p = [], path, dict(params or {})
        for _ in range(200):
            r = self.get(url, p)
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code} {path}:{r.text[:200]}")
            data = r.json()
            out.extend(data if isinstance(data, list) else [data])
            nxt = r.links.get("next", {}).get("url")
            if not nxt:
                return out
            url, p = nxt, None
        return out


def plan_position(plan: dict, lat: float, lng: float):
    """
    把 AP 的經緯度換算成「在平面圖上的位置百分比」(左上角 = 0,0;右下角 = 1,1)。
    做法:以左上角為原點,算出「往右」「往下」兩條邊的向量,再解出 AP 落在這兩個方向上的比例。
    圖有旋轉也算得出來。範圍很小,所以把經度乘 cos(緯度) 當成平面近似就夠準。
    """
    tl, tr, bl = plan.get("topLeftCorner"), plan.get("topRightCorner"), plan.get("bottomLeftCorner")
    if not (tl and tr and bl):
        return None
    k = math.cos(math.radians(tl["lat"]))

    def vec(a, b):   # a -> b 的平面向量
        return ((b["lng"] - a["lng"]) * k, b["lat"] - a["lat"])

    ex, ey = vec(tl, tr)      # 圖的「右」方向
    fx, fy = vec(tl, bl)      # 圖的「下」方向
    px, py = vec(tl, {"lat": lat, "lng": lng})
    det = ex * fy - ey * fx
    if abs(det) < 1e-18:
        return None
    u = (px * fy - py * fx) / det
    v = (ex * py - ey * px) / det
    return u, v


def load_status_by_serial(m: Meraki, org_id: str) -> dict:
    """設備狀態(online/alerting/offline/dormant)。官方標示 devices/statuses 之後可能淘汰,所以失敗時只警告。"""
    try:
        rows = m.get_all(f"/organizations/{org_id}/devices/statuses")
        return {r["serial"]: r.get("status", "?") for r in rows}
    except Exception as exc:  # noqa: BLE001
        print(f"  [警告] 取不到設備狀態(devices/statuses):{exc}")
        return {}


def floor_rank(plan: dict) -> int:
    """排序用:你們的平面圖沒有填樓層編號(floorNumber 是空的),改用名稱判斷。B3F → -3、01F → 1、07F → 7。"""
    n = plan.get("floorNumber")
    if isinstance(n, (int, float)):
        return int(n)
    name = str(plan.get("name", "")).upper().replace(" ", "")
    mt = re.match(r"^(B)?(\d+)", name)
    if mt:
        return -int(mt.group(2)) if mt.group(1) else int(mt.group(2))
    return 999


def worst(statuses: list) -> str:
    rank = {"offline": 3, "alerting": 2, "online": 1, "dormant": 0}
    return max(statuses, key=lambda s: rank.get(s, 0)) if statuses else "-"


def download_image(url: str, path: str) -> bool:
    """下載平面圖。用乾淨的連線(不帶 API Key),因為圖片網址可能在別的主機。"""
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code != 200 or not r.content:
            print(f"    [警告] 下載圖片失敗 HTTP {r.status_code}")
            return False
        with open(path, "wb") as f:
            f.write(r.content)
        from urllib.parse import urlparse
        print(f"    圖片已下載({len(r.content) // 1024} KB),來源主機:{urlparse(url).netloc}(正式環境的 DB server 也要能連到它)")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"    [警告] 下載圖片失敗:{exc}")
        return False


PREVIEW_CSS = """
body{background:#0d0d0d;color:#e8e8e8;font-family:system-ui,"Microsoft JhengHei",sans-serif;padding:16px}
h2{margin:24px 0 4px} .meta{color:#999;font-size:13px;margin-bottom:8px}
.box{position:relative;display:inline-block;max-width:100%;border:1px solid #333;border-radius:8px;
     background:linear-gradient(rgba(120,160,230,.06) 1px,transparent 1px) 0 0/40px 40px,linear-gradient(90deg,rgba(120,160,230,.06) 1px,transparent 1px) 0 0/40px 40px}
.box img{display:block;max-width:100%;max-height:78vh;filter:invert(1);mix-blend-mode:screen}
.box.orig img{filter:none;mix-blend-mode:normal}
.ap{position:absolute;width:16px;height:16px;margin:-8px 0 0 -8px;border-radius:50%;border:2px solid #000}
.online{background:#3ddc97}.alerting{background:#fab219}.offline{background:#ff4d6d}.dormant,.unknown{background:#777}
.ap span{position:absolute;left:18px;top:-2px;font-size:11px;color:#dfe6f2;white-space:nowrap;text-shadow:0 0 3px #000}
.warn{color:#fab219}button{background:#222;color:#fff;border:1px solid #555;border-radius:6px;padding:4px 10px;cursor:pointer;margin-left:8px}
"""


def write_preview(out_dir: str, sections: list) -> str:
    parts = [f"<!doctype html><meta charset='utf-8'><title>Meraki 平面圖預覽</title><style>{PREVIEW_CSS}</style>",
             "<h1>Meraki 平面圖預覽(透明線稿 + AP 燈號)</h1><div class='meta'>每張圖右邊的按鈕可切換「透明線稿」與「原圖」。若 AP 位置明顯偏離,把此頁截圖給我。</div>"]
    for sec in sections:
        parts.append(f"<h2>{html.escape(sec['title'])}</h2><div class='meta'>{html.escape(sec['meta'])}"
                     "<button onclick=\"this.parentNode.nextSibling.classList.toggle('orig')\">切換原圖/線稿</button></div>")
        dots = "".join(
            f"<div class='ap {d['status']}' style='left:{d['u']*100:.2f}%;top:{d['v']*100:.2f}%' title='{html.escape(d['name'])}'><span>{html.escape(d['name'])}</span></div>"
            for d in sec["aps"])
        parts.append(f"<div class='box'><img src='{html.escape(sec['img'])}'>{dots}</div>")
    path = os.path.join(out_dir, "preview.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description="Meraki 唯讀探測")
    ap.add_argument("--org", help="只看這個組織 ID")
    ap.add_argument("--out", default="meraki_probe", help="輸出資料夾")
    ap.add_argument("--network", action="append", help="只看這個網路名稱(完全相符,不分大小寫);可重複指定。例如 --network HQ")
    args = ap.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY") or os.environ.get("MERAKI_API_KEY")
    if not key:
        sys.exit("找不到環境變數 MERAKI_DASHBOARD_API_KEY(請先設定你的 Meraki 唯讀 API Key)")
    os.makedirs(args.out, exist_ok=True)
    m = Meraki(key)

    try:
        orgs = m.get_all("/organizations")
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"連不到 Meraki 或金鑰無效:{exc}\n請檢查:金鑰是否正確、DB server 能否連 api.meraki.com:443(Proxy/防火牆白名單)。")
    if args.org:
        orgs = [o for o in orgs if str(o.get("id")) == str(args.org)]
    print(f"找到 {len(orgs)} 個組織:" + "、".join(f"{o['name']}({o['id']})" for o in orgs))

    raw_dump, sections = {}, []
    for org in orgs:
        oid = org["id"]
        print(f"\n=== 組織:{org['name']}({oid}) ===")
        try:
            nets = m.get_all(f"/organizations/{oid}/networks")
        except Exception as exc:  # noqa: BLE001
            print(f"  [警告] 取不到網路清單:{exc}")
            continue
        print(f"  網路 {len(nets)} 個:" + "、".join(f"{n['name']}[{','.join(n.get('productTypes', []))}]" for n in nets))
        status = load_status_by_serial(m, oid)
        devs_all = {}
        try:   # 設備名稱/型號(用來顯示 AP 名稱)
            for d in m.get_all(f"/organizations/{oid}/devices"):
                devs_all[d["serial"]] = d
        except Exception as exc:  # noqa: BLE001
            print(f"  [警告] 取不到設備清單:{exc}")

        for net in nets:
            if "wireless" not in net.get("productTypes", []):
                continue
            if args.network and net["name"].lower() not in {x.lower() for x in args.network}:
                continue
            try:
                plans = m.get_json(f"/networks/{net['id']}/floorPlans")
            except Exception as exc:  # noqa: BLE001
                print(f"  [{net['name']}] 取不到樓層平面圖:{exc}")
                continue
            print(f"\n  [{net['name']}](網路 ID {net['id']})樓層平面圖 {len(plans)} 張")
            raw_dump[net["id"]] = plans
            for p in sorted(plans, key=floor_rank):
                devs = p.get("devices", [])
                st = [status.get(d["serial"], "unknown") for d in devs]
                cnt = {k: st.count(k) for k in sorted(set(st))}
                print(f"    「{p.get('name')}」(排序 {floor_rank(p)}) 設備 {len(devs)} 台 {cnt} · "
                      f"圖 {p.get('width')}x{p.get('height')} m · 圖片 {p.get('imageExtension')} · 網址到期 {p.get('imageUrlExpiresAt')}")
                aps, bad = [], 0
                for d in devs:
                    if d.get("lat") is None or d.get("lng") is None:
                        continue
                    pos = plan_position(p, d["lat"], d["lng"])
                    if pos is None:
                        continue
                    u, v = pos
                    if not (-0.02 <= u <= 1.02 and -0.02 <= v <= 1.02):
                        bad += 1
                    full = devs_all.get(d["serial"], {})
                    aps.append({"name": d.get("name") or full.get("name") or d["serial"], "u": u, "v": v,
                                "status": status.get(d["serial"], "unknown")})
                if bad:
                    print(f"      [注意] 有 {bad} 台設備算出來落在圖外,代表座標對不上圖片,要校正")
                if p.get("imageUrl"):
                    fn = f"{net['id']}_{p['floorPlanId']}.{(p.get('imageExtension') or 'png').lower()}".replace("/", "_")
                    if download_image(p["imageUrl"], os.path.join(args.out, fn)):
                        sections.append({"title": f"{net['name']} · {p.get('name')}",
                                         "meta": f"{len(aps)} 台 AP 有座標 · 圖片 {fn}", "img": fn, "aps": aps})

    with open(os.path.join(args.out, "floorplans_raw.json"), "w", encoding="utf-8") as f:
        json.dump(raw_dump, f, ensure_ascii=False, indent=2)
    if sections:
        print(f"\n已產生預覽頁:{write_preview(args.out, sections)}")
        print("用瀏覽器開啟 preview.html,看看實際平面圖變成透明線稿、AP 燈號是否落在正確位置。")
    print(f"原始資料已存到:{os.path.join(args.out, 'floorplans_raw.json')}")


if __name__ == "__main__":
    main()
