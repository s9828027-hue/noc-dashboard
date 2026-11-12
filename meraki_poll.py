#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Meraki 無線 AP 樓層狀態收集器(唯讀)
====================================
用途:定時向 Meraki Dashboard API 取得「HQ 大樓各樓層的 AP 位置、狀態、連線品質」,寫成 meraki_latest.json,
     並把各樓層的平面圖下載到 meraki_plans 資料夾,給大螢幕畫面的「大樓無線 AP 健康度」使用。
     只有讀取(GET),不會更改 Meraki 的任何設定。

這支腳本做什麼
--------------
  1. 找出 HQ 網路,讀取它的樓層平面圖與每層的 AP(位置來自 Meraki 的經緯度,換算成圖上的百分比)
  2. 讀取設備狀態(online / alerting / offline / dormant)
  3. 讀取近 1 小時各 AP 的連線成功率(assoc/auth/dhcp/dns 失敗次數 vs 成功次數)
  4. 讀取目前未解除的告警,對到是哪一支 AP
  5. 讀取各 AP 目前的連線用戶數(這項抓不到時會略過,不影響其他資料)
  6. 平面圖只在「圖片有更新」時才重新下載(圖片網址 7 天會過期,所以每次都重新取得新網址)
  7. 每次執行追加一行到 meraki_history.csv(給畫面畫 24 小時在線趨勢)

使用前準備
----------
  pip install requests
  Meraki 唯讀 API Key,放法二選一:
    (a) 環境變數 MERAKI_DASHBOARD_API_KEY(測試時用,關掉視窗就消失)
    (b) 正式環境(DB server):用系統管理員 PowerShell 執行  python meraki_poll.py --set-key
        金鑰會用 Windows 機器層級加密(DPAPI)存成 meraki_apikey.machine.dat,只有 SYSTEM 與系統管理員能讀;
        dashboard_server(SYSTEM 帳號)會自動讀它,不需要設環境變數
  DB server 要連得到 https://api.meraki.com 以及平面圖主機 meraki-apac.s3.ap-northeast-1.amazonaws.com (443)

用法
----
  python meraki_poll.py            # 抓一次、寫檔、印摘要
  python meraki_poll.py --quiet    # 只寫檔(給 dashboard_server 背景定時執行用)
  python meraki_poll.py --dry      # 只印摘要,不寫任何檔案(第一次測試用,最安全)
  python meraki_poll.py --set-key  # 輸入並加密儲存 API Key(要系統管理員;輸入時畫面不會顯示)
  python meraki_poll.py --check-key  # 檢查加密的金鑰讀得出來,而且 Meraki 接受它

要改的設定都在下面「設定區」。
"""

import argparse
import csv
import getpass
import shutil
import subprocess
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("缺少 requests:請先執行  pip install requests")

# ─────────────────────────── 設定區 ───────────────────────────
ORG_ID = os.environ.get("MERAKI_ORG_ID", "000000")             # 組織 ID(改成你的,或用環境變數 MERAKI_ORG_ID)
NETWORK_NAME = os.environ.get("MERAKI_NETWORK_NAME", "HQ")      # 只收這個網路(名稱完全相符,不分大小寫)
NETWORK_ID = os.environ.get("MERAKI_NETWORK_ID", "")            # 知道網路 ID 就填,可省一次查詢
# 要顯示的樓層(用 Meraki 上平面圖的名稱)。B2F、B3F 是停車場,不放;要加就在這裡加。
FLOORS_INCLUDE = ["B1F", "01F", "02F", "03F", "04F", "05F", "06F", "07F"]
BASE_URL = os.environ.get("MERAKI_BASE_URL", "https://api.meraki.com/api/v1").rstrip("/")
STATS_WINDOW_SEC = 7200        # 連線成功率看最近多久(秒);設成 2 小時,跟 Meraki 畫面的預設區間一致,方便對照
MIN_ATTEMPTS = 10              # 連線嘗試次數少於這個數,成功率沒有意義,顯示「資料不足」
CLIENT_WINDOW_SEC = 300        # 用戶數:算最近多少秒內出現過的連線用戶
HISTORY_KEEP_DAYS = 7          # 歷史檔只保留幾天
TIMEOUT = 30
PAUSE = 0.2                    # 每次呼叫間隔,遠低於「每組織每秒 10 次」
# ──────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "meraki_latest.json")
HISTORY_FILE = os.path.join(SCRIPT_DIR, "meraki_history.csv")
PLANS_DIR = os.path.join(SCRIPT_DIR, "meraki_plans")
HEALTH_CACHE = os.path.join(SCRIPT_DIR, "meraki_health_cache.json")   # 逐台查健康分數時的暫存(5 分鐘內重複使用)
HEALTH_REFRESH_SEC = 300       # 健康分數多久重新查一次(只有「逐台查」模式才用到)
KEY_FILE = os.path.join(SCRIPT_DIR, "meraki_apikey.machine.dat")       # 機器層級 DPAPI 加密的 API Key
GOOGLE_KEY_FILE = os.path.join(SCRIPT_DIR, "google_sa.machine.dat")    # Google 服務帳戶金鑰(DPAPI 加密;只用來「唯讀」讀已知事件試算表)
SHEET_CONF_FILE = os.path.join(SCRIPT_DIR, "diag_incidents_source.json")   # 試算表設定(試算表 ID、分頁範圍);沒有這個檔就只讀本機 diag_incidents.csv
SHEET_CACHE_FILE = os.path.join(SCRIPT_DIR, "diag_incidents_cache.json")   # 上一次成功讀到的內容(Google 連不上時退回用)
PLAN_INDEX = os.path.join(PLANS_DIR, "_index.json")      # 記錄每張圖目前存的是哪個版本(md5)


# ── API Key 的加密儲存(Windows DPAPI,機器層級:這台電腦上任何帳號都能解,所以另外用檔案權限限制)──
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    inb = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    if protect:   # 0x4 = CRYPTPROTECT_LOCAL_MACHINE
        ok = crypt32.CryptProtectData(ctypes.byref(inb), None, None, None, None, 0x4, ctypes.byref(out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def save_key(key: str) -> None:
    if os.name != "nt":
        raise RuntimeError("加密儲存只支援 Windows;其他系統請改用環境變數 MERAKI_DASHBOARD_API_KEY")
    with open(KEY_FILE, "wb") as f:
        f.write(_dpapi(key.encode("utf-8"), True))
    # 只留 SYSTEM(讀)與系統管理員(完全控制),拿掉繼承來的其他權限
    subprocess.run(["icacls.exe", KEY_FILE, "/inheritance:r", "/grant", "SYSTEM:(R)", "/grant", "BUILTIN\\Administrators:(F)"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def load_key() -> str | None:
    """先看環境變數,沒有再讀加密檔。都沒有回傳 None。"""
    k = os.environ.get("MERAKI_DASHBOARD_API_KEY") or os.environ.get("MERAKI_API_KEY")
    if k:
        return k.strip()
    if os.name == "nt" and os.path.isfile(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return _dpapi(f.read(), False).decode("utf-8").strip()
    return None


def save_google_key(json_text: str) -> None:
    """服務帳戶 JSON 金鑰:驗證格式後用 DPAPI(本機層級)加密存檔,只留 SYSTEM 讀取與系統管理員完全控制。"""
    info = json.loads(json_text)
    if info.get("type") != "service_account" or not info.get("client_email") or not info.get("private_key"):
        raise ValueError("這不是 Google 服務帳戶的 JSON 金鑰檔(要有 type=service_account、client_email、private_key)")
    if os.name != "nt":
        raise RuntimeError("加密儲存只支援 Windows;其他系統請用環境變數 GOOGLE_SA_JSON_FILE 指到金鑰檔")
    with open(GOOGLE_KEY_FILE, "wb") as f:
        f.write(_dpapi(json_text.encode("utf-8"), True))
    subprocess.run(["icacls.exe", GOOGLE_KEY_FILE, "/inheritance:r", "/grant", "SYSTEM:(R)", "/grant", "BUILTIN\\Administrators:(F)"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def load_google_key() -> dict | None:
    f = os.environ.get("GOOGLE_SA_JSON_FILE")
    if f and os.path.isfile(f):
        with open(f, "r", encoding="utf-8") as fh:
            return json.load(fh)
    if os.name == "nt" and os.path.isfile(GOOGLE_KEY_FILE):
        with open(GOOGLE_KEY_FILE, "rb") as fh:
            return json.loads(_dpapi(fh.read(), False).decode("utf-8"))
    return None


def has_key() -> bool:
    """給 dashboard_server 判斷「要不要啟動 Meraki 背景更新」用:有環境變數或加密檔就算有。"""
    return bool(os.environ.get("MERAKI_DASHBOARD_API_KEY") or os.environ.get("MERAKI_API_KEY") or os.path.isfile(KEY_FILE))


class Meraki:
    def __init__(self, key: str):
        self.s = requests.Session()
        # 用自訂標頭帶金鑰:Meraki 會轉址到別的主機,Authorization 標頭在跨主機轉址時會被丟掉,自訂標頭不會
        self.s.headers.update({"X-Cisco-Meraki-API-Key": key, "Accept": "application/json"})

    def get(self, path, params=None):
        url = path if path.startswith("http") else BASE_URL + path
        for _ in range(5):
            r = self.s.get(url, params=params, timeout=TIMEOUT)
            if r.status_code == 429:                       # 呼叫太快:依 Retry-After 等一下再試
                time.sleep(min(float(r.headers.get("Retry-After", "1")), 30))
                continue
            time.sleep(PAUSE)
            return r
        raise RuntimeError(f"一直被限流(429):{path}")

    def get_all(self, path, params=None):
        """會換頁的清單端點:跟著回應標頭的 next 連結一頁頁抓。"""
        out, url, p = [], path, dict(params or {})
        for _ in range(100):
            r = self.get(url, p)
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code} {path}:{r.text[:160]}")
            data = r.json()
            out.extend(data if isinstance(data, list) else [data])
            nxt = r.links.get("next", {}).get("url")
            if not nxt:
                return out
            url, p = nxt, None
        return out

    def get_json(self, path, params=None):
        r = self.get(path, params)
        if r.status_code != 200:
            # 多附回應來源(Server 標頭)與內容長度:回應是空的 400,通常是中間的防火牆/Proxy 擋的,不是 Meraki 本身
            raise RuntimeError(f"HTTP {r.status_code} {path}:{r.text[:160]}(Server={r.headers.get('Server', '-')}, 內容 {len(r.content)} 位元組)")
        return r.json()


def norm_floor(name: str) -> str:
    return re.sub(r"\s+", "", str(name)).upper()


def floor_rank(name: str) -> int:
    """B1F → -1、01F → 1、07F → 7(名稱沒有數字就排最後)。"""
    mt = re.match(r"^(B)?(\d+)", norm_floor(name))
    if not mt:
        return 999
    return -int(mt.group(2)) if mt.group(1) else int(mt.group(2))


def floor_label(name: str) -> str:
    """畫面上顯示的短名稱:01F → 1F、B1F → B1F。"""
    mt = re.match(r"^(B?)0*(\d+)(.*)$", norm_floor(name))
    return f"{mt.group(1)}{mt.group(2)}{mt.group(3) or 'F'}" if mt else str(name)


def plan_position(plan: dict, lat: float, lng: float):
    """把 AP 經緯度換算成平面圖上的位置百分比(左上 = 0,0;右下 = 1,1)。圖有旋轉也算得出來。"""
    tl, tr, bl = plan.get("topLeftCorner"), plan.get("topRightCorner"), plan.get("bottomLeftCorner")
    if not (tl and tr and bl):
        return None
    import math
    k = math.cos(math.radians(tl["lat"]))
    vec = lambda a, b: ((b["lng"] - a["lng"]) * k, b["lat"] - a["lat"])   # noqa: E731
    ex, ey = vec(tl, tr)
    fx, fy = vec(tl, bl)
    px, py = vec(tl, {"lat": lat, "lng": lng})
    det = ex * fy - ey * fx
    if abs(det) < 1e-18:
        return None
    return round((px * fy - py * fx) / det, 5), round((ex * py - ey * px) / det, 5)


def short_names(names: list) -> dict:
    """把 AP 名稱共同的前綴去掉,畫面上才放得下。例:HQ-AP-2W-01 → 2W-01。"""
    if len(names) < 2:
        return {n: n for n in names}
    pre = os.path.commonprefix(names)
    cut = pre.rfind("-") + 1 if "-" in pre else 0
    return {n: (n[cut:] or n) for n in names}


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)       # 先寫暫存檔再取代,避免大螢幕剛好讀到寫一半的檔案


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(s))


def sync_plan_image(plan: dict, index: dict, warnings: list) -> str | None:
    """平面圖只在內容有變(md5 不同)或檔案不存在時才下載。回傳檔名(相對於 meraki_plans)。"""
    url = plan.get("imageUrl")
    if not url:
        return None
    ext = (plan.get("imageExtension") or "png").lower()
    fn = f"{safe_name(plan['floorPlanId'])}.{ext}"
    path = os.path.join(PLANS_DIR, fn)
    md5 = plan.get("imageMd5") or ""
    if os.path.isfile(path) and md5 and index.get(fn) == md5:
        return fn
    try:
        r = None
        for attempt in range(4):                     # 圖片大、中間的防火牆偶爾會把連線切斷(10054):最多試 4 次,每次間隔拉長
            try:
                r = requests.get(url, timeout=TIMEOUT)       # 乾淨連線:不帶 API Key(圖片在別的主機)
                break
            except requests.exceptions.ConnectionError:
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        if r.status_code != 200 or not r.content:
            raise RuntimeError(f"HTTP {r.status_code}")
        os.makedirs(PLANS_DIR, exist_ok=True)
        with open(path + ".tmp", "wb") as f:
            f.write(r.content)
        os.replace(path + ".tmp", path)
        index[fn] = md5
        print(f"  已下載平面圖 {plan.get('name')}({len(r.content)//1024} KB,來源 {urlparse(url).netloc})")
        return fn
    except Exception as exc:  # noqa: BLE001
        # 備援:網路一直擋住圖片下載時,可把圖片手動放進 meraki_plans_manual 資料夾,檔名用樓層名稱(例如 05F.png)
        for e2 in ("png", "jpg", "jpeg", "gif"):
            man = os.path.join(SCRIPT_DIR, "meraki_plans_manual", f"{norm_floor(plan.get('name', ''))}.{e2}")
            if os.path.isfile(man):
                fn = f"{safe_name(plan['floorPlanId'])}.{e2}"
                os.makedirs(PLANS_DIR, exist_ok=True)
                shutil.copyfile(man, os.path.join(PLANS_DIR, fn))
                index[fn] = md5
                warnings.append(f"平面圖 {plan.get('name')} 下載失敗,改用手動放置的 {os.path.basename(man)}")
                return fn
        warnings.append(f"平面圖 {plan.get('name')} 下載失敗:{exc}")
        return fn if os.path.isfile(path) else None   # 下載失敗就沿用舊圖


def parse_health(r: dict):
    sn = (r.get("device") or {}).get("serial")
    return sn, {"onboarding": (r.get("onboarding") or {}).get("latest"), "performance": (r.get("performance") or {}).get("latest")}


def fetch_health(m: Meraki, net_id: str, serials: list, warnings: list) -> dict:
    """
    取得每支 AP 的 Onboarding / Performance 分數(官方標示這兩個端點都是 beta)。
    先試「整個網路一次查」;這個環境回 404 的話,改成「逐台查」(96 台約要 40 秒),並且 5 分鐘內重複使用上次結果,避免每次都打 96 次。
    兩種都不行就略過,不影響其他資料。
    """
    try:
        out = {}
        for r in m.get_json(f"/networks/{net_id}/wireless/devices/healthScores"):
            sn, v = parse_health(r)
            if sn:
                out[sn] = v
        return out
    except Exception as exc:  # noqa: BLE001
        err_net = str(exc)

    cache = load_json(HEALTH_CACHE, {})
    if time.time() - cache.get("ts", 0) < HEALTH_REFRESH_SEC and set(serials) <= set(cache.get("scores", {})):
        return cache["scores"]
    if not serials:
        return {}
    first = m.get(f"/devices/{serials[0]}/wireless/healthScores")
    if first.status_code != 200:
        warnings.append(f"AP 健康分數無法取得(整網查詢:{err_net[:60]};逐台查詢:HTTP {first.status_code})")
        return {}
    out = {}
    for i, sn in enumerate(serials):
        try:
            r = first if i == 0 else m.get(f"/devices/{sn}/wireless/healthScores")
            if r.status_code == 200:
                _, v = parse_health(r.json())
                out[sn] = v
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"AP 健康分數部分失敗:{exc}")
            break
    write_json(HEALTH_CACHE, {"ts": time.time(), "scores": out})
    return out


def collect(m: Meraki, warnings: list) -> dict:
    net_id = NETWORK_ID
    if not net_id:
        nets = m.get_all(f"/organizations/{ORG_ID}/networks")
        hit = [n for n in nets if n["name"].lower() == NETWORK_NAME.lower()]
        if not hit:
            raise RuntimeError(f"組織 {ORG_ID} 裡找不到名為「{NETWORK_NAME}」的網路(現有:{'、'.join(n['name'] for n in nets)})")
        net_id = hit[0]["id"]

    plans = m.get_json(f"/networks/{net_id}/floorPlans")
    want = {norm_floor(x) for x in FLOORS_INCLUDE}
    plans = [p for p in plans if norm_floor(p.get("name", "")) in want]
    if not plans:
        raise RuntimeError(f"HQ 的平面圖裡沒有符合 FLOORS_INCLUDE 的樓層:{FLOORS_INCLUDE}")
    plans.sort(key=lambda p: -floor_rank(p["name"]))      # 由上(7F)到下(B1F)

    # 設備狀態(官方標示 devices/statuses 之後可能淘汰;失敗就全部視為未知,並在 warnings 提醒)
    status = {}
    try:
        for r in m.get_all(f"/organizations/{ORG_ID}/devices/statuses", {"networkIds[]": net_id}):
            status[r["serial"]] = r.get("status", "unknown")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"設備狀態取得失敗:{exc}")

    # 連線品質:近 1 小時每支 AP 的成功/失敗次數
    stats = {}
    try:
        for r in m.get_json(f"/networks/{net_id}/wireless/devices/connectionStats", {"timespan": STATS_WINDOW_SEC}):
            c = r.get("connectionStats") or {}
            fail = sum(int(c.get(k) or 0) for k in ("assoc", "auth", "dhcp", "dns"))
            ok = int(c.get("success") or 0)
            stats[r["serial"]] = {"attempts": ok + fail, "success": ok, "fail": fail,
                                  "assoc": c.get("assoc") or 0, "auth": c.get("auth") or 0,
                                  "dhcp": c.get("dhcp") or 0, "dns": c.get("dns") or 0}
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"連線成功率取得失敗:{exc}")

    # Meraki 自己的 AP 健康分數(畫面上 Wireless > Monitor > Access points 清單裡的 Onboarding / Performance 兩欄)
    serials = [d["serial"] for p in plans for d in p.get("devices", []) if d.get("productType") in (None, "wireless")]
    health = fetch_health(m, net_id, serials, warnings)

    # 未解除的告警(整個組織取回來,再挑出屬於 HQ 網路的)
    alerts = {}
    try:
        for a in m.get_all(f"/organizations/{ORG_ID}/assurance/alerts", {"perPage": 300}):
            if (a.get("network") or {}).get("id") != net_id or a.get("resolvedAt") or a.get("dismissedAt"):
                continue
            for d in (a.get("scope") or {}).get("devices") or []:
                alerts.setdefault(d.get("serial"), []).append(
                    {"title": a.get("title"), "severity": a.get("severity"), "since": a.get("startedAt")})
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"告警取得失敗:{exc}")

    # 用戶數:最近 N 秒內出現的用戶,依「最近連到的 AP」統計。抓不到就略過(畫面顯示 --)
    clients = None
    try:
        clients = {}
        for c in m.get_all(f"/networks/{net_id}/clients", {"timespan": CLIENT_WINDOW_SEC, "perPage": 1000}):
            s = c.get("recentDeviceSerial")
            if s:
                clients[s] = clients.get(s, 0) + 1
    except Exception as exc:  # noqa: BLE001
        clients = None
        warnings.append(f"用戶數取得失敗(略過):{exc}")

    os.makedirs(PLANS_DIR, exist_ok=True)
    index = load_json(PLAN_INDEX, {})
    all_names = [d.get("name") or d["serial"] for p in plans for d in p.get("devices", [])]
    short = short_names(all_names)

    floors, tot = [], {"aps": 0, "online": 0, "alerting": 0, "offline": 0, "dormant": 0, "unknown": 0}
    for p in plans:
        fn = sync_plan_image(p, index, warnings)
        aps, cnt = [], {"online": 0, "alerting": 0, "offline": 0, "dormant": 0, "unknown": 0}
        for d in p.get("devices", []):
            if d.get("productType") not in (None, "wireless"):
                continue
            name = d.get("name") or d["serial"]
            st = status.get(d["serial"], "unknown")
            cnt[st if st in cnt else "unknown"] += 1
            pos = plan_position(p, d["lat"], d["lng"]) if d.get("lat") is not None and d.get("lng") is not None else None
            s = stats.get(d["serial"])
            aps.append({
                "serial": d["serial"], "name": name, "short": short.get(name, name), "model": d.get("model"),
                "status": st, "u": pos[0] if pos else None, "v": pos[1] if pos else None,
                "onboarding": (health.get(d["serial"]) or {}).get("onboarding"),
                "performance": (health.get(d["serial"]) or {}).get("performance"),
                "attempts": s["attempts"] if s else None, "success": s["success"] if s else None,
                "success_pct": round(s["success"] / s["attempts"] * 100, 1) if s and s["attempts"] >= MIN_ATTEMPTS else None,
                "fail": ({k: s[k] for k in ("assoc", "auth", "dhcp", "dns")} if s else None),
                "clients": (clients.get(d["serial"], 0) if clients is not None else None),
                "alerts": alerts.get(d["serial"], []),
            })
        for k, v in cnt.items():
            tot[k] += v
        tot["aps"] += len(aps)
        okp = [a["success_pct"] for a in aps if a["success_pct"] is not None]
        ob = [a["onboarding"] for a in aps if a["onboarding"] is not None]
        pf = [a["performance"] for a in aps if a["performance"] is not None]
        att = sum(a["attempts"] or 0 for a in aps)
        suc = sum(a["success"] or 0 for a in aps)
        floors.append({
            "name": p["name"], "label": floor_label(p["name"]), "rank": floor_rank(p["name"]),
            "plan_file": fn, "plan_md5": p.get("imageMd5"), "width_m": p.get("width"), "height_m": p.get("height"),
            "counts": cnt, "ap_count": len(aps),
            "clients": (sum(a["clients"] or 0 for a in aps) if clients is not None else None),
            "onboarding_avg": round(sum(ob) / len(ob), 1) if ob else None, "onboarding_min": min(ob) if ob else None,
            "performance_avg": round(sum(pf) / len(pf), 1) if pf else None, "performance_min": min(pf) if pf else None,
            "attempts": att, "success_pct": round(suc / att * 100, 1) if att >= MIN_ATTEMPTS else None,   # 整層加權成功率
            "success_pct_min": min(okp) if okp else None,
            "aps": aps,
        })
    write_json(PLAN_INDEX, index)
    return {"network": {"id": net_id, "name": NETWORK_NAME}, "totals": tot, "floors": floors}


def trim_history(now_ts: float) -> None:
    """歷史檔只留最近 HISTORY_KEEP_DAYS 天,避免越長越大。"""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.reader(f))
    except OSError:
        return
    cut = now_ts - HISTORY_KEEP_DAYS * 86400
    keep = [rows[0]] + [r for r in rows[1:] if r and _ts(r[0]) >= cut] if rows else []
    if len(keep) < len(rows):
        with open(HISTORY_FILE, "w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerows(keep)


def _ts(s: str) -> float:
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return 0.0


def append_history(now_iso: str, tot: dict) -> None:
    exists = os.path.isfile(HISTORY_FILE)
    with open(HISTORY_FILE, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["time_utc", "aps", "online", "alerting", "offline", "dormant"])
        w.writerow([now_iso, tot["aps"], tot["online"], tot["alerting"], tot["offline"], tot["dormant"]])
    trim_history(time.time())


def read_trend(hours: int = 24, max_points: int = 96) -> list:
    """從歷史檔取最近 N 小時的「在線 AP 數」,點太多就等距抽樣,給畫面畫趨勢線。"""
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
    except OSError:
        return []
    cut = time.time() - hours * 3600
    pts = [{"t": r["time_utc"], "online": int(r["online"]), "aps": int(r["aps"])} for r in rows
           if r.get("time_utc") and _ts(r["time_utc"]) >= cut]
    if len(pts) > max_points:
        step = len(pts) / max_points
        pts = [pts[int(i * step)] for i in range(max_points)] + [pts[-1]]
    return pts



# ── 搜尋裝置 / 使用者(給大螢幕的搜尋框用)──────────────────────────────
# 隱私設計:用戶端清單只暫存在「記憶體」FIND_CACHE_SEC 秒;不寫檔、不記錄搜尋字串、不記錄結果。
FIND_WINDOW_SEC = 86400        # 搜尋範圍:最近 24 小時內有連線過的裝置(超過這個時間沒連線就搜不到)
FIND_CACHE_SEC = 60            # 清單在記憶體暫存幾秒(連續搜尋不會重複打 Meraki)
FIND_MAX_RESULTS = 20          # 最多回傳幾筆
_find_lock = threading.Lock()
_find_cache = {"ts": 0.0, "rows": []}
_net_id_cache = {"id": NETWORK_ID}


def _resolve_network_id(m: "Meraki") -> str:
    if _net_id_cache["id"]:
        return _net_id_cache["id"]
    nets = m.get_all(f"/organizations/{ORG_ID}/networks")
    hit = [n for n in nets if n["name"].lower() == NETWORK_NAME.lower()]
    if not hit:
        raise RuntimeError(f"找不到名為「{NETWORK_NAME}」的網路")
    _net_id_cache["id"] = hit[0]["id"]
    return _net_id_cache["id"]


def _epoch(v):
    """Meraki 的時間可能是秒數或 ISO 字串,統一轉成秒數。"""
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def clean_find_query(q) -> str:
    """搜尋字串檢查:3~40 字,只允許文字、數字、空白與 . : @ -(擋掉奇怪字元)。不合格丟 ValueError。"""
    q = re.sub(r"\s+", " ", str(q or "")).strip()
    if not (3 <= len(q) <= 40) or not re.fullmatch(r"[\w .:@\-]+", q):
        raise ValueError("bad query")
    return q


def _load_find_rows() -> list:
    with _find_lock:
        now = time.time()
        if now - _find_cache["ts"] < FIND_CACHE_SEC:
            return _find_cache["rows"]
        k = load_key()
        if not k:
            raise RuntimeError("沒有 Meraki 金鑰")
        m = Meraki(k)
        net = _resolve_network_id(m)
        rows = []
        for c in m.get_all(f"/networks/{net}/clients", {"timespan": FIND_WINDOW_SEC, "perPage": 1000}):
            wired = str(c.get("recentDeviceConnection") or "").lower() == "wired"
            rows.append({
                "mac": (c.get("mac") or "").lower(), "name": c.get("description") or "", "user": c.get("user") or "",
                "ip": c.get("ip") or "", "ssid": c.get("ssid") or "", "online": str(c.get("status") or "").lower() == "online",
                "last_seen": _epoch(c.get("lastSeen")), "wired": wired,
                "ap_serial": c.get("recentDeviceSerial") or "", "ap_name": c.get("recentDeviceName") or "",
                "vendor": c.get("manufacturer") or ""})
        _find_cache["ts"], _find_cache["rows"] = now, rows
        return rows


def find_clients(q) -> dict:
    """依「使用者 / 裝置名稱 / MAC / IP」找出裝置目前(或最後一次)連在哪支 AP。MAC 可以含 : - . 或不含,也可只輸入一部分。"""
    q = clean_find_query(q)
    ql = q.lower()
    flat = re.sub(r"[:.\-\s]", "", ql)
    is_hex = len(flat) >= 4 and re.fullmatch(r"[0-9a-f]+", flat) is not None
    rows = _load_find_rows()
    hits = []
    for r in rows:
        if ((is_hex and flat in r["mac"].replace(":", "")) or ql in r["name"].lower() or ql in r["user"].lower()
                or ql in r["ip"] or ql in r["mac"]):
            hits.append(r)
    hits.sort(key=lambda r: (not r["online"], -(r["last_seen"] or 0)))
    return {"total": len(hits), "results": hits[:FIND_MAX_RESULTS], "window_hours": FIND_WINDOW_SEC // 3600}



# ── 單一用戶連線品質診斷(搜尋結果裡的「診斷」按鈕用)────────────────────────
# 資料來源(都是 Meraki 官方 API、唯讀):訊號品質歷史、延遲歷史/統計、連線統計、連線事件、網路事件(斷線原因)、
# 所在 AP 的連線統計與通道使用率。判斷用「規則」算出,每一項都附證據;結果只暫存記憶體 60 秒,不寫檔、不記錄。
DIAG_HOURS = (1, 2, 4, 24)
DIAG_CACHE_SEC = 60
SNR_POOR = 20            # SNR(訊號雜訊比)低於這個值算偏弱(Meraki 建議 ≥ 25 良好、20~25 尚可)
RSSI_POOR = -75          # 訊號強度低於這個值(dBm)算偏弱
LAT_HIGH_MS = 50         # 5 分鐘平均延遲超過這個值算高
ROAM_PER_HOUR_WARN = 6   # 每小時換 AP 超過幾次算頻繁
CHAN_UTIL_BUSY = 50      # AP 通道使用率平均超過這個百分比算忙碌
_diag_cache: dict = {}
_diag_lock = threading.Lock()
KNOW_FILE = os.path.join(SCRIPT_DIR, "diag_knowledge.json")      # 可自行編輯:斷線原因分類、已知問題(沒有這個檔也能跑,用內建值)
INCIDENT_FILE = os.path.join(SCRIPT_DIR, "diag_incidents.csv")   # 可自行編輯:已知事件(施工、維護、停電…),診斷時自動對照
POP_CACHE_SEC = 600      # 「大樓其他用戶」的比較基準快取 10 分鐘(只存數字,不存 MAC)
_pop_cache: dict = {}
DEFAULT_KNOW = {
    # cat:benign=正常行為、ambiguous=不明(要看頻率)、suspicious=疑似通道/連線問題
    "disassoc_reasons": {
        "1": {"text": "未指定原因(裝置沒說為什麼就斷了)", "cat": "ambiguous"},
        "2": {"text": "先前的驗證已失效(密碼錯誤或裝置沒正常登出)", "cat": "ambiguous"},
        "3": {"text": "裝置自己離開(關 Wi-Fi、睡眠)", "cat": "benign"},
        "4": {"text": "閒置太久被 AP 移除", "cat": "benign"},
        "5": {"text": "AP 負載太高,無法再服務", "cat": "suspicious"},
        "8": {"text": "裝置離開(漫遊或關閉 Wi-Fi)", "cat": "benign"},
        "15": {"text": "4 向交握逾時(金鑰協商失敗)", "cat": "suspicious"},
        "23": {"text": "802.1X 驗證失敗", "cat": "suspicious"},
        "34": {"text": "通道品質太差(AP 送的封包一直沒被確認,就是掉包)", "cat": "suspicious"}},
    "event_descriptions": [      # 原因碼拿不到時,改用事件說明文字比對(不分大小寫、包含即可)
        {"match": "client has left", "cat": "benign"}, {"match": "association expired", "cat": "benign"},
        {"match": "deauthenticated", "cat": "benign"}, {"match": "client balancing", "cat": "benign"},
        {"match": "unknown reason", "cat": "ambiguous"}, {"match": "previous authentication expired", "cat": "ambiguous"}],
    "known_issues": [],          # 例:{"model": "CW9166", "firmware": "CW 30\\.", "title": "…", "detail": "…", "url": "…"}
}
CAT_TEXT = {"benign": "正常行為", "ambiguous": "不明", "suspicious": "疑似問題"}


def load_knowledge() -> tuple:
    """內建值 + diag_knowledge.json(有的話)。檔案壞掉不影響診斷,只回報一則訊息。"""
    k = {"disassoc_reasons": dict(DEFAULT_KNOW["disassoc_reasons"]), "event_descriptions": list(DEFAULT_KNOW["event_descriptions"]), "known_issues": []}
    if not os.path.isfile(KNOW_FILE):
        return k, ""
    try:
        with open(KNOW_FILE, "r", encoding="utf-8-sig") as f:
            u = json.load(f)
        k["disassoc_reasons"].update({str(a): b for a, b in (u.get("disassoc_reasons") or {}).items() if isinstance(b, dict)})
        k["event_descriptions"] = [x for x in (u.get("event_descriptions") or []) if isinstance(x, dict)] + k["event_descriptions"]
        k["known_issues"] = [x for x in (u.get("known_issues") or []) if isinstance(x, dict)]
        return k, ""
    except (OSError, ValueError) as exc:
        return k, f"diag_knowledge.json 讀取失敗({type(exc).__name__}),已改用內建值"


SHEETS_BASE = os.environ.get("GSHEETS_BASE_URL", "https://sheets.googleapis.com/v4").rstrip("/")
_sheet_state: dict = {"t": 0.0, "rows": None, "msg": "", "creds": None}
_sheet_lock = threading.Lock()
# 試算表(Google 表單的回覆)欄位名稱對照:題目名稱含這些字就對應到該欄(不分大小寫)
COL_ALIASES = {"start_d": ("開始日期", "start date"), "start": ("開始時間", "開始", "start"), "end_d": ("結束日期", "end date"),
               "end": ("結束時間", "結束", "end"), "scope": ("範圍", "樓層", "scope"), "note": ("說明", "備註", "事件", "note")}


def parse_time(x) -> float | None:
    """認得常見格式:2026-10-21 09:00、2026/10/21 上午 9:00:00、10/21/2026 9:00 AM、只有日期…(視為伺服器本地時間)。"""
    x = str(x or "").strip()
    if not x:
        return None
    mt = re.search(r"(上午|下午|AM|PM|am|pm)?\s*(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(上午|下午|AM|PM|am|pm)?", x)
    h = mi = sec = 0
    rest = x
    if mt:
        h, mi, sec = int(mt.group(2)), int(mt.group(3)), int(mt.group(4) or 0)
        ap_ = (mt.group(1) or mt.group(5) or "").upper()
        if ap_ in ("下午", "PM") and h < 12:
            h += 12
        if ap_ in ("上午", "AM") and h == 12:
            h = 0
        rest = x[:mt.start()] + " " + x[mt.end():]
    md = re.search(r"(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})", rest)
    if md:
        y, mo, d = int(md.group(1)), int(md.group(2)), int(md.group(3))
    else:
        md = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})", rest)        # 美式 月/日/年(Google 試算表預設的英文格式)
        if not md:
            return None
        mo, d, y = int(md.group(1)), int(md.group(2)), int(md.group(3))
    try:
        return time.mktime(datetime(y, mo, d, h, mi, sec).timetuple())
    except (ValueError, OverflowError):
        return None


def _sheet_rows_to_events(values: list) -> list:
    """試算表第一列是題目名稱(欄位標題),之後每列是一筆事件。回傳 [{start,end,scope,note}]。"""
    if not values or len(values) < 2:
        return []
    head = [str(h or "").strip().lower() for h in values[0]]

    def col(key, exact_first=True):
        for al in COL_ALIASES[key]:
            for n, h in enumerate(head):
                if h == al.lower():
                    return n
        for al in COL_ALIASES[key]:
            for n, h in enumerate(head):
                if al.lower() in h and not (key in ("start", "end") and "日期" in h):
                    return n
        return None
    c = {k: col(k) for k in COL_ALIASES}
    if c["start"] is None and c["start_d"] is None:
        raise ValueError("試算表找不到「開始時間」欄(第一列題目名稱要包含「開始時間」)")
    out = []
    for row in values[1:]:
        g = lambda k: (str(row[c[k]]).strip() if c[k] is not None and c[k] < len(row) else "")   # noqa: E731
        st = f"{g('start_d')} {g('start')}".strip() if c["start_d"] is not None else g("start")
        en = f"{g('end_d')} {g('end')}".strip() if c["end_d"] is not None else g("end")
        a, b = parse_time(st), parse_time(en)
        if a is None:
            continue
        out.append({"start": a, "end": b if b is not None else a + 86400, "scope": g("scope") or "ALL", "note": g("note")[:120]})
    return out


def _fetch_sheet_events(conf: dict) -> list:
    """用服務帳戶(唯讀範圍)向 Google Sheets API 讀一次。需要 pip install google-auth。"""
    info = load_google_key()
    if not info:
        raise RuntimeError("找不到 Google 服務帳戶金鑰(請先執行 --set-google-key)")
    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
    except ImportError:
        raise RuntimeError("缺少套件 google-auth,請在 DB server 執行:pip install google-auth")
    cred = _sheet_state.get("creds")
    if cred is None:
        cred = service_account.Credentials.from_service_account_info(info, scopes=["https://www.googleapis.com/auth/spreadsheets.readonly"])
        _sheet_state["creds"] = cred
    if not cred.valid:
        cred.refresh(Request())
    rng = conf.get("range") or "A:Z"
    from urllib.parse import quote
    r = requests.get(f"{SHEETS_BASE}/spreadsheets/{conf['spreadsheet_id']}/values/{quote(rng, safe='')}",
                     params={"valueRenderOption": "FORMATTED_VALUE", "dateTimeRenderOption": "FORMATTED_STRING"},
                     headers={"Authorization": f"Bearer {cred.token}"}, timeout=15)
    if r.status_code != 200:
        hint = {403: "(沒有權限:請確認試算表有分享給服務帳戶 email,權限至少「檢視者」)", 404: "(找不到:請確認試算表 ID 與分頁名稱)"}.get(r.status_code, "")
        raise RuntimeError(f"Google Sheets HTTP {r.status_code}{hint}")
    return _sheet_rows_to_events(r.json().get("values") or [])


def sheet_events() -> tuple:
    """(事件清單, 訊息)。快取 5 分鐘;讀不到就用上次成功的內容(記憶體 → 檔案),並回報訊息讓畫面註明。沒設定試算表就回空。"""
    conf = load_json(SHEET_CONF_FILE, None)
    if not conf or not conf.get("spreadsheet_id"):
        return [], ""
    ttl = max(30, int(conf.get("cache_sec") or 300))
    with _sheet_lock:
        st = _sheet_state
        if st["rows"] is not None and time.time() - st["t"] < ttl:
            return st["rows"], st["msg"]
        try:
            st["rows"], st["msg"], st["t"] = _fetch_sheet_events(conf), "", time.time()
            try:
                write_json(SHEET_CACHE_FILE, {"saved_at": time.time(), "rows": st["rows"]})
            except OSError:
                pass
        except Exception as exc:  # noqa: BLE001
            st["creds"] = None
            if st["rows"] is None:
                old = load_json(SHEET_CACHE_FILE, {}) or {}
                st["rows"] = old.get("rows") or []
            st["msg"] = f"讀取已知事件試算表失敗,改用上次的內容({str(exc)[:90]})"
            st["t"] = time.time() - ttl + 60          # 失敗後 1 分鐘再試,不要每次診斷都卡 15 秒
        return st["rows"], st["msg"]


def load_incidents(t0: float, t1: float, floor: str, ap_names: set) -> tuple:
    """已知事件 = 本機 diag_incidents.csv(欄位 start,end,scope,note) + Google 試算表(選用)。回傳 (和這段時間、這個位置有關的事件, 訊息)。
    scope 可填 ALL、樓層(如 4F)、或 AP 名稱;可用逗號/頓號寫多個。"""
    rows = []
    if os.path.isfile(INCIDENT_FILE):
        try:
            raw = open(INCIDENT_FILE, "rb").read()
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = raw.decode("cp950", errors="replace")      # Excel 在中文 Windows 另存「CSV」預設是 Big5,也讀得懂
            for r in csv.DictReader(text.splitlines()):
                a, b = parse_time(r.get("start")), parse_time(r.get("end"))
                if a is not None:
                    rows.append({"start": a, "end": b if b is not None else a + 86400, "scope": (r.get("scope") or "ALL").strip(), "note": (r.get("note") or "").strip()[:120]})
        except (OSError, csv.Error, ValueError):
            pass
    srows, msg = sheet_events()
    out = []
    for r in rows + srows:
        if r["end"] < t0 or r["start"] > t1:
            continue
        scopes = [x.strip().lower() for x in re.split(r"[,,、;;]", r["scope"] or "ALL") if x.strip()] or ["all"]
        if any(sc in ("all", "*", "全部") or sc == (floor or "").lower() or sc in ap_names for sc in scopes):
            out.append(r)
    return sorted(out, key=lambda x: x["start"])[:6], msg


def _rank(pop, v):
    """v 比 pop 裡多少 % 的人差(數字越大越差)。樣本太少(<20)就不比。"""
    if v is None or not pop or len(pop) < 20:
        return None
    return round(100.0 * sum(1 for x in pop if x <= v) / len(pop))


def _pctile(pop, q):
    return pop[min(len(pop) - 1, int(len(pop) * q))] if pop else None


def _ts(v):
    return _epoch(v)


def _avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else None


def _ap_names() -> dict:
    """HQ 的 AP:序號 → 顯示名稱、目前用戶數(從 meraki_latest.json 讀,沒有就空)。"""
    out = {}
    for f in (load_json(OUTPUT_FILE, {}) or {}).get("floors", []):
        for a in f.get("aps", []):
            out[a.get("serial")] = {"short": a.get("short") or a.get("name"), "full": a.get("name"), "floor": f.get("label"), "clients": a.get("clients")}
    return out


def diagnose_client(mac: str, hours: int) -> dict:
    mac = str(mac or "").lower().replace("-", ":")
    if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac) or int(hours) not in DIAG_HOURS:
        raise ValueError("bad args")
    hours = int(hours)
    key = (mac, hours)
    with _diag_lock:
        hit = _diag_cache.get(key)
        if hit and time.time() - hit[0] < DIAG_CACHE_SEC:
            return hit[1]
        for k in [k for k, v in _diag_cache.items() if time.time() - v[0] > 300]:   # 清掉舊的,記憶體不會一直長
            _diag_cache.pop(k, None)
        res = _diagnose(mac, hours)
        _diag_cache[key] = (time.time(), res)
        return res


def _diagnose(mac: str, hours: int) -> dict:
    k = load_key()
    if not k:
        raise RuntimeError("沒有 Meraki 金鑰")
    m = Meraki(k)
    net = _resolve_network_id(m)
    span = hours * 3600
    res_sec = 300                      # 5 分鐘一點(1/2/4/24 小時都用這個,最多 288 點;300 是這幾個端點都接受的值)
    now = time.time()
    unavail = {}

    def get(name, path, params=None):
        try:
            r = m.get(path, params)
        except Exception as exc:  # noqa: BLE001
            unavail[name] = type(exc).__name__
            return None
        if r.status_code != 200:
            unavail[name] = f"HTTP {r.status_code}"
            return None
        try:
            return r.json()
        except ValueError:
            unavail[name] = "非 JSON"
            return None

    cl = get("用戶資料", f"/networks/{net}/clients/{mac}") or {}
    serial = cl.get("recentDeviceSerial") or ""
    names = _ap_names()
    apn = lambda s: (names.get(s) or {}).get("short") or s    # noqa: E731

    sig = get("訊號", f"/networks/{net}/wireless/signalQualityHistory", {"clientId": mac, "timespan": span, "resolution": res_sec}) or []
    lat = get("延遲歷史", f"/networks/{net}/wireless/latencyHistory", {"clientId": mac, "timespan": span, "resolution": res_sec}) or []
    lst = (get("延遲統計", f"/networks/{net}/wireless/clients/{mac}/latencyStats", {"timespan": span}) or {}).get("latencyStats") or {}
    cst = (get("連線統計", f"/networks/{net}/wireless/clients/{mac}/connectionStats", {"timespan": span}) or {}).get("connectionStats") or {}
    cev = get("連線事件", f"/networks/{net}/wireless/clients/{mac}/connectivityEvents", {"timespan": span, "perPage": 1000}) or []
    ev = get("網路事件", f"/networks/{net}/events", {"productType": "wireless", "clientMac": mac, "perPage": 1000}) or {}
    ev = [e for e in (ev.get("events") if isinstance(ev, dict) else []) or [] if (_ts(e.get("occurredAt")) or 0) >= now - span]
    devstats = get("AP 連線統計", f"/networks/{net}/wireless/devices/connectionStats", {"timespan": span}) or []
    util = get("通道使用率", f"/networks/{net}/wireless/channelUtilizationHistory", {"deviceSerial": serial, "timespan": span, "resolution": 600}) if serial else None
    dev = (get("AP 型號/韌體", f"/devices/{serial}") or {}) if serial else {}
    know, know_msg = load_knowledge()
    if know_msg:
        unavail["知識檔"] = know_msg
    # 大樓其他用戶的比較基準:只留數字(不留 MAC),快取 10 分鐘。拿不到就不比(畫面會註明)
    pk = min(span, 604800)
    hit = _pop_cache.get(pk)
    if hit and time.time() - hit[0] < POP_CACHE_SEC:
        pop = hit[1]
    else:
        pl = get("大樓用戶延遲比較", f"/networks/{net}/wireless/clients/latencyStats", {"timespan": pk, "fields": "avg"})
        pc = get("大樓用戶連線比較", f"/networks/{net}/wireless/clients/connectionStats", {"timespan": pk})
        pop = {"lat": sorted(v for v in ((((x or {}).get("latencyStats") or {}).get("bestEffortTraffic") or {}).get("avg") for x in (pl or [])) if isinstance(v, (int, float))),
               "fail": sorted(100.0 * f / (f + o) for f, o in ((sum(int(((x or {}).get("connectionStats") or {}).get(k2) or 0) for k2 in ("assoc", "auth", "dhcp", "dns")),
                                                                   int(((x or {}).get("connectionStats") or {}).get("success") or 0)) for x in (pc or [])) if f + o >= 5)}
        if pl is not None or pc is not None:
            _pop_cache[pk] = (time.time(), pop)

    # ── 訊號 ──
    sp = [{"t": _ts(x.get("startTs")), "rssi": x.get("rssi"), "snr": x.get("snr")} for x in sig]
    have = [x for x in sp if x["rssi"] is not None or x["snr"] is not None]
    poor = [x for x in have if (x["snr"] is not None and x["snr"] < SNR_POOR) or (x["rssi"] is not None and x["rssi"] < RSSI_POOR)]
    signal = {"points": sp, "avg_rssi": _avg([x["rssi"] for x in have]), "avg_snr": _avg([x["snr"] for x in have]),
              "min_rssi": min([x["rssi"] for x in have if x["rssi"] is not None], default=None),
              "poor_pct": _pct(len(poor), len(have)), "samples": len(have)}
    # ── 延遲 ──
    lp = [{"t": _ts(x.get("startTs")), "ms": x.get("avgLatencyMs")} for x in lat]
    lv = [x["ms"] for x in lp if x["ms"] is not None]
    high = [v for v in lv if v >= LAT_HIGH_MS]

    def tail(cls):
        d = (lst.get(cls) or {}).get("rawDistribution") or {}
        tot = sum(d.values()) if d else 0
        return _pct(sum(v for kk, v in d.items() if int(kk) >= 64), tot), tot

    be_tail, be_tot = tail("bestEffortTraffic")
    vo_tail, vo_tot = tail("voiceTraffic")
    be_avg = (lst.get("bestEffortTraffic") or {}).get("avg")
    latency = {"points": lp, "avg": _avg(lv), "max": max(lv, default=None), "high_pct": _pct(len(high), len(lv)),
               "besteffort_tail_pct": be_tail, "voice_tail_pct": vo_tail, "packets": be_tot + vo_tot, "besteffort_avg": be_avg,
               "peer_rank": _rank(pop["lat"], be_avg), "peer_median": _pctile(pop["lat"], 0.5), "peer_p90": _pctile(pop["lat"], 0.9), "peer_n": len(pop["lat"])}
    # ── 連線建立 ──
    fails = {x: int(cst.get(x) or 0) for x in ("assoc", "auth", "dhcp", "dns")}
    ok = int(cst.get("success") or 0)
    conn = {"success": ok, **fails, "fail_pct": _pct(sum(fails.values()), ok + sum(fails.values()))}
    conn.update({"peer_rank": _rank(pop["fail"], conn["fail_pct"]) if ok + sum(fails.values()) >= 5 else None, "peer_median": _pctile(pop["fail"], 0.5), "peer_n": len(pop["fail"])})
    # ── 漫遊 / 換 AP ──
    seq = sorted([e for e in cev if e.get("type") in ("assoc", "roam") and e.get("deviceSerial")], key=lambda e: _ts(e.get("occurredAt")) or 0)
    switches, pingpong, prev, prev2 = 0, 0, None, None
    ap_cnt: dict = {}
    for e in seq:
        s = e["deviceSerial"]
        ap_cnt[s] = ap_cnt.get(s, 0) + 1
        if prev and s != prev:
            switches += 1
            if prev2 and s == prev2:
                pingpong += 1          # A→B→A:在兩支 AP 間來回跳
        if prev != s:
            prev2, prev = prev, s
    bands: dict = {}
    for e in cev:
        if e.get("band"):
            bands[str(e["band"])] = bands.get(str(e["band"]), 0) + 1
    roam = {"switches": switches, "pingpong": pingpong, "per_hour": round(switches / hours, 1),
            "aps": sorted([{"serial": s, "name": apn(s), "count": c} for s, c in ap_cnt.items()], key=lambda x: -x["count"])[:6], "bands": bands}
    # ── 斷線:依「原因碼 → 事件說明」分成 正常行為 / 不明 / 疑似問題,只有後兩類才算「斷線偏多」 ──
    dis = [e for e in ev if e.get("type") == "disassociation"]
    rc: dict = {}
    cats = {"benign": 0, "ambiguous": 0, "suspicious": 0}
    for e in dis:
        mm = re.search(r"\d+", str((e.get("eventData") or {}).get("reason") or ""))     # 原因碼可能是 34 或 "34" 或 "reason 34"
        code = mm.group(0) if mm else "?"
        info = know["disassoc_reasons"].get(code)
        cat = info.get("cat") if info else None
        if cat not in cats:
            blob = (str(e.get("description") or "") + " " + json.dumps(e.get("eventData") or {}, ensure_ascii=False)).lower()
            cat = next((x.get("cat") for x in know["event_descriptions"] if str(x.get("match") or "").lower() and str(x["match"]).lower() in blob and x.get("cat") in cats), "ambiguous")
        cats[cat] += 1
        rc.setdefault(code, [0, cat, (info or {}).get("text") or "其他原因"])[0] += 1
    disassoc = {"total": len(dis), "cats": cats, "per_hour": round((cats["ambiguous"] + cats["suspicious"]) / hours, 1),
                "reasons": sorted([{"code": c, "text": v[2], "count": v[0], "cat": v[1], "cat_text": CAT_TEXT[v[1]]} for c, v in rc.items()], key=lambda x: -x["count"])[:6],
                "capped": len(ev) >= 1000}
    # ── 所在 AP ──
    rate = {}
    for r in devstats:
        c = r.get("connectionStats") or {}
        tot = int(c.get("success") or 0) + sum(int(c.get(x) or 0) for x in ("assoc", "auth", "dhcp", "dns"))
        if tot >= 20:
            rate[r.get("serial")] = 100.0 * sum(int(c.get(x) or 0) for x in ("assoc", "auth", "dhcp", "dns")) / tot
    allr = sorted(rate.values())
    cu = []
    for x in (util or []):
        v = x.get("utilizationTotal")
        if v is None:      # 不同版本的回傳格式:wifi0/wifi1(每個無線電)或 byBand;取各頻段中最忙的那個
            cand = [(x.get(w) or {}).get("utilizationTotal") for w in ("wifi0", "wifi1")]
            if isinstance(x.get("byBand"), list):
                cand += [((b.get("total") or {}).get("percentage")) for b in x["byBand"]]
            cand = [c for c in cand if isinstance(c, (int, float))]
            v = max(cand) if cand else None
        if v is not None:
            cu.append(v)
    ap = {"serial": serial, "name": apn(serial) if serial else "", "floor": (names.get(serial) or {}).get("floor"), "clients": (names.get(serial) or {}).get("clients"),
          "fail_pct": round(rate[serial], 1) if serial in rate else None, "hq_median_fail_pct": round(allr[len(allr) // 2], 1) if allr else None,
          "util_avg": round(_avg(cu), 1) if cu else None, "model": dev.get("model") or "", "firmware": dev.get("firmware") or ""}
    incidents, inc_msg = load_incidents(now - span, now, ap["floor"] or "", {str(x).lower() for x in (ap["name"], (names.get(serial) or {}).get("full"), serial) if x})
    if inc_msg:
        unavail["已知事件試算表"] = inc_msg

    # ══ 白話判斷(規則)══
    # 三個等級的意思(畫面上有說明):
    #   crit 明顯異常 = 證據強(例如斷線原因 34、訊號大多偏弱、來回漫遊又同時訊號差/斷線),建議處理
    #   warn 需要注意 = 單項偏離,但還不足以斷定,建議拉長時間或請使用者在「卡的當下」回報時間再查
    #   info 參考     = 背景資訊,多半是正常行為(例如訊號很好時的漫遊、大樓多數人都有的現象)
    F = []     # (level, group, title, detail)
    n_att = ok + sum(fails.values())
    sig_ok = signal["samples"] >= 3
    sig_good = sig_ok and (signal["poor_pct"] or 0) < 10 and (signal["avg_snr"] is None or signal["avg_snr"] >= 25)
    sig_bad = sig_ok and (signal["poor_pct"] or 0) >= 30
    susp = cats["suspicious"]
    rssi_t = round(signal["avg_rssi"]) if signal["avg_rssi"] is not None else "--"
    snr_t = round(signal["avg_snr"]) if signal["avg_snr"] is not None else "--"

    if sig_ok and (signal["poor_pct"] or 0) >= 30:
        F.append(("crit" if signal["poor_pct"] >= 60 else "warn", "signal", "訊號偏弱",
                  f"這段時間有 {signal['poor_pct']}% 的時段訊號偏弱(SNR 低於 {SNR_POOR} 或 RSSI 低於 {RSSI_POOR} dBm),平均 RSSI {rssi_t} dBm、SNR {snr_t}。通常是離 AP 太遠、被牆擋住,或裝置天線/省電設定的問題。"))

    # 延遲:先看絕對值,再跟「大樓其他用戶」比;比較不出來時,訊號好就降一級(尖峰多半是裝置省電、背景流量或應用端)
    lat_strong = (latency["high_pct"] or 0) >= 50 or (latency["avg"] or 0) >= 100 or (latency["besteffort_tail_pct"] or 0) >= 15
    lat_mild = (latency["high_pct"] or 0) >= 25 or (latency["avg"] or 0) >= 60 or (latency["besteffort_tail_pct"] or 0) >= 8 or (latency["voice_tail_pct"] or 0) >= 5
    lat_lv = "crit" if lat_strong else "warn" if lat_mild else None
    lat_note = ""
    if lat_lv:
        rk = latency["peer_rank"]
        if rk is not None:
            lat_note = f"在大樓 {latency['peer_n']} 位用戶中,他的一般流量延遲比 {rk}% 的人差(中位數 {round(latency['peer_median'])} ms、最差 10% 約 ≥ {round(latency['peer_p90'])} ms)。"
            if rk < 80:
                lat_lv, lat_note = "info", lat_note + "表示大樓多數人也有類似的延遲,不算他個人的問題。"
            elif rk < 90 and lat_lv == "crit":
                lat_lv = "warn"
        elif sig_good and not susp:
            lat_lv = "warn" if lat_lv == "crit" else "info"
            lat_note = "訊號很好,延遲尖峰比較像裝置省電、背景流量或應用端造成(無法與大樓其他人比較時的保守判斷)。"
    if lat_lv:
        F.append((lat_lv, "latency", "延遲偏高 / 不穩",
                  f"平均延遲 {round(latency['avg']) if latency['avg'] is not None else '--'} ms、最高 {latency['max']} ms;{latency['high_pct']}% 的 5 分鐘區段超過 {LAT_HIGH_MS} ms,一般流量有 {latency['besteffort_tail_pct']}% 的封包延遲 ≥ 64 ms。"
                  f"無線上的封包遺失會被重送,表現出來就是延遲變高、忽快忽慢。{lat_note}"))

    # 漫遊:訊號很好又沒有其他症狀時,只當參考(人在走動很正常);有訊號差/斷線/延遲異常同時出現才升級
    if roam["pingpong"] >= 2 or roam["per_hour"] >= ROAM_PER_HOUR_WARN:
        side = sig_bad or susp or lat_lv in ("warn", "crit")
        if not side and sig_good:
            rl, extra = "info", "但訊號良好、沒有其他異常,多半只是人在移動(例如走去會議室),不必處理。"
        elif roam["pingpong"] >= 4 and side:
            rl, extra = "crit", "同時還有訊號差、斷線或延遲異常,換 AP 很可能就是造成中斷的原因。"
        else:
            rl, extra = "warn", "每次換 AP 都可能造成短暫中斷;常見於人站在兩支 AP 交界處,或訊號不夠好時裝置一直想換。"
        F.append((rl, "roam", "漫遊頻繁" if rl != "info" else "漫遊較多(訊號良好)",
                  f"{hours} 小時內換了 {roam['switches']} 次 AP(平均每小時 {roam['per_hour']} 次),其中 {roam['pingpong']} 次是在兩支 AP 間來回跳。{extra}"))

    r34 = rc.get("34", [0])[0]
    if r34:
        F.append(("crit" if r34 >= 3 else "warn", "disassoc", "有因為通道品質差被斷線", f"出現 {r34} 次斷線原因 34:AP 送出的封包一直沒被裝置確認(就是實際的掉包),被判定通道品質太差而中斷連線。"))
    bad_dis = cats["ambiguous"] + cats["suspicious"]
    if bad_dis >= 6 and disassoc["per_hour"] >= 3:      # 用「每小時次數」判斷,不會因為時間範圍拉長就必然超標;正常行為(離開、閒置)不算
        F.append(("crit" if susp >= 6 else "warn", "disassoc", "斷線偏多",
                  f"{hours} 小時內有 {bad_dis} 次不明或疑似問題的斷線(每小時 {disassoc['per_hour']} 次);另有 {cats['benign']} 次屬正常行為(離開、閒置)不計入。原因分布見下方。"))

    if conn["fail_pct"] is not None and n_att >= 5 and conn["fail_pct"] >= 20:
        top = max(fails, key=fails.get)
        cl_ = "crit" if conn["fail_pct"] >= 50 and n_att >= 10 else "warn"
        peer = ""
        if conn["peer_rank"] is not None:
            peer = f"在大樓 {conn['peer_n']} 位用戶中,他的失敗率比 {conn['peer_rank']}% 的人高(中位數 {conn['peer_median']:.0f}%)。"
            if conn["peer_rank"] < 80:
                cl_, peer = "info", peer + "大樓多數人也常失敗(此環境驗證失敗偏多是常態),不算他個人的問題。"
        F.append((cl_, "conn", "連線建立常失敗" if cl_ != "info" else "連線建立失敗(大樓常態)",
                  f"連線嘗試失敗 {conn['fail_pct']}%(關聯 {fails['assoc']}、驗證 {fails['auth']}、DHCP {fails['dhcp']}、DNS {fails['dns']}),最多是「{ {'assoc': '關聯', 'auth': '驗證', 'dhcp': 'DHCP', 'dns': 'DNS'}[top] }」。"
                  f"驗證失敗多半是帳密/憑證問題;DHCP、DNS 失敗則偏向網路端問題。{peer}"))

    b24 = bands.get("2.4", 0) + bands.get("2", 0)
    if bands and "5" in str(cl.get("wirelessCapabilities") or "") and b24 / max(sum(bands.values()), 1) >= 0.5:
        F.append(("info", "band", "多半停在 2.4 GHz", "這台裝置支援 5 GHz,但多數連線事件發生在 2.4 GHz;2.4 GHz 容易被干擾、速度也較慢。"))
    if ap["util_avg"] is not None and ap["util_avg"] >= CHAN_UTIL_BUSY:
        F.append(("warn", "ap", "所在 AP 通道很忙", f"{ap['name']} 的通道使用率平均 {ap['util_avg']}%,通道擁擠會讓所有人都變慢、重送變多。"))
    if ap["fail_pct"] is not None and ap["hq_median_fail_pct"] is not None and ap["fail_pct"] >= max(2 * ap["hq_median_fail_pct"], 20):
        F.append(("crit" if ap["fail_pct"] >= max(3 * ap["hq_median_fail_pct"], 30) else "warn", "ap", "所在 AP 整體連線失敗率偏高",
                  f"{ap['name']} 的連線失敗率 {ap['fail_pct']}%,明顯高於大樓中位數 {ap['hq_median_fail_pct']}%,可能是這支 AP 或這一區的問題,不只這位用戶。"))
    for ki in know["known_issues"]:      # 你自己整理的已知問題(例如韌體 Release Notes 的 Known issues),型號/韌體符合才顯示
        try:
            if re.search(str(ki.get("model") or ".*"), ap["model"] or "", re.I) and (not ki.get("firmware") or re.search(str(ki["firmware"]), ap["firmware"] or "", re.I)) and ap["model"]:
                F.append(("info", "known", f"已知問題:{ki.get('title') or ''}", f"{ap['name']}({ap['model']} / {ap['firmware'] or '韌體未知'})符合你登錄的已知問題。{ki.get('detail') or ''}{(' 參考:' + ki['url']) if ki.get('url') else ''}"))
        except re.error:
            continue
    if incidents:
        F.append(("info", "incident", "這段時間有已知事件", "、".join(f"{time.strftime('%m/%d %H:%M', time.localtime(x['start']))}~{time.strftime('%H:%M', time.localtime(x['end']))} {x['scope']}:{x['note']}" for x in incidents) + "。請先確認症狀是否與它重疊。"))

    order = {"crit": 0, "warn": 1, "info": 2}
    F.sort(key=lambda x: order[x[0]])
    groups: dict = {}
    for lv_, g_, _, _ in F:
        if lv_ in ("crit", "warn") and order[lv_] < order.get(groups.get(g_), 9):
            groups[g_] = lv_
    gl = {g: l for g, l in groups.items()}
    kinds = {g for g in gl}

    # ── 已排除 / 正常的項目:幫忙縮小範圍 ──
    ruled = []
    if sig_good:
        ruled.append(f"訊號良好(平均 RSSI {rssi_t} dBm、SNR {snr_t} dB):先排除距離太遠、被遮擋")
    if n_att >= 3 and not any(fails.values()):
        ruled.append("連線建立沒有失敗:可排除驗證、DHCP、DNS")
    if len(ev) and not r34:
        ruled.append("沒有因通道品質差被斷線(原因 34)")
    if "ap" not in kinds and (ap["fail_pct"] is not None or ap["util_avg"] is not None):
        ruled.append("所在 AP 的失敗率與通道使用率正常:不像整支 AP 的問題")
    if not any(f[1] == "roam" for f in F) and cev:
        ruled.append("換 AP 次數正常")
    if lat_lv is None and lv:
        ruled.append("延遲正常")

    got = sum(1 for x in (signal["samples"], len(lv), n_att, len(cev), len(ev)) if x)     # 有幾類資料真的拿到內容
    ap_g, user_g = {"ap"}, {"signal", "roam", "band", "disassoc"}
    if got <= 1 or len([k for k in unavail if k not in ("知識檔", "大樓用戶延遲比較", "大樓用戶連線比較", "AP 型號/韌體", "已知事件試算表")]) >= 5:
        direction = "資料不足,無法判斷:這位用戶在這段時間幾乎沒有可用的紀錄(可能裝置沒連線、離線太久,或 Meraki 沒回資料)。請把時間範圍拉長,或確認他現在是否連在無線上。"
    elif not kinds:
        direction = ("這段時間沒有明顯異常:訊號、延遲、連線都在可接受範圍。若使用者仍覺得卡,請他回報「卡的當下」的時間,再用 1 小時範圍查那個時段;"
                     "也可能問題在無線之外(有線網路、對外網路、應用程式本身)。")
    elif kinds & ap_g and kinds & user_g:
        direction = "AP 端與用戶端都有跡象:這支 AP 本身偏忙或失敗率高,同時這位用戶的訊號/漫遊也不理想。建議先看這支 AP(負載、干擾、通道),再確認用戶位置與裝置。"
    elif kinds & ap_g:
        direction = "偏向「AP / 這一區」的問題:同一支 AP 上的其他用戶也受影響的機率高,建議先檢查這支 AP 的負載、干擾與通道。"
    elif kinds & user_g:
        direction = "偏向「這位用戶所在位置或裝置」的問題:建議確認他的位置是否在 AP 覆蓋邊緣、裝置 Wi-Fi 驅動與省電設定,必要時請他換個位置測試。"
    elif kinds == {"latency"} and sig_good:
        direction = ("無線射頻品質良好,只有延遲忽高忽低:比較像裝置省電、背景流量、應用程式,或無線以外(有線/對外網路)造成,不像無線掉包。"
                     "建議請使用者回報「卡的當下」的時間,再用 1 小時範圍查那個時段,並同時檢查該時段的對外線路與伺服器。")
    else:
        direction = "偏向「連線建立過程」或延遲的問題:請對照失敗的步驟(驗證 / DHCP / DNS)或延遲數字往對應的服務檢查。"
    if incidents and kinds:
        direction += " 此時段有已知事件(見下方),請先確認是否相關。"

    n_crit, n_warn = sum(1 for g in gl.values() if g == "crit"), sum(1 for g in gl.values() if g == "warn")
    insufficient = direction.startswith("資料不足")
    if insufficient:
        verdict = {"level": "info", "title": "資料不足,無法判斷", "confidence": "低"}
    elif n_crit:
        verdict = {"level": "crit", "title": f"有明顯的連線品質問題({n_crit} 類明顯異常" + (f"、{n_warn} 類需要注意" if n_warn else "") + ")", "confidence": "高" if n_crit + n_warn >= 2 else "中"}
    elif n_warn:
        verdict = {"level": "warn", "title": f"有 {n_warn} 類需要注意的跡象,但證據不夠強,尚不能斷定", "confidence": "中" if n_warn >= 2 else "低"}
    else:
        verdict = {"level": "good", "title": "這段時間沒有明顯異常", "confidence": "中" if ruled else "低"}
    verdict["ruled_out"] = ruled
    return {"client": {"mac": mac, "name": cl.get("description") or "", "user": cl.get("user") or "", "ip": cl.get("ip") or "", "ssid": cl.get("ssid") or "",
                       "os": cl.get("os") or "", "caps": cl.get("wirelessCapabilities") or "", "ap_serial": serial, "ap_name": apn(serial) if serial else ""},
            "hours": hours, "findings": [{"level": a, "group": g, "title": t, "detail": d} for a, g, t, d in F], "group_levels": gl, "direction": direction, "verdict": verdict,
            "signal": signal, "latency": latency, "conn": conn, "roam": roam, "disassoc": disassoc, "ap": ap, "incidents": incidents, "unavailable": unavail,
            "thresholds": {"snr": SNR_POOR, "rssi": RSSI_POOR, "lat_ms": LAT_HIGH_MS}}


def main() -> None:
    ap = argparse.ArgumentParser(description="Meraki HQ 樓層 AP 收集器(唯讀)")
    ap.add_argument("--set-key", action="store_true", help="輸入 Meraki API Key,加密後存到 meraki_apikey.machine.dat(要系統管理員)")
    ap.add_argument("--set-google-key", metavar="JSON檔路徑", help="把 Google 服務帳戶的 JSON 金鑰檔加密存到 google_sa.machine.dat(要系統管理員);存好後請刪除原本的 JSON 檔")
    ap.add_argument("--check-incidents", action="store_true", help="測試讀取已知事件(Google 試算表 + 本機 diag_incidents.csv),顯示解析結果")
    ap.add_argument("--check-key", action="store_true", help="檢查加密的金鑰讀得出來、Meraki 也接受它")
    ap.add_argument("--quiet", action="store_true", help="只寫檔,不印摘要")
    ap.add_argument("--detail", action="store_true", help="另外印出每支 AP 的連線次數明細(成功/各類失敗),用來核對成功率算得對不對")
    ap.add_argument("--dry", action="store_true", help="只印摘要,不寫任何檔案(下載平面圖除外,會存到 meraki_plans)")
    args = ap.parse_args()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if args.set_key:
        k = getpass.getpass("貼上 Meraki 唯讀 API Key(輸入時不會顯示,貼上後按 Enter):").strip()
        if not k:
            sys.exit("沒有輸入金鑰。")
        try:
            Meraki(k).get_json("/organizations")
        except Exception as exc:  # noqa: BLE001
            # 多印「金鑰長度」(不印金鑰本身):Meraki 金鑰通常是 40 個英數字,長度不對多半是貼上時多貼/少貼了
            sys.exit(f"Meraki 不接受這把金鑰或連不上:{exc}\n(收到的金鑰長度 {len(k)},正常約 40)\n沒有儲存。")
        try:
            save_key(k)
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"儲存失敗(要用系統管理員身分執行):{exc}")
        sys.exit(f"已加密儲存到 {KEY_FILE}(只有 SYSTEM 與系統管理員能讀)。")
    if args.set_google_key:
        try:
            with open(args.set_google_key, "r", encoding="utf-8") as f:
                txt = f.read()
            save_google_key(txt)
            em = json.loads(txt).get("client_email")
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"儲存失敗:{exc}")
        sys.exit(f"已加密儲存到 {GOOGLE_KEY_FILE}。\n服務帳戶 email:{em}\n請(1) 把已知事件的試算表分享給這個 email(檢視者即可);(2) 刪除原本的 JSON 檔:{args.set_google_key}")
    if args.check_incidents:
        conf = load_json(SHEET_CONF_FILE, None)
        print(f"試算表設定檔:{'有' if conf else '沒有'}({SHEET_CONF_FILE})")
        _sheet_state.update(t=0.0, rows=None)
        rows, msg = sheet_events()
        print(f"Google 試算表:{len(rows)} 筆" + (f"  ←  {msg}" if msg else ""))
        for r in rows[-5:]:
            print("  ", time.strftime("%Y-%m-%d %H:%M", time.localtime(r["start"])), "→", time.strftime("%Y-%m-%d %H:%M", time.localtime(r["end"])), "|", r["scope"], "|", r["note"])
        inc, _ = load_incidents(time.time() - 7 * 86400, time.time() + 86400, "", set())
        print(f"最近 7 天(含明天)的事件(含本機 CSV,範圍 ALL 或不限):{len(inc)} 筆")
        sys.exit(0)
    if args.check_key:
        try:
            k = load_key()
            if not k:
                sys.exit("找不到金鑰(沒有環境變數,也沒有 meraki_apikey.machine.dat)。")
            orgs = Meraki(k).get_all("/organizations")
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"金鑰讀取或驗證失敗:{exc}")
        sys.exit(f"金鑰可用(長度 {len(k)}),Meraki 回應 {len(orgs)} 個組織。")

    try:
        key = load_key()
    except Exception as exc:  # noqa: BLE001
        key = None
        print(f"[警告] 讀取加密金鑰失敗:{exc}")
    if not key:
        err = "找不到 Meraki API Key(請先執行  python meraki_poll.py --set-key)"
        if not args.dry:
            old = load_json(OUTPUT_FILE, {})
            write_json(OUTPUT_FILE, {**old, "generated_at": now_iso, "status": "error", "message": err})
        sys.exit(f"[錯誤] {err}")

    warnings: list = []
    try:
        data = collect(Meraki(key), warnings)
    except Exception as exc:  # noqa: BLE001
        msg = f"Meraki 資料取得失敗:{exc}"
        print(f"[錯誤] {msg}")
        if not args.dry:       # 保留上一次成功的資料,只把狀態標成 error,畫面可顯示「資料過期/異常」
            old = load_json(OUTPUT_FILE, {})
            write_json(OUTPUT_FILE, {**old, "generated_at": now_iso, "status": "error", "message": msg})
        sys.exit(1)

    payload = {"generated_at": now_iso, "status": "ok", "message": "", "warnings": warnings[:6], **data}
    if not args.dry:
        append_history(now_iso, data["totals"])
        payload["trend"] = read_trend()
        write_json(OUTPUT_FILE, payload)
    if not args.quiet:
        t = data["totals"]
        print(f"\nHQ 共 {len(data['floors'])} 層、{t['aps']} 支 AP:在線 {t['online']}、警告 {t['alerting']}、離線 {t['offline']}、休眠 {t['dormant']}、未知 {t['unknown']}")
        for f in data["floors"]:
            c = f["counts"]
            sp = f["success_pct_min"]
            fp = f["success_pct"]
            dash = lambda v: "--" if v is None else f"{v:g}"   # noqa: E731
            print(f"  {f['label']:<4} AP {f['ap_count']:>3}  在線 {c['online']:>3} 警告 {c['alerting']} 離線 {c['offline']} 休眠 {c['dormant']}  "
                  f"用戶 {f['clients'] if f['clients'] is not None else '--':>4}  "
                  f"上線分數 平均 {dash(f['onboarding_avg']):>5} 最低 {dash(f['onboarding_min']):>3}  "
                  f"效能分數 平均 {dash(f['performance_avg']):>5} 最低 {dash(f['performance_min']):>3}  "
                  f"(連線成功率參考 {('%.0f%%' % fp) if fp is not None else '--'})")
        if args.detail:
            rows = sorted([(a, f["label"]) for f in data["floors"] for a in f["aps"]],
                          key=lambda t: (t[0]["onboarding"] is None, t[0]["onboarding"] if t[0]["onboarding"] is not None else 0))[:12]
            print(f"\n上線分數最低的 12 支 AP(連線次數是最近 {STATS_WINDOW_SEC // 60} 分鐘):")
            print(f"  {'樓層':<5}{'AP':<22}{'上線':>5}{'效能':>5}{'嘗試':>6}{'成功':>6}{'assoc':>7}{'auth':>6}{'dhcp':>6}{'dns':>5}")
            for a, lb in rows:
                fl = a["fail"] or {}
                v = lambda x: "--" if x is None else str(x)   # noqa: E731
                print(f"  {lb:<5}{a['short']:<22}{v(a['onboarding']):>5}{v(a['performance']):>5}{v(a['attempts']):>6}{v(a['success']):>6}"
                      f"{fl.get('assoc', 0):>7}{fl.get('auth', 0):>6}{fl.get('dhcp', 0):>6}{fl.get('dns', 0):>5}")
        for a in [x for f in data["floors"] for x in f["aps"] if x["status"] not in ("online",) or x["alerts"]][:10]:
            print(f"  [注意] {a['name']}:{a['status']} {'; '.join(al['title'] or '' for al in a['alerts'])}")
        if warnings:
            print("警告:" + ";".join(warnings[:4]))
        print("(--dry 模式,未寫檔)" if args.dry else f"已寫出:{OUTPUT_FILE}")


if __name__ == "__main__":
    main()
