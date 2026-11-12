#!/usr/bin/env python3
"""
模擬資料產生器(demo 模式用,所有數字都是假的)
==============================================
這支程式做什麼:
  不連任何真實設備,直接「算」出大螢幕需要的全部資料,格式和各支輪詢程式寫出的檔案一模一樣:
    線路使用率(netflow_poll_poc.py)、防火牆健康度(fw_health_poll.py)、核心設備存活(availability_poll.py)、
    外部流量國別(threat_map_data.py)、高風險 IP 命中(risk_ip_match.py)、大樓無線 AP(meraki_poll.py)。
  另外提供 Top N、搜尋、連線品質診斷的範例回應。

設計重點:
  - 所有數值都是「時間的函式」:同一個時間點算出來的結果永遠一樣,所以
    (1) dashboard_server.py --demo 可以每次被問就即時算,不需要寫任何檔案;
    (2) demo/build_static.py 可以預先算出一串畫面,做成 GitHub Pages 的靜態展示頁。
  - Meraki 的樓層/AP 基礎資料、搜尋與診斷回應放在 demo/canned/,
    是用「真的 meraki_poll.py」去查「假的 Meraki API」(demo/fake_meraki_api.py)錄下來的,
    所以格式保證和正式環境一致。
  - IP 一律使用文件保留位址(203.0.113.x、198.51.100.x、192.0.2.x)或私有位址,人名與設備名稱都是虛構的。

單獨執行可以看一份快照:
    python demo/demo_data.py            # 印出目前的摘要
    python demo/demo_data.py --json     # 印出完整 JSON(等同 /api/summary 的內容)
"""
import copy
import json
import math
import os
import random
import re
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CANNED_DIR = os.path.join(HERE, "canned")
PLANS_DIR = os.path.join(CANNED_DIR, "plans")       # 假的樓層平面圖(線稿)

WARN_PCT, CRIT_PCT = 70, 90

# ── 線路:(ID, 名稱, 設備, 介面, 下載頻寬, 上傳頻寬, 平常下載%, 平常上傳%) ──
LINES = [
    ("5000095", "ISP-A 主線 1G/600M", "Core-SW-1", "Uplink-1", 1000, 600, 46, 21),
    ("5000107", "ISP-B 備援 1G/600M", "Core-SW-1", "Uplink-2", 1000, 600, 38, 30),
    ("5000097", "ISP-C 專線 300M/300M", "Core-SW-1", "Uplink-3", 300, 300, 20, 11),
    ("5000108", "ISP-D 網際網路 1G/600M", "Edge-FW", "WAN2", 1000, 600, 13, 6),
]
# 負載平衡器內側的兩個觀察點:畫面上不顯示,只給「NAT 前內部 IP 推算」使用
INSIDE_LINES = [("5000105", "F5-內網-1", "LB-Inside-1"), ("5000106", "F5-內網-2", "LB-Inside-2")]
LINE_LABELS = {l[0]: l[1] for l in LINES}

BUSY_CYCLE_SEC = 480      # 每 8 分鐘,ISP-B 的上傳會衝高一次(示範「超標 → 整條變紅 → 自動跳出 Top N」)
BUSY_FROM, BUSY_TO = 300, 400


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def _wave(t: float, period: float, phase: float = 0.0) -> float:
    """-1 ~ 1 的平滑波動。"""
    return math.sin(2 * math.pi * (t / period + phase))


def _jitter(t: float, key: int, step: float = 15.0) -> float:
    """-1 ~ 1 的小抖動:同一個 15 秒區間內固定不變,所以畫面不會每次重新整理都亂跳。"""
    return random.Random(int(t // step) * 7919 + key).uniform(-1, 1)


_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def shift_times(obj, delta: float, ref: float):
    """
    把一份錄下來的資料裡「所有時間」往後平移 delta 秒(就地修改並回傳)。
    錄製的範例回應時間停在錄製當下;平移後,畫面上看到的就會是「剛剛」而不是好幾天前。
    判斷方式:ISO 格式的時間字串,以及數值落在錄製時間前後幾天內的 epoch 秒數。
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = shift_times(v, delta, ref)
        return obj
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            obj[i] = shift_times(v, delta, ref)
        return obj
    if isinstance(obj, str) and _ISO_RE.match(obj):
        try:
            dt = datetime.fromisoformat(obj.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            new = datetime.fromtimestamp(dt.timestamp() + delta, timezone.utc)
            return new.strftime("%Y-%m-%dT%H:%M:%SZ") if obj.endswith("Z") else new.isoformat()
        except ValueError:
            return obj
    if isinstance(obj, (int, float)) and not isinstance(obj, bool) and abs(obj - ref) < 4 * 86400:
        return obj + delta
    return obj


def captured_at() -> float:
    """範例回應是什麼時候錄的(讀 meraki_base.json 的產生時間)。"""
    global _meraki_base
    if _meraki_base is None:
        _meraki_base = _load("meraki_base.json")
    return datetime.fromisoformat(_meraki_base["generated_at"]).timestamp()


def _level(pct: float) -> str:
    return "crit" if pct >= CRIT_PCT else "warn" if pct >= WARN_PCT else "ok"


# ══════════════════════════════════════════════════════════════════════
# 線路使用率
# ══════════════════════════════════════════════════════════════════════
def line_utils(t: float) -> dict:
    """回傳 {線路ID: (下載%, 上傳%)}。"""
    out = {}
    for i, (lid, _label, _dev, _if, _ci, _co, base_in, base_out) in enumerate(LINES):
        u_in = base_in + 9 * _wave(t, 1500, i * 0.23) + 4 * _wave(t, 260, i * 0.41) + 2.5 * _jitter(t, i)
        u_out = base_out + 5 * _wave(t, 1100, i * 0.37) + 3 * _wave(t, 200, i * 0.19) + 2 * _jitter(t, 50 + i)
        if lid == "5000107":                                    # ISP-B 上傳的週期性尖峰
            ph = t % BUSY_CYCLE_SEC
            if BUSY_FROM - 60 <= ph < BUSY_FROM:                # 爬升
                u_out += (ph - (BUSY_FROM - 60)) / 60 * 62
            elif BUSY_FROM <= ph < BUSY_TO:                     # 高點(超過 90% 門檻)
                u_out = 93 + 2 * _jitter(t, 99)
            elif BUSY_TO <= ph < BUSY_TO + 40:                  # 回落
                u_out += (1 - (ph - BUSY_TO) / 40) * 62
        out[lid] = (max(1.0, min(99.0, u_in)), max(1.0, min(99.0, u_out)))
    return out


def netflow(t: float) -> dict:
    now_iso = _iso(t)
    utils = line_utils(t)
    records = []
    for lid, label, dev, iface, cap_in, cap_out, _bi, _bo in LINES:
        u_in, u_out = utils[lid]
        cur_in, cur_out = round(cap_in * u_in / 100, 2), round(cap_out * u_out / 100, 2)
        p_in, p_out = round(cur_in / cap_in * 100), round(cur_out / cap_out * 100)
        records.append({
            "id": lid, "label": label, "device": dev, "interface": iface, "status_text": "Up", "link_up": True,
            "capacity_in_mbps": cap_in, "capacity_out_mbps": cap_out,
            "current_in_mbps": cur_in, "current_out_mbps": cur_out,
            "util_in_pct": p_in, "util_out_pct": p_out, "warn_pct": WARN_PCT, "crit_pct": CRIT_PCT,
            "level_in": _level(p_in), "level_out": _level(p_out), "timestamp_utc": now_iso,
        })
    total_in = sum(r["current_in_mbps"] for r in records)
    total_out = sum(r["current_out_mbps"] for r in records)
    for k, (lid, label, iface) in enumerate(INSIDE_LINES):      # 內側觀察點:大約各分一半的總流量
        share = 0.5 + (0.08 if k == 0 else -0.08)
        cur_in, cur_out = round(total_out * share, 2), round(total_in * share, 2)
        records.append({
            "id": lid, "label": label, "device": "Core-SW-1", "interface": iface, "status_text": "Up", "link_up": True,
            "capacity_in_mbps": 10000, "capacity_out_mbps": 10000, "current_in_mbps": cur_in, "current_out_mbps": cur_out,
            "util_in_pct": round(cur_in / 100), "util_out_pct": round(cur_out / 100), "warn_pct": WARN_PCT, "crit_pct": CRIT_PCT,
            "level_in": "ok", "level_out": "ok", "timestamp_utc": now_iso,
        })
    return {"generated_at": now_iso, "lines": records, "warn_pct": WARN_PCT, "crit_pct": CRIT_PCT, "snmp_overlay": {"active": False}}


# ══════════════════════════════════════════════════════════════════════
# 防火牆(HA 兩台:一台主用、一台備援)
# ══════════════════════════════════════════════════════════════════════
def firewall(t: float) -> dict:
    active = 38000 + 4200 * _wave(t, 1800) + 900 * _wave(t, 240, 0.3) + 300 * _jitter(t, 7, 60)
    rows = []
    for i, (label, device, role) in enumerate([("FW-A", "10.0.0.252", "active"), ("FW-B", "10.0.0.253", "standby")]):
        sess = int(active if role == "active" else active * 0.985)        # 備援那台會同步 session,數字接近
        tcp = int(sess * 0.55)
        udp = int(sess * 0.44)
        metrics = {
            "session_util_pct": round(sess / 12000),                       # 假設上限約 120 萬 session
            "active_sessions": sess, "tcp_sessions": tcp, "udp_sessions": udp, "icmp_sessions": sess - tcp - udp,
            "ssl_proxy_sessions": int(2300 + 250 * _wave(t, 900)) if role == "active" else 60 + int(8 * _jitter(t, 21, 60)),
            "dataplane_cpu_pct": round(11 + 4 * _wave(t, 700) + 1.5 * _jitter(t, 31, 60)) if role == "active" else 0,
            "mgmt_cpu_pct": round(2 + 1 * abs(_jitter(t, 40 + i, 60))),
            "memory_util_pct": 31,
        }
        rows.append({"label": label, "device": device, "metrics": metrics,
                     "surge_ratio": round(1.0 + 0.12 * abs(_wave(t, 600, i * 0.2)), 1) if role == "active" else 1.0,
                     "role": role, "alerts": []})
    return {"generated_at": _iso(t), "active_firewall": "FW-A", "cluster_alerts": [], "firewalls": rows}


# ══════════════════════════════════════════════════════════════════════
# 核心設備存活
# ══════════════════════════════════════════════════════════════════════
def availability(t: float) -> dict:
    rows = []
    for i, label in enumerate(["Core-SW-1", "Core-SW-2", "FW-A", "FW-B"]):
        rows.append({"label": label, "response_ms": 1 + (i // 2) + (1 if _jitter(t, 60 + i, 60) > 0.75 else 0),
                     "packet_loss_pct": 0, "pingable": True, "status_text": "Clear", "alerts": []})
    return {"generated_at": _iso(t), "devices": rows}


# ══════════════════════════════════════════════════════════════════════
# 外部流量國別(世界地圖)
# ══════════════════════════════════════════════════════════════════════
_COUNTRIES = [  # iso, 名稱, IN 流量(GB), OUT 流量(GB), 連線 IP 數, CDN 佔比 %
    ("TW", "Taiwan", 31.8, 9.4, 46, 22.0), ("US", "United States", 14.2, 6.1, 31, 71.5), ("HK", "Hong Kong", 9.6, 2.8, 12, 48.0),
    ("JP", "Japan", 6.1, 3.3, 15, 35.0), ("SG", "Singapore", 4.4, 1.9, 9, 64.0), ("DE", "Germany", 2.2, 0.7, 6, 18.0),
    ("GB", "United Kingdom", 1.3, 0.5, 4, 12.0), ("NL", "Netherlands", 0.8, 0.9, 3, 9.0), ("KR", "South Korea", 0.6, 0.2, 3, 5.0),
    ("BR", "Brazil", 0.2, 0.05, 1, 0.0),
]
_EXPECTED = {"TW", "US", "JP", "SG", "HK", "IE", "DE", "NL", "GB"}
_ORGS = ["Example Cloud CDN", "Example Telecom", "Example Hosting", "Example Streaming", "Example SaaS Inc."]


def _doc_ip(seed: int) -> str:
    """產生文件保留位址(RFC 5737),不會對應到任何真實主機。"""
    r = random.Random(seed)
    return f"{r.choice(['203.0.113', '198.51.100', '192.0.2'])}.{r.randint(2, 250)}"


def threat_map(t: float) -> dict:
    hour = int(t // 3600)                        # 這份資料正式環境約每小時更新,所以一小時內不變

    def build(direction: str) -> list:
        col = 2 if direction == "in" else 3
        rows = []
        for i, c in enumerate(_COUNTRIES):
            gb = round(c[col] * (1 + 0.15 * random.Random(hour * 31 + i).uniform(-1, 1)), 3)
            rows.append({"iso": c[0], "name": c[1], "gb": gb, "ip_count": c[4],
                         "top_ips": [{"ip": _doc_ip(i * 10 + k), "org": _ORGS[(i + k) % len(_ORGS)], "gb": round(gb * w, 3)}
                                     for k, w in enumerate((0.42, 0.21, 0.09))],
                         "cdn_pct": c[5], "cdn_mostly": c[5] >= 60, "unexpected": c[0] not in _EXPECTED, "high_risk": False})
        total = sum(r["gb"] for r in rows) or 1.0
        for r in rows:
            r["pct"] = round(r["gb"] / total * 100, 2)
        rows.sort(key=lambda r: r["gb"], reverse=True)
        return rows

    return {"generated_at": _iso(hour * 3600 + 300), "timeframe": "hourly",
            "note": "只統計各線路 Top 連線中的外部公網 IP,不含未進入排行的小流量連線。(示範資料)",
            "in": build("in"), "out": build("out"), "unknown_gb": {"in": 0.12, "out": 0.03}}


# ══════════════════════════════════════════════════════════════════════
# 高風險 IP 命中
# ══════════════════════════════════════════════════════════════════════
def risk_hits(t: float) -> dict:
    hit = {
        "line": "5000095", "line_label": LINE_LABELS["5000095"], "peer_ip": "203.0.113.66", "iso": "NL", "country": "Netherlands",
        "match": "ip", "entry": "203.0.113.66", "note": "示範:清單上的可疑主機", "oversized": False,
        "port": "443", "protocol": "TCP", "app": "https", "local_ip": "203.0.113.10", "gb": 0.0312, "traffic": "31.9 MB",
        "nat": {"ip": "10.20.5.31", "confidence": "高",
                "candidates": [{"ip": "10.20.5.31", "similarity": 0.94, "f5_gb": 0.0301}, {"ip": "10.20.2.44", "similarity": 0.41, "f5_gb": 0.0102}]},
    }
    return {
        "generated_at": _iso(t - t % 300), "status": "ok", "timeframe": "hourly",
        "list_files": [{"name": "risk_ip_demo.txt", "mtime": _iso(t - t % 86400)}], "list_counts": {"ip": 128, "cidr": 14, "oversized": 2, "domain_ignored": 5, "invalid": 0},
        "lines_checked": 4, "lines_total": 4, "rows_checked": 400, "warnings": [],
        "hits": [hit], "alert_cidr": False, "cidr_hits": [], "oversized_hits": [],
        "note": "依外部對象 IP 與簽核系統清單比對(NetFlow 每小時彙總、只含 Top N 連線)。命中不等於一定中毒,請搭配防火牆紀錄確認。(示範資料)",
    }


# ══════════════════════════════════════════════════════════════════════
# Meraki 大樓無線 AP
# ══════════════════════════════════════════════════════════════════════
_meraki_base = None


def _load(name: str):
    with open(os.path.join(CANNED_DIR, name), "r", encoding="utf-8") as f:
        return json.load(f)


def meraki(t: float) -> dict:
    """以錄下來的基礎資料為底,只更新會變動的部分(時間、用戶數、趨勢)。"""
    global _meraki_base
    if _meraki_base is None:
        _meraki_base = _load("meraki_base.json")
    d = copy.deepcopy(_meraki_base)
    d["generated_at"] = _iso(t - t % 60)
    daytime = 0.55 + 0.45 * _wave(t, 86400, -0.25 - 0.375)       # 白天人多、半夜人少(以 UTC+8 的中午為高點)
    for fi, floor in enumerate(d["floors"]):
        total = 0
        for ai, ap in enumerate(floor["aps"]):
            if ap["status"] == "offline":
                ap["clients"] = 0
                continue
            base = 4 + (fi * 5 + ai * 3) % 14
            ap["clients"] = max(0, round(base * daytime + 1.5 * _jitter(t, fi * 100 + ai, 60)))
            total += ap["clients"]
            for al in ap.get("alerts") or []:                     # 告警開始時間:固定在「幾十分鐘前」
                al["since"] = _iso(t - 1500 - (ai * 700) % 5000)
        floor["clients"] = total
    d["warnings"] = []
    aps, online_now = d["totals"]["aps"], d["totals"]["online"]
    trend = []
    for i in range(96):                                           # 最近 24 小時、每 15 分鐘一點
        ts = t - (95 - i) * 900
        online = online_now + 2 if i < 60 else online_now + 1 if i < 88 else online_now
        trend.append({"t": _iso(ts), "online": online, "aps": aps})
    d["trend"] = trend
    return d


# ══════════════════════════════════════════════════════════════════════
# 組成 /api/summary(和 dashboard_server.py 的格式相同)
# ══════════════════════════════════════════════════════════════════════
def summary(now: float | None = None) -> dict:
    t = time.time() if now is None else now

    def src(data: dict, period: int) -> dict:
        # age_sec = 距離上次更新幾秒。模擬「每 period 秒更新一次」的輪詢程式。
        return {"available": True, "age_sec": int(t % period), "stale": False, "data": data}

    poll = t - t % 60          # 輪詢程式一分鐘跑一次,所以數字每分鐘才變
    return {
        "server_time": t, "topn_enabled": True, "demo": True,
        "netflow": src(netflow(poll), 60),
        "firewall": src(firewall(poll), 60),
        "availability": src(availability(poll), 60),
        "threat_map": src(threat_map(t), 3600),
        "risk_hits": src(risk_hits(t), 300),
        "meraki": src(meraki(t), 60),
    }


# ══════════════════════════════════════════════════════════════════════
# Top N、搜尋、診斷(使用者點擊時才會問)
# ══════════════════════════════════════════════════════════════════════
_APPS = [("https", "443", "TCP"), ("https", "443", "TCP"), ("quic", "443", "UDP"), ("https", "443", "TCP"), ("ssh", "22", "TCP"),
         ("smtp", "25", "TCP"), ("rtmp", "1935", "TCP"), ("https", "8443", "TCP"), ("dns", "53", "UDP"), ("ntp", "123", "UDP")]
_INSIDE_HOSTS = ["10.20.5.31", "10.20.3.21", "10.20.2.44", "10.20.7.18", "10.30.1.12", "10.30.1.15", "10.20.4.63", "10.20.6.90"]
_NAT_IP = {"5000095": "203.0.113.10", "5000107": "198.51.100.10", "5000097": "192.0.2.10", "5000108": "203.0.113.130"}


def topn(line_id: str, direction: str, rows: int = 10, now: float | None = None) -> dict:
    """某條線路某方向的 Top N 連線(含「NAT 前內部 IP 推算」)。"""
    if line_id not in LINE_LABELS:
        return {"error": {"message": "不認得這個線路 ID"}}
    t = time.time() if now is None else now
    hour = int(t // 3600)
    r = random.Random(hour * 100 + int(line_id) + (1 if direction == "in" else 2))
    nat_ip = _NAT_IP[line_id]
    shares = sorted((r.uniform(1.5, 22) for _ in range(rows)), reverse=True)
    scale = min(1.0, 86 / sum(shares))
    records = []
    for i, share in enumerate(shares):
        peer = _doc_ip(hour + int(line_id) * 13 + i * 7 + (0 if direction == "in" else 500))
        app, port, proto = _APPS[(i + int(line_id) % 3) % len(_APPS)]
        pct = round(share * scale, 2)
        gb = pct * 0.9
        inside = _INSIDE_HOSTS[(i * 3 + int(line_id)) % len(_INSIDE_HOSTS)]
        if i < 6:
            nat = {"ip": inside, "confidence": "高" if i < 3 else "中",
                   "candidates": [{"ip": inside, "similarity": round(0.97 - i * 0.07, 2), "f5_gb": round(gb * 0.96, 3)},
                                  {"ip": _INSIDE_HOSTS[(i * 3 + 1) % len(_INSIDE_HOSTS)], "similarity": round(0.4 - i * 0.03, 2), "f5_gb": round(gb * 0.3, 3)}]}
        elif i < 8:
            nat = {"ip": inside, "confidence": "低", "candidates": [{"ip": inside, "similarity": 0.52, "f5_gb": round(gb * 0.5, 3)},
                                                                     {"ip": _INSIDE_HOSTS[(i + 2) % len(_INSIDE_HOSTS)], "similarity": 0.49, "f5_gb": round(gb * 0.47, 3)}]}
        else:
            nat = {"ip": None, "confidence": "未推算", "reason": "這筆流量太小,或不在 NetFlow 前 100 筆連線內,無法推算"}
        records.append({
            "src": peer if direction == "in" else nat_ip, "dst": nat_ip if direction == "in" else peer,
            "port": port, "protocol": proto, "app": app,
            "traffic": f"{gb:.2f} GB" if gb >= 1 else f"{gb * 1024:.1f} MB", "pct": pct, "nat": nat,
        })
    start = datetime.fromtimestamp(hour * 3600).strftime("%Y-%m-%d %H:%M")
    end = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    return {"line_id": line_id, "line_label": LINE_LABELS[line_id], "direction": direction, "time_range": f"{start} ~ {end}",
            "total_bytes_readable": None, "records": records,
            "nat": {"status": "ok", "inside_age_sec": int(t % 300), "inside": [l[1] for l in INSIDE_LINES]}}


_find_all = None
_diag_all = None


def find(q: str, now: float | None = None) -> dict:
    """搜尋使用者 / 裝置 / MAC / IP 連在哪支 AP。示範資料只有 8 個虛構的用戶端。"""
    global _find_all
    if _find_all is None:
        _find_all = _load("find_all.json")
    t = time.time() if now is None else now
    q = (q or "").strip().lower()
    if not 3 <= len(q) <= 40:
        raise ValueError("bad query")
    hits = []
    for row in _find_all["results"]:
        text = " ".join(str(row.get(k) or "") for k in ("mac", "name", "user", "ip")).lower()
        if q in text or q.replace("-", ":") in text:
            row = dict(row)
            row["last_seen"] = t - (45 if row.get("online") else 5400)
            hits.append(row)
    return {"total": len(hits), "results": hits, "window_hours": _find_all.get("window_hours", 24)}


def diag(mac: str, hours: int, now: float | None = None) -> dict:
    """單一用戶端的連線品質診斷。示範資料有三種情境:訊號差、忽好忽壞、正常。"""
    global _diag_all
    t = time.time() if now is None else now
    if _diag_all is None:
        _diag_all = _load("diag.json")
    mac = (mac or "").strip().lower()
    if hours not in (1, 2, 4, 24) or len(mac) != 17:
        raise ValueError("bad parameter")
    profile = {"02:00:5e:10:00:01": "02:00:5e:10:00:01", "02:00:5e:10:00:08": "02:00:5e:10:00:01",     # 訊號差
               "02:00:5e:10:00:03": "02:00:5e:10:00:03"}.get(mac, "02:00:5e:10:00:02")                 # 忽好忽壞 / 其餘正常
    out = copy.deepcopy(_diag_all[f"{profile}|{hours}"])
    shift_times(out, t - captured_at(), captured_at())     # 圖表的時間軸平移到「現在」
    if profile != mac:                                    # 套用同一種情境,但顯示被查的那個人
        me = next((r for r in find(mac, t)["results"]), None)
        if me:
            out["client"].update({k: me.get(k) for k in ("mac", "name", "user", "ip", "ssid")})
            out["client"]["ap_serial"] = me.get("ap_serial")
            out["client"]["ap_name"] = (me.get("ap_name") or "").replace("HQ-AP-", "")
    return out


if __name__ == "__main__":
    s = summary()
    if "--json" in sys.argv:
        print(json.dumps(s, ensure_ascii=False, indent=1))
    else:
        for line in s["netflow"]["data"]["lines"][:4]:
            print(f"{line['label']:<24} IN {line['util_in_pct']:>3}%  OUT {line['util_out_pct']:>3}%  {line['level_in']}/{line['level_out']}")
        fw = s["firewall"]["data"]["firewalls"]
        print("防火牆:", ", ".join(f"{f['label']}({f['role']}) {f['metrics']['active_sessions']} sessions" for f in fw))
        print("AP:", s["meraki"]["data"]["totals"])
