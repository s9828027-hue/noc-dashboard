"""
NAT 前內部 IP 推算(Top N 視窗會顯示;背景也會定期寫 nat_map.json)
==================================================
用途:WAN 線路的 Top N 連線裡,我方這一端永遠是 F5 對外做完 NAT 的公網 IP
     (例如 203.0.113.10),看不出是哪台內部主機。
     F5 內網端口(F5-內網-1 / F5-內網-2)位於 NAT 之前,看到的是真正的內部 IP。
     這支程式把兩邊「對得起來」的連線配對,推算每個 NAT 公網 IP 背後可能是哪些內部 IP。

推算方法(白話)
--------------
1. 抓 WAN 線路的 Top 連線:每筆都有「外部對象 IP(peer)」和「我方 NAT IP」。
2. 抓 F5 內網端口的 Top 連線:每筆是「外部對象 IP(peer)」和「內部 IP」。
3. 用「外部對象 IP」當鑰匙配對:同一個外部對象,在 WAN 看到的連線,
   會在 F5 內側看到同一個對象連到某個內部 IP。
4. 比對「同方向的流量大小」:越接近,越可能是同一條連線,可信度越高。

重要限制(請務必知道)
--------------------
- 這是「推算」,不是精確對應。NetFlow 沒有「同一筆連線 NAT 前後」的紀錄。
- 只看得到 Top N 連線(預設每個查詢 100 筆):流量小的連線兩邊可能對不上。
- 同一個外部對象同時連到好幾個內部 IP 時,只能靠流量大小猜,會標成「低」可信度。
- NetFlow Analyzer 最細只有「每小時」彙總,時間無法更精確。
可信度:高 = 只有一個候選且流量接近;中 = 候選唯一但流量差異較大,或有多個候選但其中一個明顯最接近;
        低 = 多個候選都差不多,請對照 F5 連線紀錄確認。

使用前準備
----------
1. pip install requests
2. 設定環境變數 NFA_API_KEY(同其他腳本;用 start_noc 啟動時會自動帶入)

用法
----
python nat_infer.py            # 抓資料、推算、寫出 nat_map.json,並在畫面印出摘要
python nat_infer.py --quiet    # 只寫檔,不印摘要(給 dashboard_server 背景執行用)

dashboard_server.py 會每 30 分鐘自動執行一次這支程式(寫 nat_map.json)。
另外,大螢幕點開某條線路的 Top N 時,dashboard_server 會「即時」呼叫 enrich_topn() 推算畫面上那 10 筆,
並在「NAT 端 IP」下方顯示「↳ 內部 IP(推算)」與可信度。這樣剛發生的告警連線也看得到,不用等 30 分鐘。
"""

import ipaddress
import json
import os
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
VERIFY_SSL = False
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "nat_map.json")

TIMEFRAME = "hourly"
ROWS_PRIMARY = 100     # 每個線路、每個方向抓幾筆連線;越多越容易配對,但 API 越慢
ROWS_FALLBACK = 50     # 如果 NFA 不接受上面的筆數,退回這個

# 對外 WAN 線路(我方端是 NAT 後的公網 IP)
WAN_LINES = {
    "5000095": "ISP-A 主線 1G/600M",
    "5000107": "ISP-B 備援 1G/600M",
    "5000097": "ISP-C 專線 300M/300M",
    "5000108": "ISP-D 網際網路 1G/600M(Edge-FW WAN2)",
}
# F5 內網端口(NAT 前,看得到真正的內部 IP)
F5_LINES = {
    "5000105": "F5-內網-1",
    "5000106": "F5-內網-2",
}

# 預設每條 WAN 線路都用上面 F5_LINES(F5 內網端口)當「NAT 前」的觀察點。
# 如果某條 WAN 的 NAT 不是 F5 做的(例如 Edge-FW WAN2 是 Fortigate 自己做 NAT),
# 請在這裡指定「那台設備內側介面」的 NFA 介面 ID(用 list_nfa_interfaces.py 查),例如:
#   INSIDE_BY_WAN = {"5000108": {"5000xxx": "Edge-FW-LAN"}}
# 沒指定的線路一律用 F5_LINES。
INSIDE_BY_WAN = {}

INSIDE_CACHE_SEC = 300    # 內側連線資料快取幾秒:Top N 視窗開啟時不用每次重抓

MIN_GB_TO_REPORT = 0.01   # WAN 連線小於這個流量(GB)就不推算,避免雜訊
HIGH_SIMILARITY = 0.7     # 流量接近程度(0~1)達到這個才算「接近」
CLEAR_WINNER_GAP = 0.25   # 多個候選時,最佳者要領先第二名這麼多才算「明顯最接近」

_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
_SIZE_PATTERN = re.compile(r"([\d.]+)\s*([A-Za-z]+)")


def parse_size_to_bytes(text) -> float:
    """'15.075 GB' -> bytes"""
    m = _SIZE_PATTERN.match(str(text or "").strip())
    if not m:
        return 0.0
    value, unit = m.groups()
    return float(value) * _SIZE_UNITS.get(unit.upper(), 1)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def similarity(a: float, b: float) -> float:
    """兩個流量有多接近:1 = 一樣,越小差越多。"""
    if a <= 0 or b <= 0:
        return 0.0
    return min(a, b) / max(a, b)


# ─────────────────────────── 純運算(不需要連網,可單獨測試) ───────────────────────────
def build_wan_flows(wan_records: dict) -> list:
    """
    wan_records: {(line_id, 'in'|'out'): [conv 紀錄...]}
    回傳統一格式的 WAN 連線:{line, dir, peer, nat_ip, port, protocol, app, bytes}
    IN  = 外部對象 -> 我方(src 是 peer、dst 是 NAT IP)
    OUT = 我方 -> 外部對象(src 是 NAT IP、dst 是 peer)
    我方端若不是公網 IP(例如已經是內部 IP),代表沒有做 NAT,不需要推算,直接略過。
    """
    flows = []
    for (line, direction), rows in wan_records.items():
        for r in rows:
            src, dst = r.get("src"), r.get("dst")
            peer, local = (src, dst) if direction == "in" else (dst, src)
            if not (peer and local and is_public(peer) and is_public(local)):
                continue
            flows.append({
                "line": line, "dir": direction, "peer": peer, "nat_ip": local,
                "port": r.get("dstport") or r.get("port"), "protocol": r.get("prot"), "app": r.get("app"),
                "bytes": parse_size_to_bytes(r.get("traffic")),
            })
    return flows


def build_f5_index(f5_records: dict) -> dict:
    """
    把 F5 內側的連線整理成:index[(peer_ip, 邏輯方向)] -> {internal_ip: {"bytes": 總流量, "lines": {線路ID}, "port": 埠}}
    邏輯方向:inbound = 外部 -> 內部(src 是 peer);outbound = 內部 -> 外部(src 是內部)。
    這樣不管 NFA 在端口上叫它 IN 還是 OUT,都能跟 WAN 的同方向流量比對。
    """
    index = defaultdict(lambda: defaultdict(lambda: {"bytes": 0.0, "lines": set(), "ports": set()}))
    for (line, _direction), rows in f5_records.items():
        for r in rows:
            src, dst = r.get("src"), r.get("dst")
            if not (src and dst):
                continue
            if is_private(src) and is_public(dst):
                internal, peer, logical = src, dst, "outbound"
            elif is_private(dst) and is_public(src):
                internal, peer, logical = dst, src, "inbound"
            else:
                continue
            slot = index[(peer, logical)][internal]
            slot["bytes"] += parse_size_to_bytes(r.get("traffic"))
            slot["lines"].add(line)
            port = r.get("dstport") or r.get("port")
            if port:
                slot["ports"].add(str(port))
    return index


def judge(candidates: list) -> tuple:
    """依候選清單(已依接近程度由高到低排序)決定最佳推測與可信度。"""
    if not candidates:
        return None, "無法配對"
    best = candidates[0]
    if len(candidates) == 1:
        return best["internal_ip"], "高" if best["similarity"] >= HIGH_SIMILARITY else "中"
    gap = best["similarity"] - candidates[1]["similarity"]
    if best["similarity"] >= HIGH_SIMILARITY and gap >= CLEAR_WINNER_GAP:
        return best["internal_ip"], "中"
    return best["internal_ip"], "低"


def infer_mappings(wan_flows: list, f5_index: dict) -> tuple:
    """逐筆 WAN 連線去內側索引找候選,回傳 (mappings, 無法配對筆數, 無法配對流量 bytes)。"""
    mappings, unmatched_bytes, unmatched_count = [], 0.0, 0
    for f in wan_flows:
        if f["bytes"] < MIN_GB_TO_REPORT * 1024 ** 3:
            continue
        logical = "inbound" if f["dir"] == "in" else "outbound"
        found = f5_index.get((f["peer"], logical), {})
        cands = []
        for ip, slot in found.items():
            cands.append({
                "internal_ip": ip,
                "f5_gb": round(slot["bytes"] / 1024 ** 3, 3),
                "similarity": round(similarity(f["bytes"], slot["bytes"]), 2),
                "port_match": bool(f["port"]) and str(f["port"]) in slot["ports"],
                "f5_lines": sorted(slot["lines"]),
            })
        # 流量越接近越前面;接近程度一樣時,埠號對得上的優先
        cands.sort(key=lambda c: (c["similarity"], c["port_match"], c["f5_gb"]), reverse=True)
        best, confidence = judge(cands)
        if not cands:
            unmatched_count += 1
            unmatched_bytes += f["bytes"]
        mappings.append({
            "wan_line": f["line"], "wan_label": WAN_LINES.get(f["line"], f["line"]), "direction": f["dir"],
            "peer_ip": f["peer"], "nat_ip": f["nat_ip"], "port": f["port"], "protocol": f["protocol"], "app": f["app"],
            "wan_gb": round(f["bytes"] / 1024 ** 3, 3),
            "best_internal_ip": best, "confidence": confidence, "candidates": cands[:5],
        })
    mappings.sort(key=lambda m: m["wan_gb"], reverse=True)
    return mappings, unmatched_count, unmatched_bytes


def summarize_result(mappings: list, unmatched_count: int, unmatched_bytes: float) -> dict:
    mappings = sorted(mappings, key=lambda m: m["wan_gb"], reverse=True)
    # 依 NAT IP 彙整:每個公網 IP 背後,各內部 IP 累積了多少「被最佳推測選中」的流量
    per_nat = defaultdict(lambda: defaultdict(lambda: {"gb": 0.0, "peers": 0}))
    for m in mappings:
        if m["best_internal_ip"]:
            slot = per_nat[m["nat_ip"]][m["best_internal_ip"]]
            slot["gb"] += m["wan_gb"]; slot["peers"] += 1
    summary = [{
        "nat_ip": nat,
        "internal_ips": sorted(({"ip": ip, "gb": round(v["gb"], 3), "matched_peers": v["peers"]} for ip, v in ips.items()),
                               key=lambda x: x["gb"], reverse=True)[:10],
    } for nat, ips in per_nat.items()]
    summary.sort(key=lambda s: sum(i["gb"] for i in s["internal_ips"]), reverse=True)

    return {
        "mappings": mappings, "nat_ip_summary": summary,
        "unmatched_count": unmatched_count, "unmatched_gb": round(unmatched_bytes / 1024 ** 3, 3),
    }


def infer(wan_flows: list, f5_index: dict) -> dict:
    """單一內側索引的簡易版(測試用)。正式流程見 build_all_result():每條 WAN 可用不同的內側觀察點。"""
    return summarize_result(*infer_mappings(wan_flows, f5_index))


# ─────────────────────────── 連網抓資料 ───────────────────────────
def fetch_conversations(session, api_key: str, line_id: str, direction: str) -> list:
    """打 NFA getConvData;筆數太大被拒絕時,自動退回較小的筆數。"""
    last_err = None
    for rows in (ROWS_PRIMARY, ROWS_FALLBACK):
        params = {"apiKey": api_key, "DeviceID": line_id, "rows": rows, "TimeFrame": TIMEFRAME,
                  "pageCount": 1, "tablegridviewtype": "Grid", "Data": direction.upper()}
        resp = session.get(f"{BASE_URL}/api/json/nfadevice/getConvData", params=params, verify=VERIFY_SSL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict) and "error" in data:
            last_err = data["error"]
            continue
        return data.get("Data", [])
    print(f"  [警告] {line_id}/{direction} 查詢失敗:{last_err}")
    return []


def inside_for(wan_line: str) -> dict:
    """這條 WAN 的 NAT 前觀察點:有在 INSIDE_BY_WAN 指定就用指定的,否則用 F5_LINES。"""
    return INSIDE_BY_WAN.get(wan_line) or F5_LINES


def _fetch_one(api_key: str, line_id: str, direction: str) -> list:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    with requests.Session() as session:      # 每個查詢各用一個連線,多執行緒才安全
        return fetch_conversations(session, api_key, line_id, direction)


def _fetch_many(api_key: str, jobs: list) -> dict:
    """同時查多個 (線路ID, 方向),回傳 {(線路ID, 方向): 連線列表}。NFA 回應慢,所以平行查。"""
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(lambda j: _fetch_one(api_key, j[0], j[1]), jobs))
    return dict(zip(jobs, results))


def collect(api_key: str) -> tuple:
    """回傳 (WAN 連線, 內側連線)。內側 = 所有 WAN 用到的觀察點聯集。"""
    inside_ids = sorted({i for line in WAN_LINES for i in inside_for(line)})
    wan = _fetch_many(api_key, [(l, d) for l in WAN_LINES for d in ("in", "out")])
    inside = _fetch_many(api_key, [(i, d) for i in inside_ids for d in ("in", "out")])
    return wan, inside


def build_all_result(wan_records: dict, inside_records: dict) -> dict:
    """每條 WAN 用自己的內側觀察點推算,最後合併成同一份結果。"""
    wan_flows = build_wan_flows(wan_records)
    mappings, unmatched_count, unmatched_bytes = [], 0, 0.0
    for line in WAN_LINES:
        ids = set(inside_for(line))
        index = build_f5_index({k: v for k, v in inside_records.items() if k[0] in ids})
        m, c, b = infer_mappings([f for f in wan_flows if f["line"] == line], index)
        mappings += m; unmatched_count += c; unmatched_bytes += b
    return summarize_result(mappings, unmatched_count, unmatched_bytes)


# ─────────────────────────── 即時推算(給大螢幕 Top N 視窗用) ───────────────────────────
_inside_cache: dict = {}            # tuple(內側ID) -> (抓取時間, 索引)
_inside_lock = threading.Lock()


def get_inside_index(api_key: str, wan_line: str) -> tuple:
    """取得這條 WAN 的內側索引(快取 INSIDE_CACHE_SEC 秒)。回傳 (索引, 資料幾秒前抓的)。"""
    ids = tuple(sorted(inside_for(wan_line)))
    with _inside_lock:       # 同時間多人開視窗時,只有一個人去抓,其他人等它抓完直接用快取
        hit = _inside_cache.get(ids)
        now = time.time()
        if hit and now - hit[0] < INSIDE_CACHE_SEC:
            return hit[1], int(now - hit[0])
        records = _fetch_many(api_key, [(i, d) for i in ids for d in ("in", "out")])
        index = build_f5_index(records)
        if any(records.values()):          # 全部查不到(例如 API 暫時錯誤)就不快取,下次再試
            _inside_cache[ids] = (now, index)
        return index, 0


def enrich_topn(result: dict, api_key: str, wan_rows: list = None) -> None:
    """
    替 fetch_topn.build_records() 的結果補上「NAT 前內部 IP(推算)」。
    每筆 record 會多一個 "nat" 欄位:
      None                                    -> 這筆不需要推算(我方端本來就是內部 IP,或對象不是公網)
      {"ip": "10.x", "confidence": "高/中/低", "candidates": [...]}   -> 有推算結果
      {"ip": None, "confidence": "無法配對"/"未推算", "reason": "..."}   -> 沒找到
    整體狀態放在 result["nat"] = {"status": "ok" / "not_applicable" / "error", ...}。
    """
    line, direction = str(result.get("line_id")), result.get("direction")
    if line not in WAN_LINES:
        result["nat"] = {"status": "not_applicable"}
        return
    index, age = get_inside_index(api_key, line)
    if wan_rows is None:
        wan_rows = _fetch_one(api_key, line, direction)   # 這條線路、這個方向的前 100 筆(Top N 畫面只顯示前 10 筆)
    mappings, _, _ = infer_mappings(build_wan_flows({(line, direction): wan_rows}), index)

    lookup = {}
    for m in mappings:      # mappings 已依流量由大到小排序,同一組合只留最大的那筆
        lookup.setdefault((m["peer_ip"], m["nat_ip"], str(m["port"])), m)
        lookup.setdefault((m["peer_ip"], m["nat_ip"], None), m)

    for r in result.get("records", []):
        src, dst = r.get("src"), r.get("dst")
        peer, local = (src, dst) if direction == "in" else (dst, src)
        if not (peer and local and is_public(peer) and is_public(local)):
            r["nat"] = None
            continue
        m = lookup.get((peer, local, str(r.get("port")))) or lookup.get((peer, local, None))
        if not m:
            r["nat"] = {"ip": None, "confidence": "未推算",
                        "reason": "這筆流量太小,或不在 NetFlow 前 100 筆連線內,無法推算"}
            continue
        r["nat"] = {
            "ip": m["best_internal_ip"], "confidence": m["confidence"],
            "candidates": [{"ip": c["internal_ip"], "similarity": c["similarity"], "f5_gb": c["f5_gb"]} for c in m["candidates"][:3]],
        }
        if not m["best_internal_ip"]:
            r["nat"]["reason"] = "內側觀察點(F5 內網端口)沒有看到同一個外部對象的連線"
    result["nat"] = {"status": "ok", "inside_age_sec": age, "inside": sorted(inside_for(line).values())}


def print_summary(result: dict, quiet: bool) -> None:
    if quiet:
        return
    maps = result["mappings"]
    print(f"\n共 {len(maps)} 筆 WAN 連線做了推算;無法配對 {result['unmatched_count']} 筆({result['unmatched_gb']} GB)。")
    print("\n【各 NAT 公網 IP 背後可能的內部 IP】(依累積流量排序)")
    for s in result["nat_ip_summary"][:5]:
        print(f"  {s['nat_ip']}")
        for i in s["internal_ips"][:5]:
            print(f"      {i['ip']:<16} {i['gb']:>8.2f} GB  (配對到 {i['matched_peers']} 個外部對象)")
    print("\n【流量最大的前 15 筆 WAN 連線】")
    print(f"  {'線路':<24}{'方向':<5}{'外部對象':<17}{'NAT IP':<17}{'最佳推測內部 IP':<17}{'可信度':<8}{'GB':>8}")
    for m in maps[:15]:
        print(f"  {m['wan_label'][:22]:<24}{m['direction'].upper():<5}{m['peer_ip']:<17}{m['nat_ip']:<17}"
              f"{(m['best_internal_ip'] or '-'):<17}{m['confidence']:<8}{m['wan_gb']:>8.2f}")
    print("\n提醒:這是依「外部對象 IP + 流量大小」推算,可信度「低」的請對照 F5 連線紀錄確認。")


def main() -> None:
    quiet = "--quiet" in sys.argv
    api_key = os.environ.get("NFA_API_KEY") or os.environ.get("OPM_API_KEY")
    if not api_key:
        sys.exit("找不到環境變數 NFA_API_KEY。請先設定:$env:NFA_API_KEY = \"你的APIKey\"")

    wan_records, inside_records = collect(api_key)
    result = build_all_result(wan_records, inside_records)
    result.update({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "timeframe": TIMEFRAME,
        "rows_per_query": ROWS_PRIMARY,
        "note": "推算結果,非精確對應:依外部對象 IP 與同方向流量大小配對。可信度低者請對照 F5 連線紀錄。",
    })
    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    os.replace(tmp, OUTPUT_FILE)   # 先寫暫存檔再取代,避免大螢幕剛好讀到寫一半的檔案
    if not quiet:
        print(f"已寫出:{OUTPUT_FILE}")
    print_summary(result, quiet)


if __name__ == "__main__":
    main()
