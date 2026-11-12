#!/usr/bin/env python3
"""
假的 Meraki Dashboard API(開發與測試用,資料全部是虛構的)
==========================================================
用途:沒有真的 Meraki 環境時,讓 meraki_poll.py 的「真實程式碼」有東西可以查,
     藉此測試樓層平面圖、AP 狀態、搜尋、連線品質診斷整條流程。
     demo/canned/ 裡的範例回應就是用這支假伺服器 + 真的 meraki_poll.py 產生的。

用法:
    python demo/fake_meraki_api.py 8199
    # 另一個視窗:
    set MERAKI_BASE_URL=http://127.0.0.1:8199/api/v1
    set MERAKI_API_KEY=demo-key
    set MERAKI_ORG_ID=000000
    python meraki_poll.py --dry

裡面的人名、裝置名稱、MAC、IP 都是編的:MAC 用「本機管理位址」(02: 開頭),IP 用 10.20.x.x。
"""
import http.server
import json
import random
import re
import sys
import time
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8199
ORG = "000000"
NET = "N_demo"
API_KEY = "demo-key"
NOW = int(time.time())
random.seed(11)

# ── 大樓:B1F 6 支 AP,1F~7F 各 12 支 ──
FLOORS = [("B1F", 6)] + [(f"{n:02d}F", 12) for n in range(1, 8)]
LAT0, LNG0, DLAT, DLNG = 25.0000, 121.0000, 0.0005, 0.0010      # 平面圖四個角的假座標


def ap_list():
    aps = []
    for fi, (floor, count) in enumerate(FLOORS):
        tag = floor.lstrip("0").replace("F", "") if floor != "B1F" else "B1"
        for k in range(count):
            col, row = k % 4, k // 4
            rows = (count + 3) // 4
            u = 0.14 + 0.72 * (col / 3)
            v = 0.2 + 0.6 * (row / max(1, rows - 1)) if rows > 1 else 0.5
            aps.append({
                "serial": f"Q2DM-{fi:02d}{k:02d}-DEMO", "name": f"HQ-AP-{tag}F-{k + 1:02d}", "floor": floor,
                "lat": LAT0 - DLAT * v, "lng": LNG0 + DLNG * u, "model": "CW9166I",
            })
    return aps


APS = ap_list()
BY_SERIAL = {a["serial"]: a for a in APS}


def serial_of(name):
    return next(a["serial"] for a in APS if a["name"] == name)


# 幾支狀態不正常的 AP(讓畫面有東西可以看)
STATUS = {serial_of("HQ-AP-6F-04"): "offline", serial_of("HQ-AP-3F-06"): "offline",
          serial_of("HQ-AP-4F-03"): "alerting", serial_of("HQ-AP-2F-02"): "dormant"}

# ── 用戶端(搜尋與診斷用) ──
CLIENTS = [
    # mac, 裝置名稱, 使用者, ip, 廠牌, AP, 狀態, 診斷情境
    ("02:00:5e:10:00:01", "ALICE-MBP", "alice.chen", "10.20.3.21", "Apple", "HQ-AP-3F-01", "Online", "bad"),
    ("02:00:5e:10:00:02", "Alice-iPhone", "alice.chen", "10.20.3.22", "Apple", "HQ-AP-3F-02", "Online", "good"),
    ("02:00:5e:10:00:03", "BOB-NB", "bob.lin", "10.20.5.31", "Lenovo", "HQ-AP-5F-07", "Online", "spiky"),
    ("02:00:5e:10:00:04", "CAROL-NB", "carol.wu", "10.20.2.44", "Dell", "HQ-AP-2F-05", "Online", "good"),
    ("02:00:5e:10:00:05", "dave-pixel", "dave.huang", "10.20.7.18", "Google", "HQ-AP-7F-09", "Offline", "good"),
    ("02:00:5e:10:00:06", "MEETING-ROOM-6A", None, "10.20.6.90", "Intel", "HQ-AP-6F-01", "Online", "good"),
    ("02:00:5e:10:00:07", "erin-ipad", "erin.tsai", "10.20.1.57", "Apple", "HQ-AP-1F-03", "Online", "good"),
    ("02:00:5e:10:00:08", "FRANK-NB", "frank.lee", "10.20.4.63", "HP", "HQ-AP-4F-03", "Online", "bad"),
]
SCENARIO = {c[0]: c[7] for c in CLIENTS}


def client_row(c):
    mac, desc, user, ip, vendor, ap, status, _ = c
    return {"mac": mac, "description": desc, "user": user, "ip": ip, "ssid": "Corp-WiFi", "status": status,
            "lastSeen": NOW - (60 if status == "Online" else 5400), "recentDeviceConnection": "Wireless",
            "recentDeviceSerial": serial_of(ap), "recentDeviceName": ap, "manufacturer": vendor,
            "os": "macOS" if vendor == "Apple" else "Windows 11", "wirelessCapabilities": "802.11ax - 2.4 and 5 GHz"}


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def plan(i, floor):
    devs = [{"name": a["name"], "serial": a["serial"], "lat": a["lat"], "lng": a["lng"], "productType": "wireless", "model": a["model"]}
            for a in APS if a["floor"] == floor]
    return {"floorPlanId": f"fp{i}", "name": floor, "floorNumber": None, "width": 60, "height": 36,
            "imageUrl": f"http://127.0.0.1:{PORT}/plan/{floor}.png", "imageMd5": f"demo{floor}", "imageExtension": "png",
            "topLeftCorner": {"lat": LAT0, "lng": LNG0}, "topRightCorner": {"lat": LAT0, "lng": LNG0 + DLNG},
            "bottomLeftCorner": {"lat": LAT0 - DLAT, "lng": LNG0}, "bottomRightCorner": {"lat": LAT0 - DLAT, "lng": LNG0 + DLNG},
            "devices": devs}


def conn_stats(a, i):
    """每支 AP 的連線統計。環境裡驗證失敗偏多是常態(成功率不高),所以數字故意不漂亮。"""
    if STATUS.get(a["serial"]) == "offline":
        return None
    succ = 40 + (i * 37) % 160
    auth = 30 + (i * 53) % 220
    if a["name"] == "HQ-AP-3F-01":        # 這支特別差,給診斷「AP 失敗率偏高」用
        succ, auth = 25, 420
    return {"serial": a["serial"], "connectionStats": {"assoc": (i * 7) % 9, "auth": auth, "dhcp": (i * 3) % 5, "dns": i % 2, "success": succ}}


STATIC = {
    f"/api/v1/organizations/{ORG}/networks": [{"id": NET, "name": "HQ"}, {"id": "N_other", "name": "Branch"}],
    f"/api/v1/networks/{NET}/floorPlans": [plan(i, f) for i, (f, _) in enumerate(FLOORS)],
    f"/api/v1/organizations/{ORG}/devices/statuses": [{"serial": a["serial"], "status": STATUS.get(a["serial"], "online"), "name": a["name"],
                                                         "productType": "wireless", "networkId": NET} for a in APS],
    f"/api/v1/networks/{NET}/wireless/devices/connectionStats": [s for s in (conn_stats(a, i) for i, a in enumerate(APS)) if s],
    f"/api/v1/organizations/{ORG}/assurance/alerts": [
        {"network": {"id": NET}, "title": "AP 離線", "severity": "critical", "startedAt": iso(NOW - 5400), "scope": {"devices": [{"serial": serial_of("HQ-AP-6F-04")}]}},
        {"network": {"id": NET}, "title": "AP 離線", "severity": "critical", "startedAt": iso(NOW - 1500), "scope": {"devices": [{"serial": serial_of("HQ-AP-3F-06")}]}},
        {"network": {"id": NET}, "title": "乙太網路連線速度降低", "severity": "warning", "startedAt": iso(NOW - 8200), "scope": {"devices": [{"serial": serial_of("HQ-AP-4F-03")}]}},
    ],
    f"/api/v1/networks/{NET}/clients": [client_row(c) for c in CLIENTS],
}


def history(kind, key, n=24):
    out = []
    for i in range(n):
        t0 = NOW - (n - i) * 300
        row = {"startTs": iso(t0), "endTs": iso(t0 + 300)}
        if key == "signal":
            if kind == "bad":
                rssi, snr = -80 + random.randint(-4, 4), 14 + random.randint(-3, 3)
            elif kind == "spiky":
                rssi, snr = -44 + random.randint(-2, 2), 50
            else:
                rssi, snr = -58 + random.randint(-4, 4), 38 + random.randint(-3, 3)
            if i % 7 == 0:
                rssi = snr = None
            row.update(rssi=rssi, snr=snr)
        else:
            v = (70 + random.randint(0, 90)) if kind == "bad" else (random.choice([5, 6, 80, 95]) if kind == "spiky" else 4 + random.random() * 3)
            row["avgLatencyMs"] = v if i % 9 else None
        out.append(row)
    return out


def dynamic(path, qs):
    """診斷會用到的端點。依 MAC 回傳「訊號差 / 忽好忽壞 / 正常」三種情境。"""
    m = re.match(rf"/api/v1/networks/{NET}/(.*)", path)
    dm = re.fullmatch(r"/api/v1/devices/([\w-]+)", path)
    if dm:
        return {"serial": dm.group(1), "model": "CW9166I", "firmware": "wireless-31-1-6"} if dm.group(1) in BY_SERIAL else None
    if not m:
        return None
    p = m.group(1)
    mac = (re.search(r"clients/([0-9a-f:]{17})", p) or [None, None])[1] or (qs.get("clientId") or [None])[0] or (qs.get("clientMac") or [None])[0]
    kind = SCENARIO.get(mac, "good")
    me = next((c for c in CLIENTS if c[0] == mac), CLIENTS[1])
    home = serial_of(me[5])
    floor_aps = [a["serial"] for a in APS if a["floor"] == BY_SERIAL[home]["floor"]]
    others = [s for s in floor_aps if s != home][:2] or [home]

    if p == "wireless/clients/latencyStats":       # 大樓其他用戶(比較基準)
        return [{"mac": "02:00:5e:20:00:%02x" % i, "latencyStats": {"bestEffortTraffic": {"avg": 5 + (i % 10) * 3 + (40 if i % 7 == 0 else 0)}}} for i in range(120)]
    if p == "wireless/clients/connectionStats":
        return [{"mac": "02:00:5e:20:00:%02x" % i, "connectionStats": {"assoc": i % 5, "auth": (i % 9) * 3, "dhcp": 0, "dns": 0, "success": 20}} for i in range(120)]
    if re.fullmatch(r"clients/[0-9a-f:]{17}", p):
        return client_row(me) if mac in SCENARIO else None
    if p.endswith("/connectionStats") and "clients/" in p:
        cs = {"assoc": 6, "auth": 14, "dhcp": 3, "dns": 0, "success": 20} if kind == "bad" else {"assoc": 0, "auth": 0, "dhcp": 0, "dns": 0, "success": 4 if kind == "spiky" else 40}
        return {"mac": mac, "connectionStats": cs}
    if p.endswith("/latencyStats"):
        dist = {"0": 10, "1": 20, "2": 30, "4": 40, "8": 30, "16": 20, "32": 10,
                "64": 30 if kind == "bad" else 12 if kind == "spiky" else 0, "128": 20 if kind == "bad" else 8 if kind == "spiky" else 0, "256": 10 if kind == "bad" else 0}
        return {"mac": mac, "latencyStats": {"bestEffortTraffic": {"rawDistribution": dist, "avg": 50 if kind == "bad" else 38 if kind == "spiky" else 5},
                                             "voiceTraffic": {"rawDistribution": dist, "avg": 9}}}
    if p == "wireless/latencyHistory":
        return history(kind, "latency")
    if p == "wireless/signalQualityHistory":
        return history(kind, "signal")
    if p.endswith("/connectivityEvents"):
        if kind == "spiky":
            seq = [home, others[0]] * 3 + [home]
            return [{"occurredAt": iso(NOW - 3000 + i * 300), "type": "assoc", "band": "5", "channel": 36, "rssi": 45, "deviceSerial": s, "durationMs": 300} for i, s in enumerate(seq)]
        if kind == "good":
            return [{"occurredAt": iso(NOW - 600), "type": "assoc", "band": "5", "channel": 36, "rssi": 38, "deviceSerial": home, "durationMs": 200}]
        seq = [home, others[0], home, others[0], home, others[-1], home, others[0]]
        return [{"occurredAt": iso(NOW - 3000 + i * 300), "type": "assoc" if i % 2 else "roam", "band": "2.4" if i % 3 else "5", "channel": 6, "rssi": 14,
                 "deviceSerial": s, "durationMs": 900} for i, s in enumerate(seq)]
    if p == "wireless/failedConnections":
        return []
    if p == "events":
        if kind == "bad":
            ev = [{"occurredAt": iso(NOW - 200 * i), "type": "disassociation", "description": "Client disassociated", "eventData": {"reason": "34" if i % 2 else "4"}, "deviceSerial": home} for i in range(6)]
        elif kind == "spiky":
            ev = [{"occurredAt": iso(NOW - 900 * i), "type": "disassociation", "description": "802.11 disassociation: unknown reason", "eventData": {"reason": "1"}, "deviceSerial": home} for i in range(4)]
        else:
            ev = []
        return {"pageStartAt": iso(NOW - 86400), "pageEndAt": iso(NOW), "events": ev}
    if p == "wireless/channelUtilizationHistory":
        if kind == "bad":
            return [{"startTs": iso(NOW - 600 * i), "endTs": iso(NOW - 600 * i + 600), "wifi0": {"utilizationTotal": 58 + i % 5}, "wifi1": {"utilizationTotal": 20}} for i in range(6)]
        return [{"startTs": iso(NOW - 600), "endTs": iso(NOW), "wifi0": {"utilizationTotal": 12}, "wifi1": {"utilizationTotal": 5}}]
    return None


def plan_png(floor):
    """畫一張簡單的樓層線稿(需要 Pillow;沒有的話回傳 1x1 的空白圖)。"""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        import base64
        return base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    import io
    rnd = random.Random(floor)
    w, h = 1500, 900
    im = Image.new("RGB", (w, h), "white")
    d = ImageDraw.Draw(im)
    d.rectangle([30, 30, w - 30, h - 30], outline="black", width=7)                 # 外牆
    cx0, cx1 = w * 0.42 + rnd.randint(-40, 40), w * 0.58 + rnd.randint(-40, 40)
    d.rectangle([cx0, h * 0.34, cx1, h * 0.66], outline="black", width=5)           # 中央核心(電梯、樓梯)
    d.line([cx0, h * 0.5, cx1, h * 0.5], fill="black", width=3)
    d.line([(cx0 + cx1) / 2, h * 0.34, (cx0 + cx1) / 2, h * 0.66], fill="black", width=3)
    step = rnd.choice([170, 190, 215])
    for x in range(30 + step, w - 60, step):                                        # 上下兩排隔間
        d.line([x, 30, x, h * 0.24], fill="black", width=4)
        d.line([x, h - 30, x, h * 0.76], fill="black", width=4)
    d.line([30, h * 0.24, w - 30, h * 0.24], fill="black", width=3)
    d.line([30, h * 0.76, w - 30, h * 0.76], fill="black", width=3)
    for y in (0.42, 0.58):                                                          # 左右兩側房間
        d.line([30, h * y, w * 0.3, h * y], fill="black", width=4)
        d.line([w * 0.7, h * y, w - 30, h * y], fill="black", width=4)
    for _ in range(26):                                                             # 桌椅之類的小方塊
        x, y = rnd.randint(70, w - 190), rnd.randint(int(h * 0.27), int(h * 0.7))
        if cx0 - 90 < x < cx1 + 10:
            continue
        d.rectangle([x, y, x + rnd.randint(40, 110), y + rnd.randint(26, 60)], outline="black", width=2)
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):       # 不印存取紀錄
        pass

    def do_GET(self):
        u = urlparse(self.path)
        pm = re.fullmatch(r"/plan/(\w+)\.png", u.path)
        if pm:
            body = plan_png(pm.group(1))
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        key = self.headers.get("X-Cisco-Meraki-API-Key") or (self.headers.get("Authorization") or "").replace("Bearer ", "")
        if key != API_KEY:
            self.send_response(401)
            self.end_headers()
            return
        data = STATIC.get(u.path)
        if data is None:
            data = dynamic(u.path, parse_qs(u.query))
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"假的 Meraki API 已啟動:http://127.0.0.1:{PORT}/api/v1  (API key = {API_KEY}, org = {ORG})")
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
