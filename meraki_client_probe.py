# -*- coding: utf-8 -*-
"""Meraki 單一用戶「連線品質」資料探測(唯讀,只做 GET,不改任何設定、不寫入 Meraki)。

目的:在做「搜尋後顯示連線品質診斷」之前,先確認你們的 Meraki 組織裡,哪些「單一用戶」的品質資料
(訊號強度、連線失敗、延遲、漫遊事件、AP 通道使用率)真的拿得到、長什麼樣子。
這支程式放在 meraki_poll.py 同一個資料夾,用同一把已加密儲存的金鑰。

用法:
  python meraki_client_probe.py amylee            # 用使用者名稱 / 裝置名稱 / MAC / IP 找人(只取第一個符合的)
  python meraki_client_probe.py aa:bb:cc:11:22:33 --hours 4      # 看最近 4 小時(預設 2 小時,最多 24)
  python meraki_client_probe.py amylee --out probe.json          # 完整原始結果存到檔案(預設 meraki_client_probe.json)

輸出:每個端點一行「HTTP 狀態 + 摘要」。200 代表拿得到;404/403/400 代表你們的組織不提供或權限不足。
注意:結果檔裡有使用者的 MAC / IP / 名稱,是個人資料,請只在需要時使用,用完刪除,不要隨意外傳(要給我看請先遮蔽)。
"""
import argparse
import json
import sys
import time

import meraki_poll as mp


def short(obj, n=700):
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + " …"


def describe(data) -> str:
    if isinstance(data, list):
        keys = sorted(data[0].keys()) if data and isinstance(data[0], dict) else []
        return f"清單 {len(data)} 筆" + (f",欄位:{', '.join(keys)}" if keys else "")
    if isinstance(data, dict):
        return "物件,欄位:" + ", ".join(sorted(data.keys()))
    return type(data).__name__


def main():
    ap = argparse.ArgumentParser(description="Meraki 單一用戶連線品質資料探測(唯讀)")
    ap.add_argument("query", help="使用者名稱 / 裝置名稱 / MAC / IP(至少 3 個字)")
    ap.add_argument("--hours", type=float, default=2, help="看最近幾小時(預設 2,最多 24)")
    ap.add_argument("--out", default="meraki_client_probe.json", help="完整原始結果檔")
    a = ap.parse_args()
    span = int(max(0.25, min(24, a.hours)) * 3600)

    key = mp.load_key()
    if not key:
        sys.exit("找不到金鑰,請先執行  python meraki_poll.py --set-key")
    m = mp.Meraki(key)
    net = mp._resolve_network_id(m)

    # 1) 找人
    try:
        found = mp.find_clients(a.query)
    except ValueError:
        sys.exit("搜尋字串不正確(3~40 個字,只能用文字、數字、空白與 . : @ -)")
    if not found["results"]:
        sys.exit("找不到符合的用戶(只查最近 24 小時內有連線紀錄的)。")
    if found["total"] > 1:
        print(f"共 {found['total']} 筆符合,以下只探測第一筆(有 MAC 可以輸入完整 MAC 精準指定):")
        for r in found["results"][:5]:
            print(f"   {r['mac']}  {r['user'] or r['name'] or '-'}  {'在線' if r['online'] else '離線'}  AP={r['ap_name'] or r['ap_serial'] or '-'}")
    c = found["results"][0]
    mac, serial = c["mac"], c["ap_serial"]
    print(f"\n探測對象:{mac}({c['user'] or c['name'] or '-'}),最近連的 AP:{c['ap_name'] or serial or '-'},時間範圍 {span // 3600 if span >= 3600 else span // 60} {'小時' if span >= 3600 else '分鐘'}\n")

    now = int(time.time())
    tests = [
        ("用戶詳細資料", f"/networks/{net}/clients/{mac}", None),
        ("該用戶連線統計(關聯/驗證/DHCP/DNS 成功失敗次數)", f"/networks/{net}/wireless/clients/{mac}/connectionStats", {"timespan": span}),
        ("該用戶延遲統計", f"/networks/{net}/wireless/clients/{mac}/latencyStats", {"timespan": span}),
        ("該用戶延遲歷史", f"/networks/{net}/wireless/latencyHistory", {"clientId": mac, "timespan": span, "resolution": 300}),
        ("訊號品質歷史(RSSI / SNR)", f"/networks/{net}/wireless/signalQualityHistory", {"clientId": mac, "timespan": span, "resolution": 300}),
        ("連線事件(失敗在哪一步、漫遊到哪支 AP)", f"/networks/{net}/wireless/clients/{mac}/connectivityEvents", {"timespan": span, "perPage": 100}),
        ("失敗的連線", f"/networks/{net}/wireless/failedConnections", {"clientId": mac, "timespan": span}),
        ("網路事件記錄(關聯 / 斷線 / 漫遊)", f"/networks/{net}/events", {"productType": "wireless", "clientMac": mac, "perPage": 50}),
        ("通道使用率歷史(該用戶所在 AP)", f"/networks/{net}/wireless/channelUtilizationHistory", {"deviceSerial": serial, "timespan": span, "resolution": 600} if serial else "SKIP"),
        ("AP 型號 / 韌體(對照已知問題用)", f"/devices/{serial}", None if serial else "SKIP"),
        ("大樓所有用戶的延遲(用來比較「他比別人差多少」)", f"/networks/{net}/wireless/clients/latencyStats", {"timespan": span, "fields": "avg"}),
        ("大樓所有用戶的連線統計(同上)", f"/networks/{net}/wireless/clients/connectionStats", {"timespan": span}),
        ("所在 AP 的連線統計(同一支 AP 其他人是不是也有問題)", f"/networks/{net}/wireless/devices/connectionStats", {"timespan": span, "serial": serial} if serial else "SKIP"),
    ]
    raw = {}
    for title, path, params in tests:
        if params == "SKIP" or (params is None and "/devices/" in path and not serial):
            print(f"── {title}\n   略過(沒有 AP 序號)\n")
            continue
        try:
            r = m.get(path, params)
        except Exception as exc:  # noqa: BLE001
            print(f"── {title}\n   失敗:{type(exc).__name__}: {exc}\n")
            continue
        status = r.status_code
        if status != 200:
            msg = (r.text or "")[:140].replace("\n", " ")
            print(f"── {title}\n   HTTP {status}  {msg}\n   {path}\n")
            raw[title] = {"status": status, "text": r.text[:300]}
            continue
        try:
            data = r.json()
        except ValueError:
            data = r.text[:300]
        raw[title] = {"status": 200, "data": data}
        print(f"── {title}\n   HTTP 200  {describe(data)}\n   範例:{short(data[:2] if isinstance(data, list) else data)}\n")

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump({"client": c, "span_sec": span, "results": raw}, f, ensure_ascii=False, indent=1, default=str)
    ok = [t for t, v in raw.items() if v.get("status") == 200]
    print(f"完整結果已存到:{a.out}(含個人資料,用完請刪除)")
    print(f"可用的資料:{len(ok)} / {len(tests)} 項")


if __name__ == "__main__":
    main()
