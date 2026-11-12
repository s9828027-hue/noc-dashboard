"""
列出 NetFlow Analyzer 裡所有介面的「線路 ID」
================================================
用途:要把新的介面加進「線路使用率」,需要知道它在 NFA 的 ID(像 5000095 那種)。
     這支程式只做唯讀查詢,把每個介面的 ID、所屬設備、介面名稱、頻寬設定、目前使用率印出來。

使用前準備
----------
1. pip install requests
2. 設定環境變數 NFA_API_KEY(用 start_noc 啟動過的話,可以在同一個視窗直接執行,
   不然請先:$env:NFA_API_KEY = "你的APIKey")

用法
----
python list_nfa_interfaces.py                 # 列出全部介面
python list_nfa_interfaces.py Gi1/0/1     # 只列出名稱/設備含這個關鍵字的(不分大小寫)
python list_nfa_interfaces.py 10.0.2.253       # 看某台設備的介面
"""

import os
import sys

import requests
import urllib3

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
VERIFY_SSL = False
API_KEY = os.environ.get("NFA_API_KEY") or os.environ.get("OPM_API_KEY")

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit("找不到環境變數 NFA_API_KEY。請先設定:$env:NFA_API_KEY = \"你的APIKey\"")


def mbps(value) -> str:
    """頻寬欄位是 bps,換成 Mbps 方便閱讀。"""
    try:
        return f"{float(value) / 1_000_000:,.0f}"
    except (TypeError, ValueError):
        return "-"


def main() -> None:
    keyword = sys.argv[1].lower() if len(sys.argv) > 1 else ""
    resp = requests.get(
        f"{BASE_URL}/api/json/nfadevice/getIndexInterfaceData",
        params={"apiKey": API_KEY, "TimeFrame": "hourly", "DeviceID": -1},
        verify=VERIFY_SSL, timeout=30,
    )
    resp.raise_for_status()
    raw = resp.json()
    if "data" not in raw:
        sys.exit(f"回應裡沒有 data 欄位,原始內容:{raw}")

    rows = []
    for item in raw["data"]:
        text = f"{item.get('rName', '')} {item.get('Name', '')}".lower()
        if keyword and keyword not in text:
            continue
        rows.append(item)
    rows.sort(key=lambda i: (str(i.get("rName", "")), str(i.get("Name", ""))))

    print(f"{'線路ID':<10}{'設備':<28}{'介面':<16}{'IN頻寬Mbps':>11}{'OUT頻寬Mbps':>12}{'IN%':>6}{'OUT%':>6}")
    print("-" * 90)
    for i in rows:
        print(f"{str(i.get('ID')):<10}{str(i.get('rName', ''))[:26]:<28}{str(i.get('Name', ''))[:14]:<16}"
              f"{mbps(i.get('Speed')):>11}{mbps(i.get('outSpeed')):>12}{i.get('UtilIN', '-')!s:>6}{i.get('UtilOUT', '-')!s:>6}")
    print(f"\n共 {len(rows)} 個介面" + (f"(關鍵字:{sys.argv[1]})" if keyword else ""))


if __name__ == "__main__":
    main()
