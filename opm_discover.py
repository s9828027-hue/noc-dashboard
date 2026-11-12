"""
OpManager 裝置與監控項目探測工具
=====================================
用途:幫「防火牆健康度」和「服務存活率」找資料源。
     1) 列出 OpManager 裡所有裝置(名稱、IP、類型),讓你確認 Palo Alto、
        VPN Gateway、DNS Server 等關鍵設備有沒有在監控清單裡。
     2) 針對指定裝置,抓出它身上掛的監控項目,並用關鍵字
        (session / cpu / memory / ping / response / packet / latency ...)
        篩出我們有興趣的那幾項。

這支腳本只做「唯讀查詢」,不會修改 OpManager 的任何設定。

使用前準備
----------
1. pip install requests
2. 設定環境變數 OPM_API_KEY(OpManager 的 REST API Key,不要寫死在程式碼裡):
   PowerShell:  $env:OPM_API_KEY = "你的APIKey"

用法
----
python opm_discover.py list                      # 列出全部裝置
python opm_discover.py list palo                 # 只列名稱/類型含 palo 的裝置
python opm_discover.py monitors <deviceName>     # 看某台裝置的監控項目(關鍵字篩選)
python opm_discover.py monitors <deviceName> all # 不篩選,全部印出

<deviceName> 請用 `list` 印出來的「deviceName」欄位值(不是顯示名稱)。
每次執行都會把原始 JSON 存成檔案(raw_*.json),方便你貼給我看結構。
"""

import json
import os
import sys

import requests
import urllib3

BASE_URL = os.environ.get("OPM_BASE_URL", "https://opmanager.example.internal:8061")   # OpManager / NetFlow Analyzer 位址(可用環境變數 OPM_BASE_URL 指定)
API_KEY = os.environ.get("OPM_API_KEY")
VERIFY_SSL = False  # 內部自簽憑證先關閉驗證

# 篩選監控項目用的關鍵字(不分大小寫)
KEYWORDS = [
    "session", "connection", "cpu", "memory", "ram", "ping", "response",
    "packet", "loss", "latency", "availability", "rtt", "port", "url",
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not API_KEY:
    sys.exit("找不到環境變數 OPM_API_KEY。請先設定:$env:OPM_API_KEY = \"你的APIKey\"")


def call_api(path: str, params: dict | None = None) -> dict:
    """打 OpManager REST API。apiKey 走 URL 參數(這台主機實測必須這樣)。"""
    query = {"apiKey": API_KEY}
    if params:
        query.update(params)
    resp = requests.get(
        f"{BASE_URL}/api/json/{path}", params=query,
        verify=VERIFY_SSL, timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def save_raw(name: str, data) -> str:
    path = os.path.join(SCRIPT_DIR, f"raw_{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def find_device_list(data):
    """回應格式我們沒看過完整版,所以用寬鬆方式找出「裝置清單」那個 list。"""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("devices", "data", "deviceList", "result"):
            if isinstance(data.get(key), list):
                return data[key]
        # 再往下找一層
        for value in data.values():
            found = find_device_list(value) if isinstance(value, (dict, list)) else None
            if found:
                return found
    return []


def cmd_list(keyword: str | None) -> None:
    data = call_api("v2/device/listDevices")
    raw_path = save_raw("listDevices", data)
    devices = find_device_list(data)

    if not devices:
        print(f"沒有解析到裝置清單,請把 {raw_path} 的內容貼給我看結構。")
        return

    print(f"共 {len(devices)} 台裝置(原始資料已存 {raw_path})\n")
    print(f"{'deviceName':<32}{'displayName':<28}{'IP':<18}{'類型':<20}")
    print("-" * 98)
    shown = 0
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        name = str(dev.get("deviceName", ""))
        display = str(dev.get("displayName", ""))
        ip = str(dev.get("ipaddress") or dev.get("ipAddress") or dev.get("ip") or "")
        dtype = str(dev.get("type") or dev.get("category") or dev.get("deviceType") or "")
        haystack = f"{name} {display} {ip} {dtype}".lower()
        if keyword and keyword.lower() not in haystack:
            continue
        print(f"{name:<32}{display:<28}{ip:<18}{dtype:<20}")
        shown += 1
    print(f"\n顯示 {shown} 台。")


def walk(node, matches: list, use_filter: bool) -> None:
    """遞迴走過 JSON,把含有關鍵字的項目(dict)收集起來。"""
    if isinstance(node, dict):
        text_values = [str(v) for v in node.values() if isinstance(v, (str, int, float))]
        joined = " ".join(text_values).lower()
        if text_values and (not use_filter or any(k in joined for k in KEYWORDS)):
            # 只收「葉節點」的 dict(裡面沒有再包 dict/list),避免重複印外層
            if not any(isinstance(v, (dict, list)) for v in node.values()):
                matches.append(node)
        for value in node.values():
            walk(value, matches, use_filter)
    elif isinstance(node, list):
        for item in node:
            walk(item, matches, use_filter)


def collect_values(node, out: list) -> None:
    """在某個監控項目底下,把所有出現的 'value' 欄位收集起來。"""
    if isinstance(node, dict):
        for key, val in node.items():
            if key.lower() == "value" and isinstance(val, (str, int, float)):
                out.append(val)
            elif isinstance(val, (dict, list)):
                collect_values(val, out)
    elif isinstance(node, list):
        for item in node:
            collect_values(item, out)


def summarize_monitors(data) -> list:
    """
    找出所有帶有 DISPLAYNAME 的監控項目定義,回傳 (名稱, policyName, 數值文字) 清單。
    上次的輸出顯示:數值(value)和名稱(DISPLAYNAME)是分開在不同的 dict 裡,
    所以這裡改成「以名稱那一層為單位,往下收集它底下的 value」。
    """
    results: list = []

    def visit(node):
        if isinstance(node, dict):
            keys_lower = {k.lower(): k for k in node.keys()}
            if "displayname" in keys_lower:
                name = str(node[keys_lower["displayname"]])
                policy = str(node.get(keys_lower.get("policyname", ""), ""))
                values: list = []
                collect_values(node, values)
                text = ", ".join(str(v) for v in values[:4]) if values else "(無數值,可能需另外查詢)"
                results.append((name, policy, text))
            for val in node.values():
                visit(val)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(data)
    return results


def candidate_names(user_input: str) -> list:
    """
    你輸入的可能是顯示名稱、deviceName 或 IP,而 API 只認其中一種。
    這裡先去 listDevices 找出對應的那台裝置,再把它所有可能的名稱
    (deviceName、IP、displayName)依序排成候選清單,後面逐一嘗試。
    """
    candidates = [user_input]
    try:
        devices = find_device_list(call_api("v2/device/listDevices"))
    except requests.exceptions.RequestException:
        return candidates

    target = user_input.lower()
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        name = str(dev.get("deviceName", ""))
        display = str(dev.get("displayName", ""))
        ip = str(dev.get("ipaddress") or dev.get("ipAddress") or dev.get("ip") or "")
        if target in (name.lower(), display.lower(), ip.lower()):
            for value in (name, ip, display):
                if value and value not in candidates:
                    candidates.append(value)
            break
    return candidates


def cmd_monitors(device_name: str, show_all: bool) -> None:
    data = None
    for candidate in candidate_names(device_name):
        result = call_api("device/getAssociatedMonitors", {"name": candidate})
        if isinstance(result, dict) and result.get("error", {}).get("code") == 5009:
            print(f"  名稱「{candidate}」API 不接受,換下一個候選名稱...")
            continue
        data = result
        device_name = candidate
        break

    if data is None:
        print("[錯誤] 所有候選名稱都被 API 拒絕。請先執行 `python opm_discover.py list`,")
        print("       確認裝置真的在 OpManager 清單裡,並把該裝置那一行貼給我。")
        return

    raw_path = save_raw(f"monitors_{device_name.replace('/', '_')}", data)

    if isinstance(data, dict) and "error" in data:
        print(f"[錯誤] {data['error']}")
        return

    # 先用「監控項目名稱 + 數值」的方式整理(較易讀)
    summary = summarize_monitors(data)
    if summary:
        print(f"裝置 {device_name}:共 {len(summary)} 個監控項目(原始資料 {raw_path})\n")
        print(f"{'監控項目(DISPLAYNAME)':<44}{'policyName':<28}目前值")
        print("-" * 96)
        for name, policy, values in summary:
            if not show_all and not any(k in f"{name} {policy}".lower() for k in KEYWORDS):
                continue
            print(f"{name:<44}{policy:<28}{values}")
        print("\n(預設只顯示名稱含 cpu/session/memory/ping 等關鍵字的項目;加 `all` 顯示全部)")
        return

    # 找不到「DISPLAYNAME」結構時,退回原本的通用列印方式
    matches: list = []
    walk(data, matches, use_filter=not show_all)

    print(f"裝置 {device_name}:找到 {len(matches)} 筆符合的監控項目(原始資料 {raw_path})\n")
    for item in matches:
        line = json.dumps(item, ensure_ascii=False)
        print(line[:300] + ("..." if len(line) > 300 else ""))

    if not matches:
        print("沒有符合關鍵字的項目。可以加 `all` 看全部,或把原始 JSON 貼給我。")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)

    command = sys.argv[1].lower()
    if command == "list":
        cmd_list(sys.argv[2] if len(sys.argv) > 2 else None)
    elif command == "call":
        # 通用唯讀查詢:python opm_discover.py call <API路徑> [key=value ...]
        # 例:python opm_discover.py call device/getDeviceSummary name=10.0.0.252
        if len(sys.argv) < 3:
            sys.exit("用法:python opm_discover.py call <API路徑> [key=value ...]")
        extra = dict(arg.split("=", 1) for arg in sys.argv[3:] if "=" in arg)
        result = call_api(sys.argv[2], extra)
        raw_path = save_raw("call_" + sys.argv[2].replace("/", "_"), result)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        print(text[:3000] + ("\n...(已截斷,完整內容見 " + raw_path + ")" if len(text) > 3000 else ""))
    elif command == "monitors":
        if len(sys.argv) < 3:
            sys.exit("用法:python opm_discover.py monitors <deviceName> [all]")
        cmd_monitors(sys.argv[2], show_all=(len(sys.argv) > 3 and sys.argv[3] == "all"))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
