<#
.SYNOPSIS
  NOC 大螢幕一鍵啟動:一次開好 3 支輪詢腳本 + 大螢幕資料伺服器,並用瀏覽器開啟畫面。

.DESCRIPTION
  會開 4 個 PowerShell 視窗(每個負責一支程式),每個視窗都有「自動重啟」:
  程式如果意外中斷,10 秒後自己重新啟動,不會再發生「資料停了 8 小時才發現」。
    1. netflow_poll_poc.py   線路使用率(同時累積一週基準資料)
    2. fw_health_poll.py    兩台防火牆健康度
    3. availability_poll.py 核心設備存活率
    4. dashboard_server.py  大螢幕資料伺服器(威脅地圖資料它會自己每 30 分鐘更新)

  API Key 怎麼處理(重要):
    - 第一次執行會問你 Key,輸入時畫面不會顯示,只放在記憶體裡傳給子程式。
    - 不會寫進任何腳本或視窗標題。
    - 加 -SaveKey 才會把 Key「用 Windows 帳號加密」存成 noc_apikey.dat,
      這個檔只有「同一個 Windows 使用者、同一台電腦」才解得開,複製到別台或別的帳號都沒用。
      這樣開機自動啟動才不用人工輸入。不想留在電腦上,執行 -ForgetKey 就刪掉。

.PARAMETER Kiosk
  用 Edge / Chrome 的全螢幕 Kiosk 模式開大螢幕(Alt+F4 關閉)。沒有指定就用預設瀏覽器開一般視窗。
.PARAMETER SaveKey
  把輸入的 API Key 加密存起來,之後不用再輸入。
.PARAMETER AskKey
  忽略已存的 Key 與環境變數,強制重新輸入(Key 換新時用)。
.PARAMETER ForgetKey
  刪除已存的加密 Key 檔。
.PARAMETER InstallAutoStart
  登入 Windows 時自動執行這支腳本(需要先用 -SaveKey 存過 Key)。
.PARAMETER RemoveAutoStart
  取消開機自動啟動。
.PARAMETER NoBrowser
  只啟動程式,不開瀏覽器。
.PARAMETER SkipKeyCheck
  跳過啟動前的 API Key 驗證(驗證本身出問題時的備用開關)。
.PARAMETER Port
  大螢幕網頁的埠號,預設 8080。

.EXAMPLE
  .\start_noc.ps1                       # 第一次:問 Key,開全部,開瀏覽器
  .\start_noc.ps1 -SaveKey -Kiosk       # 存 Key,並用全螢幕開
  .\start_noc.ps1 -InstallAutoStart     # 設成登入 Windows 自動啟動
#>
param(
    [switch]$Kiosk,
    [switch]$SaveKey,
    [switch]$AskKey,
    [switch]$ForgetKey,
    [switch]$InstallAutoStart,
    [switch]$RemoveAutoStart,
    [switch]$NoBrowser,
    [switch]$SkipKeyCheck,
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
$Dir = Split-Path -Parent $PSCommandPath
$KeyFile = Join-Path $Dir "noc_apikey.dat"
$TaskName = "NOC Dashboard"

# ── 要啟動的程式 ─────────────────────────────────────────────────────────
$Jobs = @(
    @{ Title = "NOC-線路使用率";   Script = "netflow_poll_poc.py";   Extra = "" },
    @{ Title = "NOC-防火牆健康度"; Script = "fw_health_poll.py";     Extra = "" },
    @{ Title = "NOC-核心設備存活"; Script = "availability_poll.py";  Extra = "" },
    @{ Title = "NOC-大螢幕伺服器"; Script = "dashboard_server.py";   Extra = "--port $Port" }
)

function ConvertTo-PlainText([System.Security.SecureString]$Secure) {
    # 相容 Windows PowerShell 5.1(它的 ConvertFrom-SecureString 沒有 -AsPlainText)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ── 只處理「設定」類的參數,處理完就結束 ────────────────────────────────
if ($ForgetKey) {
    if (Test-Path -LiteralPath $KeyFile) { Remove-Item -LiteralPath $KeyFile -Force; Write-Host "已刪除加密的 API Key 檔。" -ForegroundColor Green }
    else { Write-Host "本來就沒有存 Key。" }
    exit 0
}

if ($RemoveAutoStart) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Host "已取消開機自動啟動。" -ForegroundColor Green
    } catch { Write-Host "沒有找到自動啟動的工作(或沒有權限取消):$($_.Exception.Message)" -ForegroundColor Yellow }
    exit 0
}

if ($InstallAutoStart) {
    if (-not (Test-Path -LiteralPath $KeyFile)) {
        Write-Host "開機自動啟動時沒有人可以輸入 Key,請先執行一次:.\start_noc.ps1 -SaveKey" -ForegroundColor Yellow
        exit 1
    }
    try {
        $psExe = (Get-Command powershell.exe).Source
        $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Kiosk"
        $action = New-ScheduledTaskAction -Execute $psExe -Argument $arg -WorkingDirectory $Dir
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
            -Description "登入 Windows 時自動啟動 NOC 大螢幕" -Force | Out-Null
        Write-Host "已設定:每次登入 Windows($env:USERNAME)就會自動啟動大螢幕(全螢幕)。" -ForegroundColor Green
        Write-Host "取消請執行:.\start_noc.ps1 -RemoveAutoStart"
    } catch {
        Write-Host "設定失敗:$($_.Exception.Message)" -ForegroundColor Red
        Write-Host "可能需要用「系統管理員身分」開啟 PowerShell 再執行一次。"
        exit 1
    }
    exit 0
}

# ── 啟動前檢查 ───────────────────────────────────────────────────────────
Write-Host "NOC 大螢幕啟動中…" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "找不到 python,請確認已安裝並加入 PATH。" -ForegroundColor Red; exit 1
}
$missing = @()
foreach ($j in $Jobs) { if (-not (Test-Path -LiteralPath (Join-Path $Dir $j.Script))) { $missing += $j.Script } }
if (-not (Test-Path -LiteralPath (Join-Path $Dir "dashboard.html"))) { $missing += "dashboard.html" }
if ($missing.Count -gt 0) {
    Write-Host "缺少檔案(要跟這支腳本放同一個資料夾):$($missing -join ', ')" -ForegroundColor Red; exit 1
}

# ── 取得並驗證 API Key ───────────────────────────────────────────────────
$BaseUrl = if ($env:OPM_BASE_URL) { $env:OPM_BASE_URL } else { "https://opmanager.example.internal:8061" }   # OpManager 位址(可用環境變數 OPM_BASE_URL 指定)

function Test-ApiKey([string]$Key) {
    # 拿這把 Key 問 OpManager 一次,回傳 "ok"(可用)/ "invalid"(被拒絕)/ "unreachable"(連不到或無法驗證)
    $tmp = Join-Path $env:TEMP "noc_keycheck.py"
    $py = @'
import os, sys
try:
    import requests, urllib3
except ImportError:
    print("沒有安裝 requests,請先執行:pip install requests")
    sys.exit(4)
urllib3.disable_warnings()
# 用「輪詢腳本實際在用」的同一支 API(availability_poll.py 一樣的路徑與參數)來驗證
try:
    r = requests.get(os.environ["NOC_CHECK_URL"] + "/api/json/device/getDeviceSummary",
                     params={"apiKey": os.environ["NOC_CHECK_KEY"], "name": "10.0.0.254"},
                     verify=False, timeout=20)
    text = r.text
    data = r.json()
except Exception as exc:
    print("連線或解析失敗:%s" % exc)
    sys.exit(3)
err = data.get("error") if isinstance(data, dict) else None
if isinstance(err, dict) and err.get("code") == 5000:
    print("OpManager 回應:code=%s message=%s" % (err.get("code"), err.get("message")))
    sys.exit(2)
# 其他錯誤(例如 5009 找不到裝置名稱)代表 Key 本身是通過驗證的
sys.exit(0)
'@
    Set-Content -LiteralPath $tmp -Value $py -Encoding UTF8
    $env:NOC_CHECK_KEY = $Key
    $env:NOC_CHECK_URL = $BaseUrl
    $code = 3
    try {
        $out = & python $tmp 2>&1
        $code = $LASTEXITCODE
        if ($code -ne 0 -and $out) { Write-Host ("  驗證時的訊息:{0}" -f ($out -join " ")) -ForegroundColor Yellow }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        Remove-Item Env:\NOC_CHECK_KEY -ErrorAction SilentlyContinue
        Remove-Item Env:\NOC_CHECK_URL -ErrorAction SilentlyContinue
    }
    if ($code -eq 0) { return "ok" }
    if ($code -eq 2) { return "invalid" }
    return "unreachable"
}

# 順序:已加密存檔 → 目前環境變數 → 手動輸入。每一把都會先驗證,錯的不會傳給子程式,也不會被存起來。
$apiKey = $null
if (-not $AskKey) {
    if (Test-Path -LiteralPath $KeyFile) {
        try {
            $sec = (Get-Content -LiteralPath $KeyFile -Raw) | ConvertTo-SecureString
            $apiKey = ConvertTo-PlainText $sec
            Write-Host "找到已加密儲存的 API Key。"
        } catch {
            Write-Host "已存的 Key 無法解密(可能換了 Windows 帳號或電腦),請重新輸入。" -ForegroundColor Yellow
        }
    }
    if (-not $apiKey -and $env:NFA_API_KEY) { $apiKey = $env:NFA_API_KEY; Write-Host "使用目前視窗已設定的 NFA_API_KEY。" }
    if (-not $apiKey -and $env:OPM_API_KEY) { $apiKey = $env:OPM_API_KEY; Write-Host "使用目前視窗已設定的 OPM_API_KEY。" }
}

$attempts = 0
while ($true) {
    if ($apiKey) {
        $apiKey = $apiKey.Trim()       # 貼上時常會多一個空白或換行,這是最常見的「Key 明明是對的卻失敗」原因
        Write-Host ("正在驗證 API Key…(長度 {0} 個字元)" -f $apiKey.Length)
        if ($SkipKeyCheck) { $result = "ok"; Write-Host "已指定 -SkipKeyCheck,略過驗證。" -ForegroundColor Yellow }
        else { $result = Test-ApiKey $apiKey }
        if ($result -eq "ok") { Write-Host "API Key 驗證成功。" -ForegroundColor Green; break }
        if ($result -eq "unreachable") {
            Write-Host "連不到 OpManager($BaseUrl),無法驗證 Key,先照這把 Key 繼續啟動。" -ForegroundColor Yellow
            break
        }
        Write-Host "這把 API Key 被 OpManager 拒絕(Authentication failed),請確認有沒有複製完整、有沒有多餘字元。" -ForegroundColor Red
        $apiKey = $null
    }
    $attempts++
    if ($attempts -gt 3) { Write-Host "連續輸入 3 次都不正確,結束。請到 OpManager 確認 API Key 後再執行。" -ForegroundColor Red; exit 1 }
    $sec = Read-Host "請輸入 OpManager API Key(輸入時不會顯示)" -AsSecureString
    $apiKey = ConvertTo-PlainText $sec
    if ([string]::IsNullOrWhiteSpace($apiKey)) { $apiKey = $null; Write-Host "沒有輸入內容。" -ForegroundColor Yellow }
}

if ($SaveKey) {
    ConvertTo-SecureString $apiKey -AsPlainText -Force | ConvertFrom-SecureString | Set-Content -LiteralPath $KeyFile -Encoding ASCII
    Write-Host "已用 Windows 帳號加密儲存(只有這個帳號、這台電腦能解開)。" -ForegroundColor Green
}

# 只設在這個程序的環境變數,之後開的子視窗會繼承;不會寫進磁碟、也不會出現在視窗的命令列上
$env:NFA_API_KEY = $apiKey
$env:OPM_API_KEY = $apiKey

# ── 逐一啟動(已在跑的不重複開)────────────────────────────────────────
function Test-AlreadyRunning([string]$Script) {
    $procs = Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine -like "*$Script*" -and
        ($_.Name -match "python|powershell|pwsh")
    }
    return [bool]$procs
}

$DirEsc = $Dir.Replace("'", "''")
$windowStyle = "Normal"
if ($Kiosk) { $windowStyle = "Minimized" }   # 全螢幕模式下,輪詢視窗縮到工作列,不擋畫面

foreach ($j in $Jobs) {
    if (Test-AlreadyRunning $j.Script) {
        Write-Host ("  已在執行,略過:{0}" -f $j.Script) -ForegroundColor Yellow
        continue
    }
    # 視窗內的迴圈:程式結束(不管正常或當掉)10 秒後自動重啟。
    # $NOC_MANAGED 只是一個標記,讓 stop_noc.ps1 找得到這些視窗。
    $cmd = "`$NOC_MANAGED = '$($j.Script)'; `$Host.UI.RawUI.WindowTitle = '$($j.Title)'; " +
           "Set-Location -LiteralPath '$DirEsc'; " +
           "while (`$true) { python $($j.Script) $($j.Extra); Write-Host ''; " +
           "Write-Host '[$($j.Script) 已停止,10 秒後自動重新啟動。要完全停止請關閉這個視窗]' -ForegroundColor Yellow; " +
           "Start-Sleep -Seconds 10 }"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -NoExit -Command `"$cmd`"" -WindowStyle $windowStyle | Out-Null
    Write-Host ("  已啟動:{0}" -f $j.Script) -ForegroundColor Green
}

# ── 等伺服器起來,再開瀏覽器 ──────────────────────────────────────────────
$url = "http://127.0.0.1:$Port/"
$ready = $false
for ($i = 0; $i -lt 25; $i++) {
    try { Invoke-WebRequest -Uri "${url}api/summary" -UseBasicParsing -TimeoutSec 2 | Out-Null; $ready = $true; break }
    catch { Start-Sleep -Seconds 1 }
}
if (-not $ready) { Write-Host "伺服器 25 秒內沒有回應,請看「NOC-大螢幕伺服器」視窗有沒有錯誤訊息。" -ForegroundColor Yellow }

if (-not $NoBrowser) {
    if ($Kiosk) {
        $pf86 = ${env:ProgramFiles(x86)}
        $candidates = @(
            "$pf86\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "$pf86\Google\Chrome\Application\chrome.exe"
        )
        $browser = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
        if ($browser) {
            if ($browser -like "*msedge.exe") { Start-Process $browser -ArgumentList "--kiosk `"$url`" --edge-kiosk-type=fullscreen" }
            else { Start-Process $browser -ArgumentList "--kiosk `"$url`"" }
        } else {
            Write-Host "找不到 Edge 或 Chrome,改用預設瀏覽器開啟(請自己按 F11 全螢幕)。" -ForegroundColor Yellow
            Start-Process $url
        }
    } else {
        Start-Process $url
    }
}

Write-Host ""
Write-Host "完成。大螢幕網址:$url" -ForegroundColor Cyan
Write-Host "全部停止請執行:.\stop_noc.ps1(或雙擊 stop_noc.bat)"
