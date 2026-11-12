<#
.SYNOPSIS
  把 NOC 大螢幕程式註冊成「開機自動執行」的 Windows 工作排程(伺服器用,不需要有人登入)。

.DESCRIPTION
  兩種角色:
    -Role Collector   裝在 DB server(內網):netflow_poll_poc.py、fw_health_poll.py、availability_poll.py、
                      dashboard_server.py(只允許 AP server 連進來)。API Key 只放這台。
    -Role Proxy       裝在 AP server(有 NAT IP):只跑 ap_proxy.py,把電視牆的請求轉給 DB server。
                      這台完全沒有 API Key,也不需要連 OpManager。

  每個程式一個工作排程,用 SYSTEM 身分、開機就啟動;程式當掉 10 秒後自動重啟;
  輸出寫到 logs\工作名稱.log(超過 5 MB 自動換新檔)。

  API Key(只有 Collector):安裝時輸入(畫面不顯示),會先向 OpManager 驗證,
  再用 Windows 的「本機加密」存成 noc_apikey.machine.dat,檔案權限只給 SYSTEM 與系統管理員。
  這個檔只有「這台電腦」解得開,複製到別台沒用。

  所有動作都要用「系統管理員身分」開 PowerShell 執行。

.PARAMETER Action
  Install(預設要自己指定)/ Uninstall / Status / Start / Stop / SetKey(只換 API Key)
.PARAMETER Role
  Collector(DB server)或 Proxy(AP server)
.PARAMETER ApServerIp
  Collector 安裝時必填:允許連到資料伺服器的 AP server IP(可逗號分隔,可用網段)。同時會建立防火牆規則。
.PARAMETER Upstream
  Proxy 安裝時必填:DB server 上資料伺服器的網址,例如 http://10.1.1.20:8080
.PARAMETER AllowClient
  Proxy 安裝時建議填:允許連到 AP server 的來源(電視牆的 IP/網段;經過 NAT 時要填 AP 實際看到的 IP)。
  同時會建立防火牆規則。
.PARAMETER Https
  Proxy 安裝時使用:讓電視牆改用 https://(自簽憑證,瀏覽器會顯示「不安全」,內部使用可接受)。
  需要 AP server 的 Python 已安裝 cryptography(pip install cryptography)。
.PARAMETER CertNames
  搭配 -Https:憑證要涵蓋的「電視牆瀏覽器網址列會打的 IP 或主機名稱」(逗號分隔),例如 10.9.9.9,ap-server。
  第一次建立憑證時必填;網址跟憑證不符,瀏覽器會多出一種錯誤。
.PARAMETER RenewCert
  搭配 -Https:重新產生憑證(換 IP、或憑證快到期時使用)。產生後要重新把 ap_proxy_cert.crt 匯入電視牆電腦。
.PARAMETER Port
  Collector:資料伺服器的埠(預設 8080)。Proxy:對電視牆開放的埠(預設 8080)。
.PARAMETER ForgetKey
  Uninstall 時一併刪除加密的 API Key 檔。
.PARAMETER SkipKeyCheck
  略過安裝時的 API Key 驗證(驗證本身出問題時的備用開關)。

.EXAMPLE
  # AP server 改用 HTTPS(自簽憑證)
  .\noc_service.ps1 -Action Install -Role Proxy -Upstream http://10.1.1.20:8080 -AllowClient 10.9.0.0/24 -Https -CertNames 10.9.9.9
  # DB server(系統管理員 PowerShell)
  .\noc_service.ps1 -Action Install -Role Collector -ApServerIp 10.1.1.30
  .\noc_service.ps1 -Action Status -Role Collector
  # AP server
  .\noc_service.ps1 -Action Install -Role Proxy -Upstream http://10.1.1.20:8080 -AllowClient 10.9.0.0/24
#>
param(
    [ValidateSet("Install", "Uninstall", "Status", "Start", "Stop", "SetKey", "Run")][string]$Action = "Status",
    [ValidateSet("Collector", "Proxy")][string]$Role = "Collector",
    [string]$ApServerIp = "",
    [string]$Upstream = "",
    [string]$AllowClient = "",
    [int]$Port = 8080,
    [switch]$Https,
    [string]$CertNames = "",
    [switch]$RenewCert,
    [switch]$ForgetKey,
    [switch]$SkipKeyCheck,
    [string]$TaskName = ""          # 內部使用(排程呼叫 -Action Run 時帶入)
)

$Dir = Split-Path -Parent $PSCommandPath
$ConfigFile = Join-Path $Dir "noc_service_config.json"
$KeyFile = Join-Path $Dir "noc_apikey.machine.dat"
$LogDir = Join-Path $Dir "logs"
$CertFile = Join-Path $Dir "ap_proxy_cert.crt"
$CertKeyFile = Join-Path $Dir "ap_proxy_key.pem"
$BaseUrl = if ($env:OPM_BASE_URL) { $env:OPM_BASE_URL } else { "https://opmanager.example.internal:8061" }   # OpManager 位址(可用環境變數 OPM_BASE_URL 指定)
$FwRuleName = @{ Collector = "NOC Dashboard Data (from AP server)"; Proxy = "NOC AP Proxy (from TV wall)" }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── 機器層級的 DPAPI 加密(任何在這台電腦上的帳號都能解,所以另外用檔案權限限制)──
function Save-MachineKey([string]$Key) {
    Add-Type -AssemblyName System.Security
    $enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Key), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes($KeyFile, $enc)
    & icacls.exe $KeyFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(F)" | Out-Null
}
function Load-MachineKey {
    Add-Type -AssemblyName System.Security
    $bytes = [IO.File]::ReadAllBytes($KeyFile)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Text.Encoding]::UTF8.GetString($plain)
}

function Read-Config {
    if (-not (Test-Path -LiteralPath $ConfigFile)) { return $null }
    return (Get-Content -LiteralPath $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# ── 向 OpManager 驗證 API Key(跟輪詢腳本用同一支 API)──
function Test-ApiKey([string]$Key, [string]$PythonExe) {
    $tmp = Join-Path $env:TEMP "noc_keycheck.py"
    $py = @'
import os, sys
try:
    import requests, urllib3
except ImportError:
    print("沒有安裝 requests,請先執行:pip install requests")
    sys.exit(4)
urllib3.disable_warnings()
try:
    r = requests.get(os.environ["NOC_CHECK_URL"] + "/api/json/device/getDeviceSummary",
                     params={"apiKey": os.environ["NOC_CHECK_KEY"], "name": "127.0.0.1"}, verify=False, timeout=20)
    data = r.json()
except Exception as exc:
    print("連線或解析失敗:%s" % exc)
    sys.exit(3)
err = data.get("error") if isinstance(data, dict) else None
if isinstance(err, dict) and err.get("code") == 5000:
    print("OpManager 回應:code=%s message=%s" % (err.get("code"), err.get("message")))
    sys.exit(2)
sys.exit(0)
'@
    Set-Content -LiteralPath $tmp -Value $py -Encoding UTF8
    $env:NOC_CHECK_KEY = $Key; $env:NOC_CHECK_URL = $BaseUrl
    $code = 3
    try {
        $out = & $PythonExe $tmp 2>&1
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

function Read-ValidatedKey([string]$PythonExe) {
    $attempts = 0
    while ($true) {
        $attempts++
        if ($attempts -gt 3) { Write-Host "連續 3 次 API Key 都不正確,結束。" -ForegroundColor Red; exit 1 }
        $sec = Read-Host "請輸入 OpManager API Key(輸入時不會顯示)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $key = ([string]$key).Trim()
        if (-not $key) { Write-Host "沒有輸入內容。" -ForegroundColor Yellow; continue }
        if ($SkipKeyCheck) { Write-Host "已指定 -SkipKeyCheck,略過驗證。" -ForegroundColor Yellow; return $key }
        Write-Host ("正在驗證 API Key…(長度 {0} 個字元)" -f $key.Length)
        $r = Test-ApiKey $key $PythonExe
        if ($r -eq "ok") { Write-Host "API Key 驗證成功。" -ForegroundColor Green; return $key }
        if ($r -eq "unreachable") { Write-Host "這台電腦連不到 OpManager($BaseUrl),無法驗證,先照這把 Key 繼續。請之後確認網路。" -ForegroundColor Yellow; return $key }
        Write-Host "這把 API Key 被 OpManager 拒絕,請確認有沒有複製完整。" -ForegroundColor Red
    }
}

function Stop-Children {
    param($Cfg)
    foreach ($t in $Cfg.tasks) {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -and $_.CommandLine -like "*$($t.script)*" -and $_.Name -match "python"
        } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}

# ══════════════ Run:由工作排程呼叫,實際執行並記錄輸出 ══════════════
if ($Action -eq "Run") {
    $ErrorActionPreference = "Continue"
    $cfg = Read-Config
    $t = $cfg.tasks | Where-Object { $_.name -eq $TaskName } | Select-Object -First 1
    if (-not $t) { exit 2 }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
    $logFile = Join-Path $LogDir ("{0}.log" -f $TaskName)
    $script:lineCount = 0
    function Add-LogLine([string]$Text) {
        $script:lineCount++
        if ($script:lineCount % 100 -eq 1 -and (Test-Path -LiteralPath $logFile) -and (Get-Item -LiteralPath $logFile).Length -gt 5MB) {
            Move-Item -LiteralPath $logFile -Destination ($logFile + ".1") -Force
        }
        Add-Content -LiteralPath $logFile -Value $Text -Encoding UTF8
    }
    Set-Location -LiteralPath $Dir
    $env:PYTHONIOENCODING = "utf-8"
    # 讓 PowerShell 用 UTF-8 解讀 python 的輸出(預設會用系統的 Big5/cp950,中文記錄會變亂碼)
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8; $OutputEncoding = [Text.Encoding]::UTF8 } catch { }
    if ($cfg.role -eq "Collector") {
        try {
            $k = Load-MachineKey
            $env:NFA_API_KEY = $k; $env:OPM_API_KEY = $k
        } catch { Add-LogLine ("[{0}] 讀不到 API Key:{1}" -f (Get-Date -Format s), $_.Exception.Message); Start-Sleep -Seconds 60; exit 3 }
    }
    $argList = @("-u", $t.script) + @(($t.args -split " ") | Where-Object { $_ })
    while ($true) {
        Add-LogLine ("[{0}] 啟動:python {1}" -f (Get-Date -Format s), ($argList -join " "))
        & $cfg.python @argList 2>&1 | ForEach-Object { Add-LogLine ([string]$_) }
        Add-LogLine ("[{0}] 程式已停止,10 秒後自動重新啟動。" -f (Get-Date -Format s))
        Start-Sleep -Seconds 10
    }
}

# ══════════════ 以下都需要系統管理員 ══════════════
if (-not (Test-Admin)) { Write-Host "請用「系統管理員身分」開啟 PowerShell 再執行。" -ForegroundColor Red; exit 1 }

if ($Action -eq "Install") {
    # 1) Python
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyCmd) { Write-Host "找不到 python。請先安裝 Python(勾選 Add to PATH 與「為所有使用者安裝」)。" -ForegroundColor Red; exit 1 }
    $pythonExe = $pyCmd.Source
    if ($pythonExe -match "\\Users\\|WindowsApps") {
        Write-Host "警告:這個 Python 裝在個人帳號底下($pythonExe),開機排程用的 SYSTEM 帳號可能用不了。" -ForegroundColor Yellow
        Write-Host "      建議用 python.org 安裝程式,選「Install for all users」,再重新執行。" -ForegroundColor Yellow
    }
    # requests 只有 Collector(收集程式)需要;Proxy(AP server)只用 Python 內建功能,不需要連網安裝套件
    if ($Role -eq "Collector") {
        & $pythonExe -c "import requests" 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Host "Python 缺少 requests。請用系統管理員執行:pip install requests" -ForegroundColor Red; exit 1 }
    }

    # 2) 依角色整理要註冊的工作
    $tasks = @()
    if ($Role -eq "Collector") {
        if (-not $ApServerIp) { Write-Host "Collector 必須指定 -ApServerIp(允許連到資料伺服器的 AP server IP),避免整個網段都能看。" -ForegroundColor Red; exit 1 }
        foreach ($f in @("netflow_poll_poc.py", "fw_health_poll.py", "availability_poll.py", "dashboard_server.py", "dashboard.html")) {
            if (-not (Test-Path -LiteralPath (Join-Path $Dir $f))) { Write-Host "缺少檔案:$f(要跟這支腳本放同一個資料夾)" -ForegroundColor Red; exit 1 }
        }
        & $pythonExe -c "import maxminddb" 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Host "(提示)Python 缺少 maxminddb,國別流量地圖無法更新。需要的話請執行:pip install maxminddb" -ForegroundColor Yellow }
        $tasks = @(
            @{ name = "NOC-Netflow";      script = "netflow_poll_poc.py";  args = "" },
            @{ name = "NOC-Firewall";     script = "fw_health_poll.py";    args = "" },
            @{ name = "NOC-Availability"; script = "availability_poll.py"; args = "" },
            @{ name = "NOC-Dashboard";    script = "dashboard_server.py";  args = "--host 0.0.0.0 --port $Port --allow-from $ApServerIp" }
        )
        if (-not (Test-Path -LiteralPath $KeyFile)) {
            Write-Host "這台電腦還沒有儲存的 API Key,現在輸入。" -ForegroundColor Cyan
            Save-MachineKey (Read-ValidatedKey $pythonExe)
            Write-Host "已加密儲存(只有這台電腦的 SYSTEM 與系統管理員能讀)。" -ForegroundColor Green
        } else { Write-Host "沿用已儲存的 API Key(要更換請執行 -Action SetKey)。" }
    } else {
        if (-not $Upstream) { Write-Host "Proxy 必須指定 -Upstream(DB server 的網址,例如 http://10.1.1.20:8080)。" -ForegroundColor Red; exit 1 }
        if (-not (Test-Path -LiteralPath (Join-Path $Dir "ap_proxy.py"))) { Write-Host "缺少檔案:ap_proxy.py" -ForegroundColor Red; exit 1 }
        $a = "--upstream $Upstream --port $Port"
        if ($Https) {
            & $pythonExe -c "import cryptography" 2>$null
            if ($LASTEXITCODE -ne 0) { Write-Host "Python 缺少 cryptography(產生憑證用)。請用系統管理員執行:pip install cryptography" -ForegroundColor Red; exit 1 }
            $haveCert = (Test-Path -LiteralPath $CertFile) -and (Test-Path -LiteralPath $CertKeyFile)
            if ($RenewCert -or -not $haveCert) {
                if (-not $CertNames) { Write-Host "要產生憑證,請用 -CertNames 填電視牆瀏覽器網址列會打的 IP 或主機名稱,例如 -CertNames 10.9.9.9,ap-server" -ForegroundColor Red; exit 1 }
                Push-Location $Dir
                try {
                    $out = & $pythonExe ap_proxy.py --make-cert --cert-names $CertNames 2>&1
                    $mk = $LASTEXITCODE
                } finally { Pop-Location }
                $out | ForEach-Object { Write-Host ("  " + $_) }
                if ($mk -ne 0 -or -not (Test-Path -LiteralPath $CertKeyFile)) { Write-Host "產生憑證失敗。" -ForegroundColor Red; exit 1 }
                # 私鑰只給 SYSTEM 與系統管理員讀取
                & icacls.exe $CertKeyFile /inheritance:r /grant "SYSTEM:(R)" /grant "BUILTIN\Administrators:(F)" | Out-Null
                Write-Host "  已產生憑證 ap_proxy_cert.crt;請把它匯入電視牆那台電腦的「受信任的根憑證授權單位」(見 部署說明.txt),瀏覽器就不會再顯示不安全。" -ForegroundColor Green
            } else { Write-Host "  沿用既有憑證 ap_proxy_cert.crt(要重新產生請加 -RenewCert -CertNames ...)。" }
            $a += " --cert ap_proxy_cert.crt --key ap_proxy_key.pem"
        }
        if ($AllowClient) { $a += " --allow-client $AllowClient" }
        else { Write-Host "(提醒)沒有指定 -AllowClient:任何連得到這個埠的人都能看到大螢幕,請務必搭配防火牆。" -ForegroundColor Yellow }
        $tasks = @(@{ name = "NOC-ApProxy"; script = "ap_proxy.py"; args = $a })
    }

    # 3) 先清掉舊的,寫設定檔,註冊工作排程
    $old = Read-Config
    if ($old) { foreach ($t in $old.tasks) { Stop-ScheduledTask -TaskName $t.name -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $t.name -Confirm:$false -ErrorAction SilentlyContinue }; Stop-Children $old }
    @{ role = $Role; python = $pythonExe; port = $Port; https = [bool]($Role -eq "Proxy" -and $Https); tasks = $tasks } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile -Encoding UTF8

    try {
    foreach ($t in $tasks) {
        $arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Action Run -TaskName $($t.name)"
        $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg -WorkingDirectory $Dir
        $taskTrigger = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $t.name -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings `
            -Description "NOC 大螢幕($Role)" -Force -ErrorAction Stop | Out-Null
        Write-Host ("  已註冊工作排程:{0}  ({1})" -f $t.name, $t.script) -ForegroundColor Green
    }

    # 4) 防火牆規則:只允許指定來源連到這個埠
    $remote = if ($Role -eq "Collector") { $ApServerIp } else { $AllowClient }
    Remove-NetFirewallRule -DisplayName $FwRuleName[$Role] -ErrorAction SilentlyContinue
    if ($remote) {
        New-NetFirewallRule -DisplayName $FwRuleName[$Role] -Direction Inbound -Protocol TCP -LocalPort $Port `
            -RemoteAddress ($remote -split ",") -Action Allow -ErrorAction Stop | Out-Null
        Write-Host ("  已建立防火牆規則:TCP {0} 只允許來源 {1}" -f $Port, $remote) -ForegroundColor Green
    } else {
        Write-Host "  沒有建立防火牆規則(未指定來源)。請自行確認防火牆設定。" -ForegroundColor Yellow
    }

    } catch {
        Write-Host ("安裝失敗:{0}" -f $_.Exception.Message) -ForegroundColor Red
        exit 1
    }

    # 5) 立刻啟動(不用等重開機)
    foreach ($t in $tasks) { Start-ScheduledTask -TaskName $t.name }
    Write-Host "`n已啟動。幾秒後可用  .\noc_service.ps1 -Action Status -Role $Role  檢查狀態。" -ForegroundColor Cyan
    exit 0
}

$cfg = Read-Config
if (-not $cfg -and $Action -ne "Uninstall") { Write-Host "還沒安裝(找不到 noc_service_config.json)。請先執行 -Action Install。" -ForegroundColor Yellow; exit 1 }

switch ($Action) {
    "Status" {
        Write-Host ("角色:{0}   Python:{1}" -f $cfg.role, $cfg.python)
        foreach ($t in $cfg.tasks) {
            $st = Get-ScheduledTask -TaskName $t.name -ErrorAction SilentlyContinue
            if (-not $st) { Write-Host ("  {0,-18} 未註冊" -f $t.name) -ForegroundColor Red; continue }
            $info = Get-ScheduledTaskInfo -TaskName $t.name
            Write-Host ("  {0,-18} 狀態:{1,-9} 上次啟動:{2}" -f $t.name, $st.State, $info.LastRunTime)
            $lf = Join-Path $LogDir ("{0}.log" -f $t.name)
            if (Test-Path -LiteralPath $lf) { Get-Content -LiteralPath $lf -Tail 3 -Encoding UTF8 | ForEach-Object { Write-Host ("      | " + $_) -ForegroundColor DarkGray } }
        }
        $p = $cfg.port
        try {
            if ($cfg.role -eq "Collector") {
                $r = Invoke-RestMethod -Uri "http://127.0.0.1:$p/api/summary" -TimeoutSec 5
                foreach ($k in @("netflow", "firewall", "availability", "threat_map")) {
                    $s = $r.$k
                    $txt = if (-not $s.available) { "無資料" } elseif ($s.stale) { "資料過期($($s.age_sec) 秒前)" } else { "正常($($s.age_sec) 秒前更新)" }
                    Write-Host ("  資料 {0,-13} {1}" -f $k, $txt)
                }
            } else {
                $scheme = "http"
                if ($cfg.https) {
                    $scheme = "https"
                    # 自簽憑證:本機自我檢查時略過憑證驗證
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                }
                $r = Invoke-RestMethod -Uri "${scheme}://127.0.0.1:$p/healthz" -TimeoutSec 8
                Write-Host ("  轉發程式:{0}   DB server:{1}   協定:{2}" -f $r.proxy, $r.upstream, $scheme.ToUpper())
            }
        } catch { Write-Host ("  本機檢查失敗:{0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    }
    "Start" { foreach ($t in $cfg.tasks) { Start-ScheduledTask -TaskName $t.name }; Write-Host "已啟動。" -ForegroundColor Green }
    "Stop" {
        foreach ($t in $cfg.tasks) { Stop-ScheduledTask -TaskName $t.name -ErrorAction SilentlyContinue }
        Stop-Children $cfg
        Write-Host "已停止(下次開機仍會自動啟動;要完全移除請用 -Action Uninstall)。" -ForegroundColor Green
    }
    "SetKey" {
        if ($cfg.role -ne "Collector") { Write-Host "只有 Collector 有 API Key。" -ForegroundColor Yellow; exit 1 }
        Save-MachineKey (Read-ValidatedKey $cfg.python)
        foreach ($t in $cfg.tasks) { Stop-ScheduledTask -TaskName $t.name -ErrorAction SilentlyContinue }
        Stop-Children $cfg
        foreach ($t in $cfg.tasks) { Start-ScheduledTask -TaskName $t.name }
        Write-Host "已更新 API Key 並重新啟動全部程式。" -ForegroundColor Green
    }
    "Uninstall" {
        if ($cfg) { foreach ($t in $cfg.tasks) { Stop-ScheduledTask -TaskName $t.name -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $t.name -Confirm:$false -ErrorAction SilentlyContinue }; Stop-Children $cfg }
        Remove-NetFirewallRule -DisplayName $FwRuleName["Collector"] -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName $FwRuleName["Proxy"] -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ConfigFile -Force -ErrorAction SilentlyContinue
        if ($ForgetKey -and (Test-Path -LiteralPath $KeyFile)) { Remove-Item -LiteralPath $KeyFile -Force; Write-Host "已刪除加密的 API Key。" }
        Write-Host "已移除工作排程與防火牆規則。" -ForegroundColor Green
    }
}
