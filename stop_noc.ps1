<#
.SYNOPSIS
  停止 start_noc.ps1 開起來的所有程式(輪詢腳本 + 大螢幕伺服器)。
.DESCRIPTION
  只會停掉「NOC 相關」的視窗與 python 程式,不會動到你其他的 PowerShell 視窗。
  不會關瀏覽器(Kiosk 模式請按 Alt+F4)。
#>
$ErrorActionPreference = "Continue"
$scripts = @("netflow_poll_poc.py", "fw_health_poll.py", "availability_poll.py", "dashboard_server.py")

# 1) 先停「自動重啟的外層視窗」,不然它會在 10 秒後把程式又叫起來
$wrappers = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "powershell|pwsh" -and $_.CommandLine -like "*NOC_MANAGED*"
}
foreach ($w in $wrappers) {
    & taskkill /PID $w.ProcessId /T /F | Out-Null
    Write-Host ("已停止視窗 PID {0}" -f $w.ProcessId)
}

# 2) 保險:還有殘留的 python(例如不是用 start_noc 開的)也一併停掉
foreach ($p in (Get-CimInstance Win32_Process | Where-Object { $_.Name -match "python" -and $_.CommandLine })) {
    foreach ($s in $scripts) {
        if ($p.CommandLine -like "*$s*") {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Host ("已停止 {0}(PID {1})" -f $s, $p.ProcessId)
        }
    }
}
Write-Host "完成。" -ForegroundColor Green
