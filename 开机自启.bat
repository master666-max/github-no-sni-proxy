@echo off

chcp 936 >nul

title GitHub 无SNI反代 - 注册开机自启



net session >nul 2>&1

if errorlevel 1 (

    echo 正在请求管理员权限...

    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"

    exit /b

)



echo ============================================================

echo   注册开机自启（登录后自动运行，不弹 UAC）

echo   任务名: gh-proxy

echo   目标  : %~dp0run-proxy.cmd

echo ============================================================

echo.



set "LOG=%~dp0autostart_register.log"

> "%LOG%" echo ===== 自启注册 %date% %time% =====



schtasks /Create /TN "gh-proxy" /TR "\"%~dp0run-proxy.cmd\"" /SC ONLOGON /RL HIGHEST /F >>"%LOG%" 2>&1

if not errorlevel 1 goto :verify



echo [!] schtasks 直建被拒 —— 新版 Windows（24H2/25H2）对 ONLOGON+最高权限

echo     组合收紧了权限，或被安全软件拦截。改用 PowerShell 注册接口再试……

>>"%LOG%" echo ----- schtasks 被拒，改走 Register-ScheduledTask -----

powershell -NoProfile -Command ^

  "$usr = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;" ^

  "$act = New-ScheduledTaskAction -Execute '%~dp0run-proxy.cmd' -WorkingDirectory '%~dp0';" ^

  "$trg = New-ScheduledTaskTrigger -AtLogOn -User $usr;" ^

  "$pri = New-ScheduledTaskPrincipal -UserId $usr -RunLevel Highest;" ^

  "$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew;" ^

  "$set.ExecutionTimeLimit = 'PT0S';" ^

  "try { Register-ScheduledTask -TaskName 'gh-proxy' -Action $act -Trigger $trg -Principal $pri -Settings $set -Force -ErrorAction Stop | Out-Null; exit 0 } catch { $_.Exception.Message | Out-File '%LOG%' -Append -Encoding utf8; exit 1 }"

if errorlevel 1 (

    echo.

    echo [x] 两种方式都注册失败。原因已写入 %LOG%

    echo     常见原因：安全软件的「计划任务防护」在拦 —— 放行本目录或暂时退出

    echo     安全软件再跑一次；或组策略禁止创建最高权限任务。

    echo.

    echo     跳过这步也行：每次手动双击「启动反代.bat」即可。

    echo.

    pause

    exit /b 1

)



:verify

schtasks /Query /TN "gh-proxy" >nul 2>&1

if errorlevel 1 (

    echo [x] 注册后查询不到任务 gh-proxy，注册未生效（详见 %LOG%）

    pause

    exit /b 1

)

echo.

echo [OK] 已注册计划任务 gh-proxy（登录自启 / 最高权限 / 无 72 小时时限）

echo      正在立即启动一次...

schtasks /Run /TN "gh-proxy" >nul 2>&1

echo [OK] 已触发。

echo.

echo      取消自启：运行「一键卸载.bat」，或删除计划任务 gh-proxy

echo.

pause

