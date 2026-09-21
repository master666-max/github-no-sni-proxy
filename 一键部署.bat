@echo off
chcp 936 >nul
title GitHub 无SNI反代 - 部署
setlocal
set "LOG=%~dp0deploy_last_run.txt"

> "%LOG%" echo ===== 部署日志 %date% %time% =====
>>"%LOG%" echo 工作目录: %~dp0

net session >nul 2>&1
if not errorlevel 1 goto :admin

echo.
echo  需要管理员权限。马上会弹出 UAC 窗口：
echo    · 管理员账号  -^> 点「是」
echo    · 标准账号    -^> 输入管理员账号密码再点「继续」
echo  （窗口可能藏在后面，任务栏找一下；2 分钟不点会自动取消）
echo.
>>"%LOG%" echo 准备提权重启自身...
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs; exit 0 } catch { $_.Exception.Message | Out-File -FilePath '%LOG%' -Append -Encoding utf8; exit 1 }"
if errorlevel 1 (
    echo  [x] 提权失败 —— 原因已写入 deploy_last_run.txt
    echo      也可以：右键「一键部署.bat」-^> 以管理员身份运行
) else (
    echo  已弹出管理员窗口。本窗口可以关了。
)
echo.
pause
exit /b

:admin
>>"%LOG%" echo ===== 已获管理员权限，开始部署 =====
call "%~dp0_find_python.cmd"
if errorlevel 1 (
    >>"%LOG%" echo [x] 找不到 Python
    echo  [x] 找不到 Python，无法部署。
    echo.
    pause
    exit /b 1
)
>>"%LOG%" echo 使用解释器: %PY%
"%PY%" "%~dp0deploy.py"
>>"%LOG%" echo deploy.py 退出码=%errorlevel%
echo.
echo  ===== 脚本结束。按任意键关闭 =====
pause >nul
exit /b
