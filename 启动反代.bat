@echo off
chcp 936 >nul
title GitHub 无SNI反代 - 运行中

net session >nul 2>&1
if errorlevel 1 (
    echo 正在请求管理员权限（监听 443 需要）...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call "%~dp0_find_python.cmd"
if errorlevel 1 (
    echo.
    pause
    exit /b 1
)

echo ============================================================
echo   GitHub 无SNI反代
echo   工作目录: %~dp0
echo   解释器  : %PY%
echo   监听    : 127.0.0.1:443
echo   ----------------------------------------------
echo   保持本窗口开着；关闭窗口即停止。
echo ============================================================
echo.

"%PY%" "%~dp0gh-proxy.py" --port 443

echo.
echo 反代已停止。
pause
