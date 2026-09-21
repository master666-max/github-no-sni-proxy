@echo off
chcp 936 >nul
title GitHub 反代 - 一键重启

net session >nul 2>&1
if errorlevel 1 (
    echo 正在请求管理员权限（停旧进程 + 监听 443 都需要）...
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
echo   GitHub 反代 · 一键重启
echo   工作目录: %~dp0
echo   解释器  : %PY%
echo ============================================================
echo.

"%PY%" "%~dp0restart_proxy.py"
set RC=%ERRORLEVEL%

echo.
if "%RC%"=="0" (
    echo [OK] 重启成功。窗口将在 8 秒后自动关闭。
    timeout /t 8 >nul
) else (
    echo [x] 重启未完成，请阅读上面的输出。
    pause
)
