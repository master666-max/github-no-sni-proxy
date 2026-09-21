@echo off
chcp 936 >nul
title GitHub 无SNI反代 - 卸载还原

net session >nul 2>&1
if errorlevel 1 (
    echo 正在请求管理员权限...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call "%~dp0_find_python.cmd"
if errorlevel 1 (
    echo [x] 找不到 Python，无法卸载。
    pause
    exit /b 1
)

"%PY%" "%~dp0undeploy.py"
echo.
pause
