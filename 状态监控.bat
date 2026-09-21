@echo off
chcp 936 >nul
title gh-proxy ×´Ì¬¼à¿Ø

call "%~dp0_find_python.cmd"
if errorlevel 1 (
    echo [x] ÕÒ²»µ½ Python£¬ÎÞ·¨Æô¶¯¼à¿Ø´°¿Ú¡£
    pause
    exit /b 1
)

start "gh-proxy ×´Ì¬¼à¿Ø" "%PYW%" "%~dp0status_gui.py"
