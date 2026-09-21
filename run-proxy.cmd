@echo off
chcp 936 >nul
rem 由计划任务 / 开机自启调用：无窗口启动反代（管理员上下文）
rem
rem 日志必须落盘：pythonw 裸跑时 stdout 无人接收，status_gui 的日志窗与
rem 「近1分钟请求」统计会全部失明（实测踩过）。
rem pid 文件由 gh-proxy.py 自己写。
rem
rem 安全：本脚本运行于管理员上下文，解释器只认显式路径，
rem 绝不回退 PATH 搜索——否则用户级恶意软件可在 PATH 目录投放同名
rem python.exe 借此提权。需要换解释器时，把绝对路径写进本目录
rem python-path.txt 即可覆盖内置清单。
rem
rem 候选清单用环境变量拼装，不含用户名/盘符硬编码。
set "PYW="
if exist "%~dp0python-path.txt" set /p PYW=<"%~dp0python-path.txt"
if not defined PYW call :try "%LOCALAPPDATA%\Programs\Python\Python314\pythonw.exe"
if not defined PYW call :try "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe"
if not defined PYW call :try "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if not defined PYW call :try "%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe"
if not defined PYW call :try "%ProgramFiles%\Python314\pythonw.exe"
if not defined PYW call :try "%ProgramFiles%\Python313\pythonw.exe"
if not defined PYW call :try "%ProgramFiles%\Python312\pythonw.exe"
if not defined PYW call :try "%ProgramFiles%\Python311\pythonw.exe"
goto :start

:try
if not defined PYW if exist %1 set "PYW=%~1"
goto :eof

:start
if not defined PYW (
  echo [%date% %time%] [x] run-proxy: 找不到 pythonw.exe（且无 python-path.txt），未启动 >> "%~dp0gh-proxy.log"
  exit /b 1
)
"%PYW%" "%~dp0gh-proxy.py" --port 443 >> "%~dp0gh-proxy.log" 2>&1
exit /b 0
