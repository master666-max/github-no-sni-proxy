@echo off
rem ============================================================
rem  找到可用的 Python，把绝对路径写进 %PY% / %PYW% 供调用者使用。
rem  - 文件名全 ASCII：不受代码页影响
rem  - 内容 cp936：中文在 cmd 里直接正常显示
rem  - 不用 setlocal：set 要传播给 call 者
rem  - 不依赖 PATH 里的任何 Unix 命令（PATH 坏了也能跑）
rem  - 不含任何用户名/盘符硬编码：用 py 启动器 + 环境变量，clone 到哪都能跑
rem  ①可把解释器绝对路径写进本目录 python-path.txt 覆盖内置清单；
rem  ②PATH 兜底命中时会回显告警（交互链可用；提权链 run-proxy.cmd
rem    已另做 fail-closed，不走本兜底）。
rem ============================================================
set "PY="
if exist "%~dp0python-path.txt" set /p PY=<"%~dp0python-path.txt"
if defined PY goto :have

rem ① Python 官方启动器 py.exe（装 Python 时默认附带，最可靠）
for /f "delims=" %%P in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do if not defined PY set "PY=%%P"

rem ② 常见安装位置（环境变量拼装，无硬编码用户名）
if not defined PY call :try "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PY call :try "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PY call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY call :try "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY call :try "%ProgramFiles%\Python314\python.exe"
if not defined PY call :try "%ProgramFiles%\Python313\python.exe"
if not defined PY call :try "%ProgramFiles%\Python312\python.exe"
if not defined PY call :try "%ProgramFiles%\Python311\python.exe"
if not defined PY call :try "C:\Python314\python.exe"
if not defined PY call :try "C:\Python313\python.exe"
if not defined PY call :try "C:\Python312\python.exe"
if not defined PY call :try "C:\Python311\python.exe"
goto :pathfb

:try
if not defined PY if exist %1 set "PY=%~1"
goto :eof

:pathfb
rem ③ 兜底：去 PATH 里找（命中=解释器不受本工具控制，回显告警供审计）
if not defined PY (
  for %%P in (python.exe) do set "PY=%%~$PATH:P"
  if defined PY (
    echo   [!] 警告：内置路径全未命中，解释器取自 PATH： %PY%
    echo       建议把可信解释器绝对路径写进本目录 python-path.txt
  )
)

if not defined PY (
  echo.
  echo   [x] 找不到 Python 3.x
  echo       请安装 Python 3.11 或更高版本：
  echo         https://www.python.org/downloads/
  echo       安装时勾选 "Add python.exe to PATH"
  echo       或把解释器绝对路径写进本目录 python-path.txt
  echo.
  exit /b 1
)

:have
rem ④ 派生无窗口版 pythonw.exe；没有就用 python.exe
set "PYW=%PY:python.exe=pythonw.exe%"
if not exist "%PYW%" set "PYW=%PY%"
exit /b 0
