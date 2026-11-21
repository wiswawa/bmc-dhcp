@echo off
rem 双击这个文件启动图形界面（对应 mac 上的 BMC DHCP.app）
rem 会弹一次 UAC：后端要改网卡地址、抓包，必须管理员权限。
setlocal enableextensions
chcp 65001 >nul 2>nul
set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

rem 优先用无窗口的 pythonw 起，避免闪一个黑框。
rem 先确认「py 启动器真的有 Python 3」：pyw.exe 存在但 -3 没解释器时，
rem start 会静默失败 —— 双击之后什么都不会发生，最难查。
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 (
  where pyw >nul 2>&1
  if not errorlevel 1 (
    start "" pyw -3 "%HERE%\app_win.py"
    exit /b 0
  )
)
where pythonw >nul 2>&1
if not errorlevel 1 (
  start "" pythonw "%HERE%\app_win.py"
  exit /b 0
)
rem 注意：微软商店的 python.exe 是个「装 Python」的跳板，所以要真跑一句才算数
python -c "import sys" >nul 2>&1
if not errorlevel 1 (
  python "%HERE%\app_win.py"
  if errorlevel 1 pause
  exit /b 0
)
echo.
echo   没找到 Python 3。去 https://www.python.org/downloads/windows/ 装一个，
echo   安装时勾上「Add python.exe to PATH」，然后再双击本文件。
echo.
start "" https://www.python.org/downloads/windows/
pause
exit /b 2
