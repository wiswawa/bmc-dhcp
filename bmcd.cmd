@echo off
rem bmcd Windows 启动器（对应 mac 上的 ./bmcd）
rem
rem   bmcd.cmd                        等价于 bmcd.cmd run
rem   bmcd.cmd scan --listen 0        找已经配好静态 IP 的机器
rem   bmcd.cmd selftest               不需要管理员的自检
rem   （ifaces / selftest 不需要 venv：venv 建不起来时也照样能跑）
rem   bmcd.cmd repair                 删掉 %LOCALAPPDATA%\bmcd\venv 重新建一遍
rem   bmcd.cmd verify                 只检查程序文件全不全（不建环境、不要管理员）
rem   set BMCD_NO_ADMIN=1 & bmcd.cmd  不想弹 UAC（只能跑 ifaces/selftest/leases）
rem
rem 首次运行会在 %LOCALAPPDATA%\bmcd\venv 建一个虚拟环境并装 scapy。
setlocal enableextensions
chcp 65001 >nul 2>nul
title bmcd

set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
set "BMCD_DIR=%LOCALAPPDATA%\bmcd"
set "VENV=%BMCD_DIR%\venv"
set "RUNPY=%VENV%\Scripts\python.exe"
set "PYTHONPATH=%HERE%\src"

rem ---------- 认子命令 ----------
set "CMD=run"
set "A=%~1"
if /i "%A%"=="run"         set "CMD=run"
if /i "%A%"=="ifaces"      set "CMD=ifaces"
if /i "%A%"=="probe"       set "CMD=probe"
if /i "%A%"=="find-static" set "CMD=find-static"
if /i "%A%"=="scan"        set "CMD=scan"
if /i "%A%"=="leases"      set "CMD=leases"
if /i "%A%"=="selftest"    set "CMD=selftest"
if /i "%A%"=="simulate"    set "CMD=simulate"
if /i "%A%"=="web"         set "CMD=web"
if /i "%A%"=="-h"          set "CMD=help"
if /i "%A%"=="--help"      set "CMD=help"
if /i "%A%"=="help"        set "CMD=help"
if /i "%A%"=="--version"   set "CMD=help"
if /i "%A%"=="repair"      set "CMD=repair"
if /i "%A%"=="rebuild"     set "CMD=repair"
if /i "%A%"=="fix"         set "CMD=repair"
if /i "%A%"=="verify"      set "CMD=verify"
if /i "%A%"=="check"       set "CMD=verify"

rem ---------- 哪些子命令需要管理员 ----------
set "NEEDADMIN=0"
if "%CMD%"=="run"         set "NEEDADMIN=1"
if "%CMD%"=="scan"        set "NEEDADMIN=1"
if "%CMD%"=="find-static" set "NEEDADMIN=1"
if "%CMD%"=="simulate"    set "NEEDADMIN=1"

rem ---------- 包完整性：少一个文件就别往下走了 ----------
rem 典型故障：zip 只解压/复制了一部分，ui\index.html 不在 ——
rem 后端能跑起来，但打开界面是一页白屏 + 一行 JSON 报错。
set "PKGOK=1"
if not exist "%HERE%\src\bmcdhcp\__init__.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\__init__.py
)
if not exist "%HERE%\src\bmcdhcp\webapp.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\webapp.py
)
if not exist "%HERE%\src\bmcdhcp\session.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\session.py
)
if not exist "%HERE%\src\bmcdhcp\scan.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\scan.py
)
if not exist "%HERE%\src\bmcdhcp\winnet.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\winnet.py
)
if not exist "%HERE%\src\bmcdhcp\ui\index.html" (
  set "PKGOK=0"
  echo [bmcd] 缺少：src\bmcdhcp\ui\index.html
)
if not exist "%HERE%\app_win.py" (
  set "PKGOK=0"
  echo [bmcd] 缺少：app_win.py
)
if "%CMD%"=="verify" goto :verify
if not "%PKGOK%"=="1" goto :incomplete

rem ---------- 诊断类子命令：不需要 venv，系统 Python 就够 ----------
rem venv 建不起来（Microsoft Store 版 Python 很常见）时，ifaces/selftest 是唯一的
rem 排查手段，不能让它们跟着一起死。所以这两条走系统解释器，不建环境、不装 scapy。
if "%CMD%"=="ifaces" goto :sysdiag
if "%CMD%"=="selftest" goto :sysdiag

rem ---------- 准备运行环境 ----------
if "%CMD%"=="repair" (
  echo [bmcd] 删掉旧的运行环境：%VENV%
  if exist "%VENV%" rmdir /s /q "%VENV%"
)
if exist "%RUNPY%" goto :maybe_admin
echo [bmcd] 首次运行：准备运行环境（装 scapy，大约 1 分钟）…
set "BASEPY="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 set "BASEPY=py -3"
if defined BASEPY goto :make_venv
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "BASEPY=python"
if not defined BASEPY goto :nopython
:make_venv
%BASEPY% -m venv "%VENV%"
if errorlevel 1 goto :nopython
"%RUNPY%" -m pip install -q --disable-pip-version-check "scapy>=2.5"
if not exist "%RUNPY%" goto :nopython
if "%CMD%"=="repair" goto :repair_done

:maybe_admin
rem repair 只关心「环境建好没有」，建好了就结束，别去跑 bmcdhcp repair
if "%CMD%"=="repair" goto :repair_done
rem 已经是提权后的自己了？提权过一次就不再问，避免 UAC 死循环
if "%BMCD_ELEVATED%"=="1" goto :run
if not "%NEEDADMIN%"=="1" goto :run
if "%BMCD_NO_ADMIN%"=="1" goto :run
rem 两种「我是不是管理员」的探测方式，fltmc 不依赖 Server 服务，优先用
fltmc >nul 2>&1
if not errorlevel 1 goto :run
net session >nul 2>&1
if not errorlevel 1 goto :run

rem ---------- 提权：写一个临时 bat，让 UAC 拉起一个新的管理员控制台 ----------
echo [bmcd] 需要管理员权限（改网卡地址 / 抓包），正在请求 UAC 授权…
set "ELEV=%TEMP%\bmcd-elevated.cmd"
> "%ELEV%"  echo @echo off
>>"%ELEV%"  echo chcp 65001 ^>nul 2^>nul
>>"%ELEV%"  echo title bmcd %CMD%
>>"%ELEV%"  echo set "BMCD_ELEVATED=1"
>>"%ELEV%"  echo set "PYTHONPATH=%HERE%\src"
>>"%ELEV%"  echo cd /d "%HERE%"
>>"%ELEV%"  echo "%RUNPY%" -m bmcdhcp %*
>>"%ELEV%"  echo echo.
>>"%ELEV%"  echo pause
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%ELEV%' -Verb RunAs"
if errorlevel 1 echo [bmcd] 已取消：没拿到管理员权限，什么都没改。
exit /b 0

:run
"%RUNPY%" -m bmcdhcp %*
exit /b %errorlevel%

:sysdiag
rem 诊断子命令：venv 能用就用（带 scapy 信息更全），否则退系统 Python。
rem 括号块里的 %errorlevel% 在**解析时**就展开（那时还是 if exist / where 的 0），
rem 所以块里不能用 %errorlevel% —— 用不带参数的 `exit /b`，它原样保留当前
rem ERRORLEVEL，把上面那条 python 的退出码带出去。
if exist "%RUNPY%" (
  "%RUNPY%" -m bmcdhcp %*
  exit /b
)
where py >nul 2>&1
if not errorlevel 1 (
  py -3 -m bmcdhcp %*
  exit /b
)
where python >nul 2>&1
if not errorlevel 1 (
  python -m bmcdhcp %*
  exit /b
)
goto :nopython

:verify
if "%PKGOK%"=="1" goto :verify_ok
echo [bmcd] 包不完整（上面列出的是缺失文件）。
echo [bmcd] 把 zip 重新完整解压到一个空目录再试。
exit /b 3
:verify_ok
echo [bmcd] 包完整：必需文件都在（%HERE%）。
exit /b 0

:incomplete
echo.
echo   程序文件不全（见上面的「缺少」），后端起不来也没有界面。
echo   处理办法：把 zip 重新完整解压到一个空目录（例如 C:\bmcd），
echo   再双击 BMC DHCP.cmd。别只复制一部分文件。
echo.
pause
exit /b 3

:repair_done
echo [bmcd] 运行环境已重建：%VENV%
if exist "%VENV%\pyvenv.cfg" (
  echo [bmcd] pyvenv.cfg 正常
) else (
  echo [bmcd] 警告：还是没生成 pyvenv.cfg，请检查 Python 安装
)
"%RUNPY%" -c "import sys;print('python', sys.version.split()[0])"
echo [bmcd] 现在可以双击 BMC DHCP.cmd 了。
exit /b 0

:nopython
echo.
echo   没找到 Python 3。
echo   去 https://www.python.org/downloads/windows/ 下载安装，
echo   安装时记得勾上「Add python.exe to PATH」，然后重新打开这个窗口。
echo.
start "" https://www.python.org/downloads/windows/
pause
exit /b 2
