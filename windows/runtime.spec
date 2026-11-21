# Two entry points, one shared runtime directory. Build on Windows, never cross-freeze.
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
scapy_data, scapy_bins, scapy_hidden = collect_all("scapy")
data = scapy_data + [(str(root / "src/bmcdhcp/ui"), "bmcdhcp/ui")]
settings = dict(pathex=[str(root), str(root / "src")], binaries=scapy_bins, datas=data,
                hiddenimports=scapy_hidden, excludes=["tkinter", "readline"])

gui = Analysis([str(root / "windows/gui_entry.py")], **settings)
console = Analysis([str(root / "windows/cli_entry.py")], **settings)
icon = str(root / "build/windows/AppIcon.ico")
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="BMC DHCP",
              console=False, icon=icon, uac_admin=False)
console_exe = EXE(PYZ(console.pure), console.scripts, [], exclude_binaries=True, name="bmcd",
                  console=True, icon=icon, uac_admin=False)
package = COLLECT(gui_exe, console_exe, gui.binaries, gui.datas,
                  console.binaries, console.datas, name="BMC DHCP")
