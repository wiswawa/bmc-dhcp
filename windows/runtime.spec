# Two entry points, one shared runtime directory. Build on Windows, never cross-freeze.
from pathlib import Path
import os
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
scapy_data, scapy_bins, scapy_hidden = collect_all("scapy")
data = scapy_data + [(str(root / "src/bmcdhcp/ui"), "bmcdhcp/ui")]
settings = dict(pathex=[str(root), str(root / "src")], binaries=scapy_bins, datas=data,
                hiddenimports=scapy_hidden, excludes=["tkinter", "readline"])

gui = Analysis([str(root / "windows/gui_entry.py")], **settings)
console = Analysis([str(root / "windows/cli_entry.py")], **settings)

# Windows 10+ supplies API-set/UCRT OS components. Do not redistribute unrelated
# DLLs copied from the runner's Windows installation.
system_root = Path(os.environ["SystemRoot"]).resolve()
def application_binary(entry):
    name, original, kind = entry
    if Path(name).name.lower().startswith(("api-ms-win-", "ext-ms-win-")):
        return False
    return not Path(original).resolve().is_relative_to(system_root)
gui.binaries = [entry for entry in gui.binaries if application_binary(entry)]
console.binaries = [entry for entry in console.binaries if application_binary(entry)]
(root / "build/windows/native-binaries.toc").write_text(
    repr([*gui.binaries, *console.binaries]), encoding="utf-8")

icon = str(root / "build/windows/AppIcon.ico")
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="BMC DHCP",
              console=False, icon=icon, uac_admin=False)
console_exe = EXE(PYZ(console.pure), console.scripts, [], exclude_binaries=True, name="bmcd",
                  console=True, icon=icon, uac_admin=False)
package = COLLECT(gui_exe, console_exe, gui.binaries, gui.datas,
                  console.binaries, console.datas, name="BMC DHCP")
