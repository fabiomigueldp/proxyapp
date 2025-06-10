#!/usr/bin/env python3
"""
Global bootstrap for mitmproxy (Windows only).

• Verifies Python ≥3.9 and Windows OS
• Elevates itself if not already admin
• Upgrades pip and installs/updates mitmproxy **globally**
• Runs `mitmproxy --install` (fails gracefully if not supported)
• Falls back to an explicit PowerShell Import-Certificate on failure
• Writes start_proxy.bat
• Logs everything to setup_log_YYYYMMDD_HHMMSS.txt
"""

from __future__ import annotations
import ctypes, os, subprocess, sys, textwrap
from datetime import datetime
from pathlib import Path

PY_MIN = (3, 9)
LOG = Path(__file__).with_suffix("").parent / f"setup_log_{datetime.now():%Y%m%d_%H%M%S}.txt"
BATCH = Path(__file__).with_suffix("").parent / "start_proxy.bat"
MAIN  = "advanced_proxy.py"
PORT  = 8080

def log(msg: str):
    print(msg, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now():%H:%M:%S}] {msg}\n")

def run(cmd: list[str] | str):
    log("> " + (cmd if isinstance(cmd, str) else " ".join(cmd)))
    result = subprocess.run(cmd, text=True, shell=isinstance(cmd, str))
    if result.returncode:
        sys.exit(f"❌ Command failed: {cmd}")

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore
    except Exception:
        return False

def elevate():
    log("Requesting administrator privileges…")
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)  # type: ignore
    sys.exit()

def main():
    if os.name != "nt":
        sys.exit("Windows only.")
    if sys.version_info < PY_MIN:
        sys.exit(f"Python {PY_MIN[0]}.{PY_MIN[1]}+ required.")

    if not is_admin():
        elevate()

    log("Upgrading pip and installing mitmproxy globally…")
    run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    run([sys.executable, "-m", "pip", "install", "--upgrade", "mitmproxy"])

    # --- certificate installation ---
    install_ok = False
    try:
        run("mitmproxy --install")   # built-in helper (v8+)
        install_ok = True
    except SystemExit:
        pass  # propagate failures below

    if not install_ok:
        # fall back to explicit PowerShell import (docs and gists)
        ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
        if not ca_path.exists():
            log("First mitmproxy run to generate CA…")
            run("mitmproxy -q")      # generate files, quit immediately
        log("Importing CA via PowerShell…")
        ps = (
            "Import-Certificate -FilePath "
            f"'{ca_path}' "
            "-CertStoreLocation 'cert:\\LocalMachine\\Root'"
        )
        run(["powershell", "-NoProfile", "-Command", ps])

    # --- launcher ---
    BATCH.write_text(
        textwrap.dedent(f"""\
            @echo off
            REM Auto-generated launcher for the Advanced Auditing Proxy
            python "{MAIN}" -p {PORT} %*
        """),
        encoding="utf-8"
    )
    log(f"Created {BATCH}")

    log("✅ All done – launch the proxy with start_proxy.bat")

if __name__ == "__main__":
    main()
