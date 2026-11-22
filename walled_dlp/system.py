"""Connect the browser to Walled DLP, and disconnect it again.

Two changes, both per user and both undone by `walled-dlp setup --undo`:

1. Trust the local CA, so the browser accepts the proxy's certificates for the monitored sites.
     Linux    the NSS databases Chrome/Chromium (~/.pki/nssdb) and Firefox use, via `certutil`
     macOS    the login keychain, via `security add-trusted-cert` (macOS asks for your password)
     Windows  the current user's Root store, via `certutil -user` (Windows asks you to confirm)
2. Point the system proxy settings at a proxy auto-config (PAC) script. The PAC sends only the
   monitored hosts to the proxy; all other traffic stays direct.
     Linux    GNOME (gsettings) or KDE (kioslaverc), which Chrome, Edge and Brave follow. The PAC is
              installed inline as a data: URL, so if Walled DLP isn't running the monitored sites
              fail to load rather than bypassing inspection.
     macOS    every network service's "Automatic proxy configuration" (networksetup)
     Windows  the user's Internet Settings AutoConfigURL, which Chrome and Edge follow
     (on macOS and Windows the PAC is fetched from http://127.0.0.1:<port>/proxy.pac)

The previous proxy settings are saved and put back on undo.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .certs import CA_NAME, CertificateAuthority
from .config import data_dir

log = logging.getLogger(__name__)


@dataclass
class Step:
    what: str
    ok: bool
    detail: str = ""

    def __str__(self) -> str:
        mark = "ok  " if self.ok else "TODO"
        return f"[{mark}] {self.what}" + (f"\n       {self.detail}" if self.detail else "")


def _state_path() -> Path:
    return data_dir() / "system-state.json"


def _load_state() -> dict:
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    log.info("running %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        proc = subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timed out")
    if check and proc.returncode:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"{cmd[0]} failed")
    return proc


# -- certificate trust ---------------------------------------------------------------------------
CHROME_IMPORT_HINT = (
    "Or import it by hand in Chrome: Settings > Privacy and security > Security > Manage certificates > "
    "Local certificates > Custom > Installed by you > Import (tick 'Trust for identifying websites')."
)


def nss_databases() -> list[Path]:
    home = Path.home()
    dbs = [home / ".pki" / "nssdb"]
    for pattern in (".mozilla/firefox/*/cert9.db", "snap/firefox/common/.mozilla/firefox/*/cert9.db", "snap/chromium/current/.pki/nssdb/cert9.db"):
        dbs.extend(Path(p).parent for p in glob.glob(str(home / pattern)))
    return list(dict.fromkeys(dbs))


def trust_ca(ca: CertificateAuthority) -> Step:
    path = str(ca.cert_path)
    if sys.platform == "darwin":
        keychain = str(Path.home() / "Library/Keychains/login.keychain-db")
        proc = _run(["security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, path])
        return Step("Trust the Walled DLP certificate (login keychain)", proc.returncode == 0, proc.stderr.strip())
    if sys.platform == "win32":
        proc = _run(["certutil", "-user", "-f", "-addstore", "Root", path])
        return Step("Trust the Walled DLP certificate (Windows user store)", proc.returncode == 0, proc.stdout.strip()[-300:] if proc.returncode else "")
    if not shutil.which("certutil"):
        return Step(
            "Trust the Walled DLP certificate",
            False,
            "`certutil` is missing. Install it (Debian/Ubuntu: sudo apt install libnss3-tools; Fedora: sudo dnf install nss-tools) "
            f"and run `walled-dlp setup` again. {CHROME_IMPORT_HINT} The certificate is {path}",
        )
    done, failed = [], []
    for db in nss_databases():
        if not (db / "cert9.db").exists():
            if db != Path.home() / ".pki" / "nssdb":
                continue
            db.mkdir(parents=True, exist_ok=True)
            _run(["certutil", "-N", "-d", f"sql:{db}", "--empty-password"])
        proc = _run(["certutil", "-d", f"sql:{db}", "-A", "-t", "C,,", "-n", CA_NAME, "-i", path])
        (done if proc.returncode == 0 else failed).append(str(db))
    detail = f"added to {', '.join(done)}" if done else ""
    if failed:
        detail += f"; failed for {', '.join(failed)}"
    return Step("Trust the Walled DLP certificate (NSS: Chrome, Chromium, Firefox)", bool(done), detail.strip("; "))


def untrust_ca(ca: CertificateAuthority) -> Step:
    if sys.platform == "darwin":
        _run(["security", "remove-trusted-cert", str(ca.cert_path)])
        proc = _run(["security", "delete-certificate", "-c", CA_NAME, str(Path.home() / "Library/Keychains/login.keychain-db")])
        return Step("Remove the Walled DLP certificate", proc.returncode in (0, 44))
    if sys.platform == "win32":
        proc = _run(["certutil", "-user", "-delstore", "Root", CA_NAME])
        return Step("Remove the Walled DLP certificate", proc.returncode == 0)
    if not shutil.which("certutil"):
        return Step("Remove the Walled DLP certificate", False, "certutil is missing; remove it in your browser's certificate settings")
    for db in nss_databases():
        if (db / "cert9.db").exists():
            while _run(["certutil", "-d", f"sql:{db}", "-D", "-n", CA_NAME]).returncode == 0:
                pass  # remove every copy
    return Step("Remove the Walled DLP certificate", True)


def ca_trusted(ca: CertificateAuthority) -> bool | None:
    """True/False where it can be checked cheaply, None where it can't."""
    if sys.platform.startswith("linux") and shutil.which("certutil"):
        db = Path.home() / ".pki" / "nssdb"
        return _run(["certutil", "-d", f"sql:{db}", "-L", "-n", CA_NAME]).returncode == 0
    if sys.platform == "darwin":
        return _run(["security", "find-certificate", "-c", CA_NAME]).returncode == 0
    if sys.platform == "win32":
        return _run(["certutil", "-user", "-verifystore", "Root", CA_NAME]).returncode == 0
    return None


# -- proxy settings ------------------------------------------------------------------------------
def _desktop() -> str:
    return os.environ.get("XDG_CURRENT_DESKTOP", "").lower()


def _kwrite() -> str | None:
    return shutil.which("kwriteconfig6") or shutil.which("kwriteconfig5")


def _kread() -> str | None:
    return shutil.which("kreadconfig6") or shutil.which("kreadconfig5")


def _gsettings_get(key: str) -> str:
    return _run(["gsettings", "get", "org.gnome.system.proxy", key]).stdout.strip().strip("'")


def _mac_services() -> list[str]:
    out = _run(["networksetup", "-listallnetworkservices"]).stdout.splitlines()[1:]
    return [s for s in out if s and not s.startswith("*")]


def set_system_proxy(pac_url: str) -> Step:
    state = _load_state()
    previous = state.get("previous_proxy")
    if sys.platform == "darwin":
        saved = {}
        for svc in _mac_services():
            out = _run(["networksetup", "-getautoproxyurl", svc]).stdout
            url = next((l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("URL:")), "")
            enabled = "Enabled: Yes" in out
            saved[svc] = {"url": url if url != "(null)" else "", "enabled": enabled}
            _run(["networksetup", "-setautoproxyurl", svc, pac_url], check=True)
            _run(["networksetup", "-setautoproxystate", svc, "on"], check=True)
        previous = previous or {"kind": "macos", "services": saved}
        result = Step("Route ChatGPT and Perplexity through Walled DLP (macOS network services)", bool(saved))
    elif sys.platform == "win32":
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                old = winreg.QueryValueEx(key, "AutoConfigURL")[0]
            except FileNotFoundError:
                old = None
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        _refresh_wininet()
        previous = previous or {"kind": "windows", "url": old}
        result = Step("Route ChatGPT and Perplexity through Walled DLP (Windows Internet Settings)", True)
    elif "kde" in _desktop() and _kwrite():
        kread = _kread()
        old = {}
        if kread:
            for k in ("ProxyType", "Proxy Config Script"):
                old[k] = _run([kread, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k]).stdout.strip()
        kw = _kwrite()
        _run([kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "2"], check=True)
        _run([kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "Proxy Config Script", pac_url], check=True)
        previous = previous or {"kind": "kde", "values": old}
        result = Step("Route ChatGPT and Perplexity through Walled DLP (KDE proxy settings)", True)
    elif shutil.which("gsettings"):
        old = {"mode": _gsettings_get("mode"), "autoconfig-url": _gsettings_get("autoconfig-url")}
        _run(["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pac_url], check=True)
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", "auto"], check=True)
        previous = previous or {"kind": "gnome", "values": old}
        result = Step("Route ChatGPT and Perplexity through Walled DLP (GNOME proxy settings)", True)
    else:
        return Step(
            "Route ChatGPT and Perplexity through Walled DLP",
            False,
            "No supported proxy settings found. Set your browser's automatic proxy configuration URL to "
            "http://127.0.0.1:<port>/proxy.pac (default port 8899), or start Chrome with --proxy-pac-url=<that URL>.",
        )
    state["previous_proxy"] = previous
    state["pac_url"] = pac_url
    _save_state(state)
    return result


def restore_system_proxy() -> Step:
    state = _load_state()
    previous = state.pop("previous_proxy", None)
    state.pop("pac_url", None)
    if not previous:
        return Step("Restore proxy settings", True, "nothing to restore")
    kind = previous.get("kind")
    if kind == "macos":
        for svc, old in previous["services"].items():
            if old["url"]:
                _run(["networksetup", "-setautoproxyurl", svc, old["url"]])
            _run(["networksetup", "-setautoproxystate", svc, "on" if old["enabled"] else "off"])
    elif kind == "windows":
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as key:
            if previous.get("url"):
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, previous["url"])
            else:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
        _refresh_wininet()
    elif kind == "kde":
        kw = _kwrite()
        if kw:
            for k, v in previous["values"].items():
                _run([kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k, v or ("0" if k == "ProxyType" else "")])
    elif kind == "gnome":
        old = previous["values"]
        _run(["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", old.get("autoconfig-url", "")])
        _run(["gsettings", "set", "org.gnome.system.proxy", "mode", old.get("mode") or "none"])
    _save_state(state)
    return Step("Restore the previous proxy settings", True)


def _refresh_wininet() -> None:
    """Tell running browsers that the Internet Settings changed."""
    try:
        import ctypes

        internet_set_option = ctypes.windll.wininet.InternetSetOptionW  # type: ignore[attr-defined]
        internet_set_option(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        log.exception("could not notify WinINet")


def proxy_configured(port: int) -> bool:
    pac_url = pac_url_for(port)
    if sys.platform.startswith("linux") and "kde" not in _desktop() and shutil.which("gsettings"):
        return _gsettings_get("mode") == "auto" and _gsettings_get("autoconfig-url") == pac_url
    return _load_state().get("pac_url") == pac_url


# -- app launcher --------------------------------------------------------------------------------
def launcher_path() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "applications" / "walled-dlp.desktop"


def install_launcher() -> Step:
    """Add Walled DLP to the desktop's application menu (Linux: a freedesktop .desktop entry)."""
    if not sys.platform.startswith("linux"):
        return Step("Add Walled DLP to the app menu", False, "Only Linux is supported; run `walled-dlp` (or the walled-dlp-app script) instead.")
    from importlib import resources

    exe = Path(sys.argv[0]).resolve() if Path(sys.argv[0]).name.startswith("walled-dlp") else None
    command = f'"{exe}" app' if exe else f'"{sys.executable}" -m walled_dlp app'
    icon = resources.files("walled_dlp.assets").joinpath("icon.png")
    path = launcher_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Walled DLP\n"
        "Comment=Check prompts and uploads to ChatGPT and Perplexity for sensitive content\n"
        f"Exec={command}\n"
        f"Icon={icon}\n"
        "Terminal=false\n"
        "Categories=Network;Security;Utility;\n"
        "StartupWMClass=Walled-dlp\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    _run(["update-desktop-database", str(path.parent)])
    return Step("Add Walled DLP to the app menu", True, str(path))


def remove_launcher() -> Step:
    path = launcher_path()
    path.unlink(missing_ok=True)
    return Step("Remove Walled DLP from the app menu", True, str(path))


# -- entry points --------------------------------------------------------------------------------
def pac_url_for(port: int) -> str:
    from .policy import pac_data_url

    if sys.platform.startswith("linux"):
        return pac_data_url(port)
    return f"http://127.0.0.1:{port}/proxy.pac"


def setup(ca: CertificateAuthority, port: int) -> list[Step]:
    return [trust_ca(ca), set_system_proxy(pac_url_for(port))]


def undo(ca: CertificateAuthority) -> list[Step]:
    return [restore_system_proxy(), untrust_ca(ca)]
