"""Supplicant lifecycle + key extraction.

Spawns wpa_supplicant, waits for the 4-way handshake to complete, and
reads the GTK / TK out of the supplicant via its control interface
(`GET_GTK` and `GET tk`).

Errors raise SupplicantError; the CLI translates them to user-facing
messages.
"""

from __future__ import annotations

import os
import glob
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

import wpaspy


def janitor_stale_tmpdirs(tmp_root: str = "/tmp") -> None:
    """Remove arpgtk-* tempdirs in /tmp older than an hour.

    Covers the SIGKILL-during-run case where atexit / finally cleanup
    didn't fire and a workdir leaked. Ignores anything fresher than 1h
    so we don't yank state out from under a concurrent run.
    """
    now = time.time()
    for path in glob.glob(f"{tmp_root}/arpgtk-*"):
        # Skip arpgtk-tb-* (testbed scratch files) -- those are owned
        # by the testbed and have their own teardown lifecycle.
        if "/arpgtk-tb" in path:
            continue
        try:
            age = now - os.path.getmtime(path)
        except OSError:
            continue
        if age > 3600:
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.unlink(path)
            except OSError:
                pass

from .errors import SupplicantError


@dataclass
class SupplicantConfig:
    iface: str
    ssid: str
    key_mgmt: str = "WPA-PSK"
    psk: Optional[str] = None
    sae_password: Optional[str] = None
    scan_freq: str = "2412"
    bssid: Optional[str] = None
    ieee80211w: Optional[int] = None


@dataclass
class CapturedKeys:
    bssid: str
    tk_hex: str
    gtk_hex: str
    gtk_idx: int
    gtk_seq: int


def _build_supplicant_conf(cfg: SupplicantConfig, ctrl_dir: str,
                           conf_path: str) -> None:
    psk_line = ""
    km = cfg.key_mgmt.upper()
    if km == "WPA-PSK":
        if not cfg.psk:
            raise SupplicantError("--psk is required for key_mgmt=WPA-PSK")
        psk_line = f'\tpsk="{cfg.psk}"\n'
    elif km == "SAE":
        if not (cfg.psk or cfg.sae_password):
            raise SupplicantError("--psk or --sae-password is required for key_mgmt=SAE")
        psk_line = (f'\tsae_password="{cfg.sae_password}"\n'
                    if cfg.sae_password else f'\tpsk="{cfg.psk}"\n')
    elif km == "NONE":
        pass
    else:
        raise SupplicantError(
            f"key_mgmt={cfg.key_mgmt} not supported (extend "
            "_build_supplicant_conf if you need EAP/etc).")

    bssid_line = f"\tbssid={cfg.bssid}\n" if cfg.bssid else ""
    pmf_line = (f"\tieee80211w={cfg.ieee80211w}\n"
                if cfg.ieee80211w is not None else "")

    conf = (
        f"ctrl_interface={ctrl_dir}\n"
        "\n"
        "network={\n"
        f'\tssid="{cfg.ssid}"\n'
        f"\tkey_mgmt={cfg.key_mgmt}\n"
        f"{psk_line}"
        f"{bssid_line}"
        f"{pmf_line}"
        f"\tscan_freq={cfg.scan_freq}\n"
        "}\n"
    )
    with open(conf_path, "w") as f:
        f.write(conf)


def _wait_for_socket(path: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


def _wpaspy_request(ctrl, cmd: str) -> str:
    resp = ctrl.request("> " + cmd)
    while not resp.startswith("> "):
        resp = ctrl.recv()
    return resp[2:]


def _wait_for_connected(ctrl, timeout: float, log) -> str:
    deadline = time.time() + timeout
    bss: Optional[str] = None
    while time.time() < deadline:
        if ctrl.pending(timeout=0.5):
            ev = ctrl.recv()
            log(ev.strip())
            if "Associated with " in ev:
                bss = ev.strip().split("Associated with ")[-1].split()[0]
            if "WPA: Key negotiation completed" in ev or "CTRL-EVENT-CONNECTED" in ev:
                if bss:
                    return bss
    raise SupplicantError(
        f"timed out after {timeout:.0f}s waiting for key negotiation. "
        "Check: PSK matches, SSID is correct, --bssid is on this band, "
        "signal strength via `iw <iface> link`, and that wpa_supplicant "
        "supports the network's auth method.")


class GtkSession:
    """Context manager: run wpa_supplicant, expose CapturedKeys, clean up."""

    def __init__(
        self,
        cfg: SupplicantConfig,
        wpa_supplicant_bin: str,
        debug: int = 0,
        timeout: float = 30.0,
        log=print,
        quiet: bool = False,
    ):
        self.cfg = cfg
        self.bin = wpa_supplicant_bin
        self.debug = debug
        self.timeout = timeout
        self.log = log
        self.quiet = quiet
        self.proc: Optional[subprocess.Popen] = None
        self.ctrl = None
        self.workdir: Optional[str] = None
        self.ctrl_dir: Optional[str] = None
        self.conf_path: Optional[str] = None
        self.keys: Optional[CapturedKeys] = None

    def __enter__(self) -> "GtkSession":
        if not (os.path.isfile(self.bin) and os.access(self.bin, os.X_OK)):
            raise SupplicantError(
                f"wpa_supplicant binary not found or not executable: "
                f"{self.bin}. Run ./build.sh first.")

        self.workdir = tempfile.mkdtemp(prefix="arpgtk-")
        self.ctrl_dir = os.path.join(self.workdir, "wpaspy_ctrl")
        os.makedirs(self.ctrl_dir, exist_ok=True)
        self.conf_path = os.path.join(self.workdir, "supplicant.conf")
        _build_supplicant_conf(self.cfg, self.ctrl_dir, self.conf_path)
        self.log(f"[+] Supplicant config: {self.conf_path}")
        self.log(f"[+] Control dir: {self.ctrl_dir}")

        cmd = [self.bin, "-Dnl80211", "-i", self.cfg.iface,
               "-c", self.conf_path, "-W"]
        if self.debug >= 2:
            cmd.append("-dd")
        elif self.debug == 1:
            cmd.append("-d")
        self.log(f"[+] Launching: {' '.join(cmd)}")

        # Suppress wpa_supplicant's own stdout when --quiet is set, but
        # leave stderr alone so the operator still sees real failures.
        stdout = subprocess.DEVNULL if self.quiet else None
        try:
            self.proc = subprocess.Popen(cmd, stdout=stdout)
        except FileNotFoundError as e:
            self._cleanup()
            raise SupplicantError(f"could not launch {self.bin}: {e}") from e

        ctrl_sock = os.path.join(self.ctrl_dir, self.cfg.iface)
        if not _wait_for_socket(ctrl_sock, timeout=10):
            self._cleanup()
            raise SupplicantError(
                f"control socket {ctrl_sock} did not appear within 10s. "
                "wpa_supplicant probably failed to start. Re-run with -d to "
                "see what it printed.")

        self.ctrl = wpaspy.Ctrl(ctrl_sock)
        self.ctrl.attach()
        self.log("[+] Attached to wpa_supplicant control interface")

        # Wrap the post-Popen logic so any exception (notably the timeout
        # raised by _wait_for_connected) reaches _cleanup() before
        # propagating. Without this, __exit__ is never called -- Python
        # only invokes it when __enter__ returns successfully -- so the
        # supplicant child orphans to init and the workdir leaks.
        try:
            ev_log = (lambda s: None) if self.quiet else (
                lambda s: self.log(f"[supplicant] {s}"))
            bss = _wait_for_connected(self.ctrl, timeout=self.timeout,
                                      log=ev_log)
            self.log(f"[+] Key negotiation complete (BSS: {bss})")

            tk_resp = _wpaspy_request(self.ctrl, "GET tk").strip()
            gtk_resp = _wpaspy_request(self.ctrl, "GET_GTK").strip()
            if "UNKNOWN COMMAND" in tk_resp or "UNKNOWN COMMAND" in gtk_resp:
                raise SupplicantError(
                    "wpa_supplicant did not recognize GET tk / GET_GTK. The "
                    "binary doesn't support these control-interface commands; "
                    "build the bundled wpa_supplicant with ./build.sh and "
                    "re-run.")

            gtk_parts = gtk_resp.split()
            if len(gtk_parts) != 3:
                raise SupplicantError(f"unexpected GET_GTK reply: {gtk_resp!r}")
            gtk_hex, gtk_idx, gtk_seq = gtk_parts

            self.keys = CapturedKeys(
                bssid=bss,
                tk_hex=tk_resp,
                gtk_hex=gtk_hex,
                gtk_idx=int(gtk_idx),
                gtk_seq=int(gtk_seq, 16),
            )
            return self
        except BaseException:
            self._cleanup()
            raise

    def get_status(self) -> dict[str, str]:
        assert self.ctrl is not None
        out = _wpaspy_request(self.ctrl, "STATUS")
        result: dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                result[k.strip()] = v.strip()
        return result

    def watch_events(self, on_rekey=None, on_roam=None) -> None:
        assert self.ctrl is not None
        roam_re = re.compile(
            r"CTRL-EVENT-CONNECTED .* bssid=([0-9a-fA-F:]+)")
        while True:
            if self.ctrl.pending(timeout=1.0):
                ev = self.ctrl.recv()
                if not self.quiet:
                    self.log(f"[supplicant] {ev.strip()}")

                roam_match = roam_re.search(ev)
                if roam_match and on_roam is not None:
                    new_bssid = roam_match.group(1)
                    if new_bssid.lower() != self.keys.bssid.lower():
                        on_roam(new_bssid)
                        self._refresh_keys(new_bssid, on_rekey)

                if ("WPA: Group rekeying completed" in ev
                        or "WPA: Group Key Handshake" in ev):
                    self._refresh_keys(self.keys.bssid, on_rekey)

    def _refresh_keys(self, bssid: str, on_rekey) -> None:
        new = _wpaspy_request(self.ctrl, "GET_GTK").strip()
        parts = new.split()
        if len(parts) != 3:
            return
        gtk_hex, gtk_idx, gtk_seq = parts
        new_keys = CapturedKeys(
            bssid=bssid,
            tk_hex=self.keys.tk_hex,
            gtk_hex=gtk_hex,
            gtk_idx=int(gtk_idx),
            gtk_seq=int(gtk_seq, 16),
        )
        self.keys = new_keys
        if on_rekey is not None:
            on_rekey(new_keys)

    def __exit__(self, exc_type, exc, tb):
        self._cleanup()

    def _cleanup(self) -> None:
        try:
            if self.ctrl is not None:
                self.ctrl.terminate()
        except Exception:
            pass
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
