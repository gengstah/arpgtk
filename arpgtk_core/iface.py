"""Monitor-interface lifecycle, channel detection, and Wi-Fi iface validation."""

from __future__ import annotations

import os
import re
import subprocess

from .errors import IfaceError


MAX_IFACE_NAME_LEN = 15  # Linux kernel limit


def iface_exists(iface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{iface}")


def get_iface_mac(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def freq_to_channel(freq_mhz: int) -> int:
    if 2412 <= freq_mhz <= 2484:
        return 14 if freq_mhz == 2484 else (freq_mhz - 2407) // 5
    if 5170 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    raise ValueError(f"cannot map frequency {freq_mhz} MHz to a channel")


def get_iface_freq(iface: str) -> int | None:
    try:
        out = subprocess.check_output(["iw", iface, "info"], text=True)
    except subprocess.CalledProcessError:
        return None
    m = re.search(r"channel\s+\d+\s+\((\d+)\s*MHz\)", out)
    return int(m.group(1)) if m else None


def get_iface_type(iface: str) -> str | None:
    """Return 'managed', 'monitor', etc, or None if iface isn't a Wi-Fi iface."""
    try:
        out = subprocess.check_output(["iw", iface, "info"],
                                      text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    m = re.search(r"^\s*type\s+(\w+)", out, re.MULTILINE)
    return m.group(1) if m else None


def validate_managed_iface(iface: str) -> None:
    """Raise IfaceError if `iface` isn't a managed-mode Wi-Fi interface."""
    if not iface_exists(iface):
        avail = " ".join(sorted(os.listdir("/sys/class/net")))
        raise IfaceError(
            f"--iface {iface} not found. Available interfaces: {avail}")
    t = get_iface_type(iface)
    if t is None:
        raise IfaceError(
            f"--iface {iface} exists but isn't a Wi-Fi interface "
            "(`iw <iface> info` failed). Pass a wireless NIC.")
    if t != "managed":
        raise IfaceError(
            f"--iface {iface} is type '{t}'; needs to be 'managed' for "
            "wpa_supplicant to associate. Try `iw dev {iface} set type "
            "managed && ip link set {iface} up`.")


def validate_iface_name(name: str) -> None:
    if len(name) > MAX_IFACE_NAME_LEN:
        raise IfaceError(
            f"interface name '{name}' exceeds Linux's {MAX_IFACE_NAME_LEN}-char "
            "limit. Pick a shorter --mon-iface.")
    if not re.match(r"^[A-Za-z0-9_.-]+$", name):
        raise IfaceError(
            f"interface name '{name}' contains characters that ip/iw won't "
            "accept. Stick to letters, digits, _ . -.")


def set_iface_channel(iface: str, channel: int, *, width: str = "HT20") -> None:
    subprocess.check_call(
        ["iw", "dev", iface, "set", "channel", str(channel), width])


def setup_monitor(phy_iface: str, mon_iface: str) -> bool:
    """Create mon_iface on the same phy as phy_iface (if missing) and bring it up.

    Returns True if we created it, False if it already existed.
    Raises IfaceError on failure.
    """
    validate_iface_name(mon_iface)
    if iface_exists(mon_iface):
        out = subprocess.check_output(["iw", mon_iface, "info"], text=True)
        if "type monitor" not in out:
            raise IfaceError(
                f"{mon_iface} already exists but is not in monitor mode. "
                f"Pick a different --mon-iface or remove it first "
                f"(`iw dev {mon_iface} del`).")
        subprocess.check_call(["ip", "link", "set", mon_iface, "up"])
        return False
    try:
        subprocess.check_call(
            ["iw", "dev", phy_iface, "interface", "add", mon_iface,
             "type", "monitor"])
    except subprocess.CalledProcessError as e:
        raise IfaceError(
            f"could not create monitor interface {mon_iface} on {phy_iface}: "
            f"{e}. Does --iface exist and support a managed+monitor virtual-"
            "iface combo on one phy?") from e
    # Many drivers (mac80211_hwsim, most modern adapters) require the
    # monitor iface in "active" mode for the radio to actually transmit
    # injected frames -- in passive mode the kernel forms the frames but
    # the radio never puts them on the air. Try to enable active mode
    # here while the iface is still down. If the driver doesn't support
    # it we surface a warning; sniffing will still work but injection
    # reliability varies.
    try:
        subprocess.check_call(
            ["iw", "dev", mon_iface, "set", "monitor", "active"],
            stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        import sys
        print(f"[!] {mon_iface}: driver rejected `set monitor active`; "
              "injection may be unreliable on this driver.",
              file=sys.stderr)
    subprocess.check_call(["ip", "link", "set", mon_iface, "up"])
    return True


def setup_managed_vif(phy_iface: str, vif_name: str) -> bool:
    """Create a second managed-mode virtual iface on the same phy as
    phy_iface (if missing) and bring it up.

    Used by --check-gtk-shared to associate twice with two different MACs
    and compare the GTKs each association receives.

    Returns True if we created it, False if it already existed.
    Raises IfaceError on failure.
    """
    validate_iface_name(vif_name)
    if iface_exists(vif_name):
        out = subprocess.check_output(["iw", vif_name, "info"], text=True)
        if "type managed" not in out:
            raise IfaceError(
                f"{vif_name} already exists but is not in managed mode. "
                f"Pick a different --chk-iface or remove it first "
                f"(`iw dev {vif_name} del`).")
        subprocess.check_call(["ip", "link", "set", vif_name, "up"])
        return False
    try:
        subprocess.check_call(
            ["iw", "dev", phy_iface, "interface", "add", vif_name,
             "type", "managed"])
    except subprocess.CalledProcessError as e:
        raise IfaceError(
            f"could not create managed vif {vif_name} on {phy_iface}: {e}. "
            "Some drivers don't allow multiple managed interfaces on one "
            f"phy; check `iw phy $(cat /sys/class/net/{phy_iface}/phy80211/"
            "name) info` for valid interface combinations. Workaround: "
            "pass --chk-iface pointing at a separate physical NIC.") from e
    # Some drivers (rt2800usb, most Realtek/Intel chipsets) accept the
    # `iw add` with exit 0 but never actually register the new netdev,
    # because their valid-interface-combinations table doesn't allow
    # concurrent managed vifs on a single phy. Catch that gap here and
    # raise the same IfaceError instead of letting the next `ip link
    # set` die on "Cannot find device".
    if not iface_exists(vif_name):
        raise IfaceError(
            f"`iw add {vif_name}` succeeded but the netdev never "
            f"appeared. The driver on phy {phy_iface} does not support "
            "multiple concurrent managed virtual interfaces on a single "
            "phy (rt2800usb, most Realtek RTLxxx and Intel iwlwifi "
            "behave this way). Confirm with "
            f"`iw phy $(cat /sys/class/net/{phy_iface}/phy80211/name) "
            "info | grep -A5 'valid interface combinations'`. Workaround: "
            "use a second physical NIC and pass --chk-iface <its_name>.")
    try:
        subprocess.check_call(["ip", "link", "set", vif_name, "up"])
    except subprocess.CalledProcessError as e:
        raise IfaceError(
            f"`iw add {vif_name}` succeeded but `ip link set {vif_name} "
            f"up` failed: {e}. The driver may have registered a stub "
            "netdev that can't be brought up. Workaround: use a second "
            "physical NIC and pass --chk-iface <its_name>.") from e
    return True


def teardown_vif(vif_name: str) -> None:
    """Bring down and delete a virtual iface we created. No-op if missing."""
    if not iface_exists(vif_name):
        return
    try:
        subprocess.call(["ip", "link", "set", vif_name, "down"])
        subprocess.call(["iw", "dev", vif_name, "del"])
    except Exception:
        pass


def detect_and_align_channel(phy_iface: str, mon_iface: str,
                             *, log=print) -> int | None:
    freq = get_iface_freq(phy_iface)
    if freq is None:
        log(f"[!] Could not read channel from {phy_iface}; leaving "
            f"{mon_iface} on whatever channel the driver picked.")
        return None
    try:
        ch = freq_to_channel(freq)
    except ValueError as e:
        log(f"[!] {e}; leaving {mon_iface} alone.")
        return None
    mon_freq = get_iface_freq(mon_iface)
    if mon_freq == freq:
        log(f"[+] {mon_iface} already on channel {ch} ({freq} MHz).")
        return ch
    try:
        set_iface_channel(mon_iface, ch)
        log(f"[+] Forced {mon_iface} to channel {ch} ({freq} MHz) "
            f"to match {phy_iface}.")
    except subprocess.CalledProcessError as e:
        log(f"[!] Could not set {mon_iface} to channel {ch}: {e}")
        return None
    return ch


def detect_default_gateway(iface: str) -> str | None:
    """Read the default gateway IP for `iface` from `ip route`. Returns None
    if no default route is set yet (e.g., no DHCP lease)."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "show", "default", "dev", iface], text=True)
    except subprocess.CalledProcessError:
        return None
    m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def get_iface_ip(iface: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "dev", iface], text=True)
    except subprocess.CalledProcessError:
        return None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
    return m.group(1) if m else None
