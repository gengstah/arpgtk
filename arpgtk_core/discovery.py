"""Target-MAC discovery and primitive verification via the managed
interface's bridged ARP-reply path.

When we inject a broadcast ARP request over GTK with `hwsrc=our_mac`,
victims that own `pdst` reply with a unicast Ethernet ARP frame addressed
to our MAC. The AP decrypts that to-DS unicast and bridges it to us
through the managed interface. We sniff the managed iface for ARP frames
matching `dst=our_mac, op=2, psrc=target_ip` -- that's the deterministic
"who answered our probe" signal.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import AsyncSniffer
from scapy.layers.l2 import ARP, Ether


@dataclass
class ArpReply:
    psrc: str   # IP that replied
    hwsrc: str  # MAC behind that IP
    seen_at: float  # monotonic timestamp


class ArpReplyWatcher:
    """Sniffs the managed iface for ARP replies addressed to our MAC.

    Started once at session init; queried per probe via wait_for_reply().
    Records all replies (most recent first) so the operator can see
    candidates ranked when discovery picks one.
    """

    def __init__(self, iface: str, our_mac: str):
        self.iface = iface
        self.our_mac = our_mac.lower()
        self._lock = threading.Lock()
        self._replies: list[ArpReply] = []
        self._sniffer: Optional[AsyncSniffer] = None

    def _on_frame(self, frame) -> None:
        try:
            if not frame.haslayer(ARP) or not frame.haslayer(Ether):
                return
            if frame[Ether].dst.lower() != self.our_mac:
                return
            arp = frame[ARP]
            if arp.op != 2:  # reply
                return
            with self._lock:
                self._replies.append(ArpReply(
                    psrc=arp.psrc, hwsrc=arp.hwsrc.lower(),
                    seen_at=time.monotonic(),
                ))
                if len(self._replies) > 256:
                    self._replies = self._replies[-256:]
        except Exception:
            pass

    def start(self) -> None:
        # BPF filter narrows the kernel-side capture so we don't wake up on
        # every Ethernet frame.
        self._sniffer = AsyncSniffer(
            iface=self.iface, prn=self._on_frame, store=False,
            filter="arp",
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def wait_for_reply(self, target_ip: str, timeout: float) -> Optional[ArpReply]:
        """Block up to `timeout` seconds for an ARP reply with psrc=target_ip.
        Returns the most recent matching reply, or None on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for r in reversed(self._replies):
                    if r.seen_at >= deadline - timeout and r.psrc == target_ip:
                        return r
            time.sleep(0.05)
        return None

    def candidates_in_window(self, window_seconds: float) -> list[ArpReply]:
        """All replies seen in the last `window_seconds`, newest first."""
        now = time.monotonic()
        with self._lock:
            return [r for r in reversed(self._replies)
                    if now - r.seen_at <= window_seconds]
