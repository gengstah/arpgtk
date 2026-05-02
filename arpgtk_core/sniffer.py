"""Monitor-side sniffer: tracks AP PN, blocks reflections of our own injects,
optionally writes a (thread-safe) pcap, exposes basic broadcast-rate stats,
and (passively) verifies that AP-from-DS broadcasts decrypt under our GTK
-- a quick "is the GTK actually shared" cross-check.
"""

from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from scapy.all import AsyncSniffer, PcapWriter
from scapy.layers.dot11 import Dot11, Dot11CCMP

from libwifi.crypto import decrypt_ccmp, dot11ccmp_get_pn
from libwifi.wifi import get_ccmp_keyid


class ReflectionFilter:
    """Track recently-injected PNs so the sniffer can ignore them.

    Some drivers loop tx frames back through rx. Without this filter, our
    own injections would bump ap_pn_seen and ratchet our PN further
    forward than the AP actually moved.
    """

    def __init__(self, ttl_seconds: float = 2.0):
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        self._entries: collections.deque[tuple[int, float]] = collections.deque()
        self._set: set[int] = set()

    def add(self, pn: int) -> None:
        with self._lock:
            now = time.monotonic()
            self._entries.append((pn, now + self.ttl))
            self._set.add(pn)
            self._prune(now)

    def is_ours(self, pn: int) -> bool:
        with self._lock:
            self._prune(time.monotonic())
            return pn in self._set

    def _prune(self, now: float) -> None:
        while self._entries and self._entries[0][1] < now:
            pn, _ = self._entries.popleft()
            self._set.discard(pn)


@dataclass
class SniffStats:
    ap_broadcasts_total: int = 0
    ap_broadcasts_recent: int = 0
    last_window_start: float = field(default_factory=time.monotonic)

    def tick(self) -> None:
        self.ap_broadcasts_total += 1
        self.ap_broadcasts_recent += 1

    def rate_per_second(self) -> float:
        now = time.monotonic()
        elapsed = max(now - self.last_window_start, 1e-3)
        rate = self.ap_broadcasts_recent / elapsed
        self.last_window_start = now
        self.ap_broadcasts_recent = 0
        return rate


class LockedPcapWriter:
    """Thread-safe wrapper around scapy's PcapWriter."""

    def __init__(self, path: str, *, link_type=None):
        # append=False so a stale file from a prior run doesn't poison our
        # link-type metadata.
        if link_type is not None:
            self._w = PcapWriter(path, append=False, sync=True, linktype=link_type)
        else:
            self._w = PcapWriter(path, append=False, sync=True)
        self._lock = threading.Lock()

    def write(self, frame) -> None:
        with self._lock:
            try:
                self._w.write(frame)
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            try:
                self._w.close()
            except Exception:
                pass


class GtkSniffer:
    """AsyncSniffer wrapper that tracks AP PN and broadcast rate, and
    optionally tees received frames into a pcap.

    Thread-safety: state is mutated only under self.state_lock. Caller
    passes the lock and a state dict so the inject loop can read
    consistent snapshots.
    """

    def __init__(
        self,
        *,
        mon_iface: str,
        ap_mac: str,
        state: dict,
        state_lock: threading.Lock,
        reflection: ReflectionFilter,
        pcap: LockedPcapWriter | None = None,
        log: Callable[[str], None] = print,
    ):
        self.mon_iface = mon_iface
        self.ap_mac = ap_mac.lower()
        self.state = state
        self.state_lock = state_lock
        self.reflection = reflection
        self.pcap = pcap
        self.log = log
        self.stats = SniffStats()
        self._sniffer: AsyncSniffer | None = None
        # Ambient-decrypt verdict for the "is GTK shared?" cross-check.
        # Set passively as AP-from-DS frames arrive; queried by --verify.
        self._decrypt_successes = 0
        self._decrypt_failures = 0

    def update_ap_mac(self, new_mac: str) -> None:
        self.ap_mac = new_mac.lower()

    def _on_frame(self, frame) -> None:
        try:
            if self.pcap is not None:
                self.pcap.write(frame)

            if not frame.haslayer(Dot11):
                return
            d = frame[Dot11]
            if d.type != 2:
                return

            fc_ds = d.FCfield & 0x03
            protected = bool(d.FCfield & 0x40)
            if fc_ds != 0x02 or not protected:
                return
            if not d.addr2 or d.addr2.lower() != self.ap_mac:
                return
            if not frame.haslayer(Dot11CCMP):
                return

            keyid = get_ccmp_keyid(frame)
            with self.state_lock:
                if keyid != self.state["gtk_idx"]:
                    return
                pn = dot11ccmp_get_pn(frame[Dot11CCMP])
                if self.reflection.is_ours(pn):
                    return
                if pn > self.state["ap_pn_seen"]:
                    self.state["ap_pn_seen"] = pn
                gtk_for_decrypt = self.state["gtk"]
            self.stats.tick()

            # Ambient cross-check: MIC pass = GTK shared, MIC fail = randomized.
            try:
                decrypt_ccmp(frame, gtk_for_decrypt, verify=True)
                self._decrypt_successes += 1
            except Exception:
                self._decrypt_failures += 1
        except Exception:
            pass

    def gtk_shared_verdict(self) -> str:
        """Returns 'shared' (>=1 successful ambient decrypt),
        'randomized' (>=3 MIC failures with no successes),
        or 'unknown' (insufficient samples -- AP probably hasn't broadcast
        anything on our keyid yet)."""
        if self._decrypt_successes > 0:
            return "shared"
        if self._decrypt_failures >= 3:
            return "randomized"
        return "unknown"

    def decrypt_counts(self) -> tuple[int, int]:
        return self._decrypt_successes, self._decrypt_failures

    def start(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.mon_iface,
                                     prn=self._on_frame, store=False)
        self._sniffer.start()
        self.log(f"[+] Sniffer started on {self.mon_iface} "
                 f"(tracking AP={self.ap_mac}, keyid={self.state['gtk_idx']})")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
