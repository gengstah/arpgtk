# arpgtk

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An audit tool for the ARP-over-GTK injection primitive on WPA2/WPA3 Wi-Fi.

`arpgtk` answers two questions about a network:

1. **Is this network exposed?** (`--check-gtk-shared`, the default.)
   Associate twice as two different clients, byte-compare the GTKs each
   association receives. Equal => the AP shares one group key across all
   clients, so a malicious associated client can encrypt broadcast frames
   under it and impersonate the AP. Unequal => the AP randomizes per
   client (Passpoint DGAF Disable or equivalent) and the primitive is
   mitigated upstream.
2. **Is a specific victim reachable right now?** (`--verify --target-ip
   IP`.) Send one CCMP-encrypted from-DS broadcast ARP request under the
   GTK with a benign 169.254.x.x requestor IP, and watch the managed
   interface for the bridged unicast ARP reply. If the reply arrives,
   the primitive works against this target.

> **Use only on networks you own or are explicitly authorized to test.**

## Background

The frame architecture, the role of the GTK, and the per-vendor
mitigation landscape are documented in:

- Zhou, Pu, Liu, Qian, Tan, Krishnamurthy, Vanhoef. *AirSnitch:
  Demystifying and Breaking Client Isolation in Wi-Fi Networks.*
  NDSS 2026. <https://papers.mathyvanhoef.com/ndss2026-airsnitch.pdf>
- *Router-side ARP defenses don't catch what they don't see*. The
  motivating post for this tool. Goes through which router-side ARP
  defenses (DAI, IP-MAC binding, ebtables on `br-lan`, MikroTik
  `arp=reply-only`, UniFi "ARP cache poisoning protection",
  MFP/802.11w) the primitive bypasses and why.
  <https://gengstah.github.io/posts/2026/05/arp-over-gtk/>

## Setup

```
git clone https://github.com/gengstah/arpgtk.git
cd arpgtk
sudo pip install -r requirements.txt --break-system-packages
./build.sh
```

The build step compiles a vendored `wpa_supplicant` (BSD-3-Clause,
upstream hostap) with the `GET_GTK` and `GET tk` control-interface
commands `arpgtk` reads from. The default `--wpa-supplicant` points at
`./wpa_supplicant/wpa_supplicant`; you can point it elsewhere if you
already have a build that supports those commands.

System packages (Debian / Ubuntu / Kali names):

- **Build-time** (for `./build.sh`): `build-essential`, `libnl-3-dev`,
  `libnl-genl-3-dev`, `libssl-dev`, `pkg-config`.
- **Runtime**: `iw`.

## Quick start

```
# 1. Is the network exposed?
sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass

# 2. Is this victim reachable right now?
sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass \
    --verify --target-ip 192.168.1.50
```

## Mode 1: `--check-gtk-shared`

Decisive preflight: associate twice on two virtual managed interfaces
on the same phy, byte-compare the GTKs each association receives.

```
sudo ./arpgtk.py \
    --iface wlan0 --ssid mynet --psk mypass
```

Output on a vulnerable network:

```
[+] Comparison iface: wlan0chk (auto-created)
[+] Iface A (wlan0)    -> aa:bb:cc:dd:ee:01
[+] Iface B (wlan0chk) -> aa:bb:cc:dd:ee:01

================ GTK comparison ================
  Iface A  iface=wlan0         MAC=11:22:33:44:55:01
           BSSID=aa:bb:cc:dd:ee:01  idx=1
           GTK=99aabbccddeeff001122334455667788
  Iface B  iface=wlan0chk      MAC=11:22:33:44:55:02
           BSSID=aa:bb:cc:dd:ee:01  idx=1
           GTK=99aabbccddeeff001122334455667788
------------------------------------------------
  RESULT:  GTK IS SHARED across clients.
           Network is exposed to ARP-over-GTK injection.
================================================
```

A `RANDOMIZED` verdict means the AP issues a different GTK per client
and the primitive is dead at the receiver's CCMP MIC check.

## Mode 2: `--verify`

```
sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass \
    --verify --target-ip 192.168.1.50
```

The verify flow:

1. Associate `wpa_supplicant` on `--iface`, capture GTK / `gtk_idx` /
   BSSID via `GET_GTK`.
2. Auto-create `wlan0mon` on the same phy and align its channel to the
   AP.
3. Sniff AP broadcasts on our `gtk_idx` for `--pn-sample-window` (1.5s
   default) to learn the AP's current PN. If no broadcasts arrive in
   that window, fall back to `max(safe-high default, --pn-offset)`.
4. Pick probe PN as `ap_pn_seen + --pn-offset` (default offset 4) when
   a sample exists, otherwise the fallback above.
5. Build one ARP request: `op=1, hwsrc=our-mac, psrc=169.254.x.x
   (benign), pdst=--target-ip`. Wrap it in a from-DS broadcast 802.11
   frame, CCMP-encrypt with the GTK at the chosen PN.
6. Inject once on the monitor iface. Watch the managed iface for a
   bridged unicast ARP reply matching `psrc=--target-ip`.
7. Print the verdict and tear down.

Output on a viable target:

```
[+] Associated: BSSID=aa:bb:cc:dd:ee:01, GTK idx=1, our MAC=11:22:33:44:55:01
[+] Monitor iface wlan0mon on channel 6 (auto-created).
[+] Sampling AP broadcast PN on keyid=1 for 1.5s...
[+] AP last broadcast PN=0x4a2f; probe PN=0x4a33 (offset=4).
[+] Probing 192.168.1.50 from 169.254.92.41...

================ Verify result ================
  RESULT:  192.168.1.50 replied with hwsrc=aa:bb:cc:dd:ee:50.
           Primitive is viable against this target.
================================================
[+] Tore down wlan0mon
```

A "no reply" verdict can mean the GTK is randomized per client (CCMP
MIC fails at the receiver, run `--check-gtk-shared` to confirm), the
probe PN was below the AP's current broadcast PN (raise `--pn-offset`),
the monitor iface ended up on the wrong channel (check
`iw <mon-iface> info`), the driver silently dropped the transmit at the
firmware, RF doesn't reach the victim, or the target is offline / on a
different VLAN / firewalling ARP. Vendor "client isolation" knobs (P2P
Blocking, LANCOM, Aruba) are bridge-side; they don't affect this probe
because the probe doesn't cross the bridge.

By default arpgtk learns the victim's MAC from the reply (auto-discovery). If you already know the MAC, pass it via `--target-mac` to skip that step. arpgtk cross-checks the asserted MAC against the reply's hwsrc and warns if another host owns this IP on the network.

If your target is an iPhone, recent Android, or other strict-stack device that won't reply to ARP requests with off-subnet `psrc`, override the link-local default with `--probe-src-ip <ip-in-target-subnet>` (typically the gateway). The trade-off is a brief `(probe-src-ip, our-mac)` cache entry on the target while it processes the request.

```
sudo ./arpgtk.py --iface wlan0 --ssid mynet --psk mypass \
    --verify --target-ip 192.168.1.50 --target-mac aa:bb:cc:dd:ee:50
```

## Full flag reference

### Required

| Flag | Purpose |
| --- | --- |
| `--iface IFACE` | Managed-mode wireless interface for `wpa_supplicant`. |
| `--ssid SSID` | Target SSID. |

### Required (mode-dependent)

| When | Flag | Purpose |
| --- | --- | --- |
| `WPA-PSK` (default) | `--psk PSK` | PSK / passphrase. |
| `SAE` | `--psk` or `--sae-password` | Either is accepted. |
| `--verify` | `--target-ip IP` | Victim IP. |

### Supplicant / association

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mon-iface NAME` | `<iface>[:12]+mon` | Auto-created monitor iface name (used by `--verify`). |
| `--chk-iface NAME` | `<iface>[:12]+chk` | Second managed iface name (used by `--check-gtk-shared`). |
| `--key-mgmt MODE` | `WPA-PSK` | Also `SAE`, `NONE`. |
| `--sae-password PW` | _(none)_ | Alternative to `--psk` for SAE. |
| `--scan-freq MHZ` | `2412` | Hint for the supplicant scan. Operating channel detected post-association. |
| `--bssid AA:BB:..` | _(none)_ | Pin association to a specific BSSID. |
| `--ieee80211w {0,1,2}` | _(none)_ | PMF override. |
| `--wpa-supplicant PATH` | `./wpa_supplicant/wpa_supplicant` (built by `./build.sh`) | Override the wpa_supplicant binary. The default file doesn't exist until you've run `./build.sh`. |
| `--timeout SEC` | `30` | Seconds to wait for key negotiation. |
| `--quiet` | off | Suppress `wpa_supplicant CTRL-EVENT` chatter once associated. |
| `--supplicant-debug` (repeatable) | 0 | Pass `-d`/`-dd` to wpa_supplicant. |

### Modes

| Flag | Default | Purpose |
| --- | --- | --- |
| _(none)_ | on | Default mode is `--check-gtk-shared`. |
| `--verify` | off | Probe-and-reply against `--target-ip`. |
| `--target-ip IP` | _(none)_ | Victim IP for `--verify`. |
| `--target-mac MAC` | auto-discover from reply | Skip learning the victim's MAC from the reply by passing it directly. Also cross-checked against the reply's hwsrc. |
| `--probe-src-ip IP` | random `169.254.x.x` link-local | Override the requestor IP in the verify probe. Pass an IP in the target's subnet (e.g. the gateway) for stricter stacks (iOS, recent Android) that drop ARP requests with off-subnet psrc. |

### Verify probe tuning

| Flag | Default | Purpose |
| --- | --- | --- |
| `--pn-offset N` | `4` | PNs above the AP's last sniffed broadcast PN to send the probe at. Bump if receivers reject the frame as a replay. Doubles as a minimum PN when the sample window finds no AP broadcasts. Accepts hex (`0x...`). |
| `--pn-sample-window SEC` | `1.5` | Seconds to sniff AP broadcasts before injecting the probe, used to learn the AP's current PN. If no broadcasts arrive in this window, fall back to a safe-high default PN. |
| `--pcap PATH` | off | Write sniffed monitor-iface frames + the injected probe to `PATH` (link-type 127, IEEE802_11_RADIOTAP). For offline analysis when `--verify` reports no reply. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `--check-gtk-shared`: GTK shared (network exposed). `--verify`: target replied (viable). |
| `1` | Error / unexpected exit. |
| `2` | `--check-gtk-shared`: GTK randomized (mitigated). `--verify`: no reply (probably mitigated, but read the output). |
| `3` | Inconclusive (BSSID mismatch, supplicant timeout, etc). |
| `130` | User cancelled (Ctrl-C). |

## Diagnosing a "no reply" verdict

When `--verify` reports no reply and you suspect the network is exposed, work down this list:

1. **Wake the target** if it's a phone or a laptop in suspend. iOS and recent Android put the Wi-Fi NIC into power-save when the screen is off and miss our single-shot injection.
2. **Pin the requestor IP** with `--probe-src-ip <gateway-ip>`. Strict stacks (iOS, recent Android, locked-down embedded) drop ARP requests whose `psrc` isn't in the receiving subnet.
3. **Raise `--pn-offset`**. On a busy AP that's been up for a long time, the AP's broadcast PN can be well above `0x100000`. Try `--pn-offset 0x1000000` or higher; accepts hex.
4. **Capture with `--pcap`** and open in Wireshark with the GTK loaded (Edit → Preferences → Protocols → IEEE 802.11 → Decryption keys, add `wpa-pwd:<psk>:<ssid>` or `wpa-psk:<32-byte-hex>`). Look for:
   - AP broadcasts on our `keyid` during the sample window (proves the AP is using a shared GTK at all).
   - Our injected frame visible on the air with a CCMP MIC that Wireshark accepts under the loaded GTK.
   - Any reply from the target (it will appear on the bridged path through the AP, not the monitor capture, so check the managed iface separately if needed).
5. **Run `--check-gtk-shared`** with a second card. If the verdict is `RANDOMIZED`, the network has per-client GTK and the primitive is mitigated. No further work helps until you find a different test target.
6. **Try a Linux victim instead.** Linux's ARP stack is permissive (replies regardless of `psrc` subnet, no PSM games). A Linux victim's reply or non-reply gives a much cleaner signal than an iPhone.

## Cleanup

Everything `arpgtk` creates is restored on every exit path (clean exit,
Ctrl-C, SIGTERM, SIGHUP, exception):

- The `wlan0chk` virtual managed interface created for `--check-gtk-shared`.
- The `wlan0mon` virtual monitor interface created for `--verify`.
- The `wpa_supplicant` child processes spawned by either mode.
- The temporary control-interface directories under `/tmp/arpgtk-*`.

If a previous run was killed with `SIGKILL` and left tempdirs behind,
they're cleaned up automatically on the next run (the janitor only
touches dirs older than one hour).

## Testbed

`testbed.sh` brings up a self-contained `mac80211_hwsim`-based test
network so you can exercise arpgtk without real Wi-Fi hardware.

```
sudo ./testbed.sh         # bring up
sudo ./testbed.sh --down  # tear down
```

When ready you'll have:

- **`br0`** (`192.168.99.1/24`, gateway, dnsmasq DHCP `192.168.99.10-99`)
- **`wlan0`** AP iface bridged into br0 (hostapd, channel 1,
  SSID=`testnetwork`, PSK=`passphrase`)
- **`wlan1`** victim STA, associated, DHCP-leased
- **`wlan2`** attacker iface. Pass to arpgtk
- **`wlan3`** spare

Run arpgtk against it:

```
# Mode 1: GTK-shared check
sudo ./arpgtk.py --iface wlan2 --ssid testnetwork --psk passphrase

# Mode 2: verify against the testbed victim
sudo ./arpgtk.py --iface wlan2 --ssid testnetwork --psk passphrase \
    --verify --target-ip <wlan1 IP, see testbed output>
```

## Integration tests

```
sudo ./testbed.sh
sudo ./test-integration.sh
```

Exercises every flag/mode end-to-end against the testbed:

| # | Test | What it covers | Result |
| --- | --- | --- | --- |
| T1 | `--verify` without `--target-ip` rejected | startup validation | PASS |
| T2 | `--verify` with malformed IP rejected | startup validation | PASS |
| T3 | Invalid `--iface` rejected | startup validation | PASS |
| T4 | `--version` prints | version flag | PASS |
| T5 | `--check-gtk-shared` (default chk-iface) | dual association + GTK byte-compare | PASS |
| T6 | `--chk-iface` custom name | iface override | PASS |
| T7 | `--bssid` pin associates and reports SHARED | supplicant config plumbing | PASS |
| T8 | `--ieee80211w 0` (PMF off) still associates | PMF override | PASS |
| T9 | `--supplicant-debug -dd` passes through | wpa_supplicant arg flow | PASS |
| T10 | `--verify` against live victim | bridged STA-to-attacker reply path | PASS |
| T11 | `--verify` against unassigned IP times out | exit-code-2 path | PASS |
| T12 | `--pn-sample-window` honored | PN sampling window override | PASS |
| T13 | `--mon-iface` custom name | iface override | PASS |
| T14 | Cleanup completeness | 0 tempdirs / 0 supplicants / 0 ifaces leaked | PASS |

One caveat for hwsim:

- `mac80211_hwsim` accumulates CCMP replay-window state across
  sequential associations. If you re-run the suite back-to-back and a
  late test flakes (`--verify` reports no reply with everything else
  green), run `sudo ./testbed.sh --down && sudo ./testbed.sh` and
  retry; that flushes the kernel-side state. Real hardware does not
  exhibit this.

## License

BSD-3-Clause. See `LICENSE`.

The vendored `wpa_supplicant/` and `src/` trees are upstream hostap
under BSD-3-Clause. `libwifi/` is Mathy Vanhoef's library under
BSD-3-Clause. `wpaspy.py` is Jouni Malinen's under BSD-3-Clause.
