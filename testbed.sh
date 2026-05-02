#!/bin/bash
# testbed.sh -- spin up a mac80211_hwsim-based test network for arpgtk.
#
# Layout once ready:
#   br0    192.168.99.1/24    bridge + DHCP server (dnsmasq)
#   wlan0  AP                 hostapd, channel 1, SSID=testnetwork, PSK=passphrase
#   wlan1  victim STA         associates + DHCP-leased
#   wlan2  attacker iface     point arpgtk here
#   wlan3  spare              free for additional STAs
#
# Usage:
#   sudo ./testbed.sh         # bring up
#   sudo ./testbed.sh --down  # tear down
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Run as root: sudo $0 [--down]"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BR=br0
GATEWAY=192.168.99.1
DHCP_RANGE_LO=192.168.99.10
DHCP_RANGE_HI=192.168.99.99
DOMAIN_NETMASK=255.255.255.0

HOSTAPD_CONF=/tmp/arpgtk-tb-hostapd.conf
HOSTAPD_LOG=/tmp/arpgtk-tb-hostapd.log
DNSMASQ_PID=/tmp/arpgtk-tb-dnsmasq.pid
DNSMASQ_LOG=/tmp/arpgtk-tb-dnsmasq.log
SUP_CONF=/tmp/arpgtk-tb-supplicant.conf
SUP_LOG=/tmp/arpgtk-tb-supplicant.log

teardown() {
    # Stop processes that hold sockets / leases
    pkill -9 -f "wpa_supplicant.*arpgtk-tb" 2>/dev/null || true
    pkill -9 -f "dh(client|cpcd).*(wlan1|wlan2|wlan3)" 2>/dev/null || true
    pkill -9 hostapd 2>/dev/null || true
    if [ -f "$DNSMASQ_PID" ]; then
        kill "$(cat "$DNSMASQ_PID")" 2>/dev/null || true
        rm -f "$DNSMASQ_PID"
    fi
    pkill -9 -f "dnsmasq.*arpgtk-tb" 2>/dev/null || true

    # Release any DHCP lease state on the simulated STAs (best-effort).
    # This also undoes the per-iface entries dhcpcd added to
    # /etc/resolv.conf and the default routes it installed -- leaving
    # them around clobbers normal DNS resolution after teardown.
    for iface in wlan1 wlan2 wlan3; do
        if command -v dhclient >/dev/null 2>&1; then
            dhclient -r "$iface" 2>/dev/null || true
        fi
        if command -v dhcpcd >/dev/null 2>&1; then
            dhcpcd -k "$iface" 2>/dev/null || true
        fi
        # Belt and suspenders: drop any default route via the testbed
        # gateway that dhcpcd may have left, and flush iface IPs.
        ip route del default via "$GATEWAY" dev "$iface" 2>/dev/null || true
        ip addr flush dev "$iface" 2>/dev/null || true
        ip link set "$iface" down 2>/dev/null || true
    done

    # If the testbed's dnsmasq IP is still in resolv.conf, refresh
    # whatever owns the host's primary route (eth0 typically) so DNS
    # resolution recovers.
    if grep -q "$GATEWAY" /etc/resolv.conf 2>/dev/null; then
        for primary in eth0 ens33 ens18 enp1s0 enp0s3; do
            if [ -d "/sys/class/net/$primary" ] && command -v dhcpcd >/dev/null 2>&1; then
                dhcpcd -n "$primary" 2>/dev/null || true
                break
            fi
        done
    fi

    # Tear down monitor / chk virtual ifaces arpgtk may have left behind
    for vif in wlan1mon wlan2mon wlan3mon wlan1chk wlan2chk wlan3chk \
               tstmon tstchk; do
        if [ -d "/sys/class/net/$vif" ]; then
            ip link set "$vif" down 2>/dev/null || true
            iw dev "$vif" del 2>/dev/null || true
        fi
    done

    # Bridge
    if ip link show "$BR" >/dev/null 2>&1; then
        ip addr flush dev "$BR" 2>/dev/null || true
        ip link set "$BR" down
        ip link delete "$BR" type bridge
    fi

    # Hwsim radios
    rmmod mac80211_hwsim 2>/dev/null || true

    # Temp config / log / run dirs
    rm -f /tmp/arpgtk-tb-*.conf /tmp/arpgtk-tb-*.log \
          /tmp/arpgtk-tb-*.pid 2>/dev/null || true
    rm -rf /run/arpgtk-tb /run/arpgtk-tb-hostapd 2>/dev/null || true

    echo "Testbed torn down."
}

# Catch Ctrl-C / SIGTERM so an interrupted bring-up still cleans up
# (set -e + an unexpected failure mid-setup would otherwise leak state).
trap 'echo; echo "Interrupted, tearing down..."; teardown; exit 130' INT TERM

if [ "${1:-}" = "--down" ]; then
    teardown; exit 0
fi

# Install hostapd + dnsmasq if missing
need=()
command -v hostapd >/dev/null 2>&1 || need+=(hostapd)
command -v dnsmasq >/dev/null 2>&1 || need+=(dnsmasq)
if [ ${#need[@]} -gt 0 ]; then
    echo "Installing missing packages: ${need[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 \
        | grep -vE "^(W:|E:.*Release file)" || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing "${need[@]}"
fi

# (Re)load mac80211_hwsim with 4 radios
echo "Loading mac80211_hwsim radios=4..."
pkill -9 -f "wpa_supplicant.*arpgtk" 2>/dev/null || true
pkill -9 hostapd 2>/dev/null || true
ip link set "$BR" down 2>/dev/null || true
ip link delete "$BR" type bridge 2>/dev/null || true
rmmod mac80211_hwsim 2>/dev/null || true
sleep 0.5
modprobe mac80211_hwsim radios=4
sleep 1
iw reg set US

# Tell NetworkManager to leave them alone
for iface in wlan0 wlan1 wlan2 wlan3; do
    nmcli dev set "$iface" managed no 2>/dev/null || true
    ip link set "$iface" up
done

# Bridge -- hostapd plugs wlan0 in via the `bridge=` directive; Linux
# refuses `ip link set wlan0 master br0` for managed-mode wireless ifaces.
ip link add name "$BR" type bridge
ip addr add "$GATEWAY/24" dev "$BR"
ip link set "$BR" up

# Permissive sysctls so the simulated STAs can reach the bridge IP
# (which lives on the same host). Distros default to arp_ignore=2 /
# rp_filter=loose / accept_local=0; with that combo, ARP replies from
# br0 to a hwsim STA on the same machine get silently dropped because
# the source IP is "local" but arrives back on a different iface. Scoped
# per-iface so we don't perturb the rest of the host.
sysctl -w net.ipv4.conf.all.arp_ignore=0 >/dev/null
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null
sysctl -w net.ipv4.conf."$BR".arp_ignore=0 >/dev/null
sysctl -w net.ipv4.conf."$BR".rp_filter=0 >/dev/null
sysctl -w net.ipv4.conf."$BR".accept_local=1 >/dev/null
for iface in wlan0 wlan1 wlan2 wlan3; do
    sysctl -w net.ipv4.conf."$iface".rp_filter=0 >/dev/null
    sysctl -w net.ipv4.conf."$iface".accept_local=1 >/dev/null
done

# hostapd
cat > "$HOSTAPD_CONF" <<EOF
ctrl_interface=/run/arpgtk-tb-hostapd
interface=wlan0
bridge=$BR
driver=nl80211

ssid=testnetwork
country_code=US
channel=1
hw_mode=g
ieee80211n=1

auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=passphrase
wpa_group_rekey=600

ap_isolate=0
EOF
mkdir -p /run/arpgtk-tb-hostapd
: > "$HOSTAPD_LOG"
hostapd -B "$HOSTAPD_CONF" -f "$HOSTAPD_LOG"
for _ in $(seq 1 20); do
    grep -q "AP-ENABLED" "$HOSTAPD_LOG" && break
    sleep 0.5
done
grep -q "AP-ENABLED" "$HOSTAPD_LOG" || { echo "hostapd failed to enable AP. See $HOSTAPD_LOG"; exit 1; }

# Hairpin on wlan0 so STA-to-STA unicasts re-exit the same bridge port
# (otherwise Linux drops them as a loop, breaking auto-discovery's reply
# path).
bridge link set dev wlan0 hairpin on 2>/dev/null || true

# dnsmasq DHCP server on br0
: > "$DNSMASQ_LOG"
dnsmasq \
    --interface="$BR" --bind-interfaces --except-interface=lo \
    --no-resolv --no-hosts --no-poll \
    --dhcp-range="$DHCP_RANGE_LO,$DHCP_RANGE_HI,$DOMAIN_NETMASK,1h" \
    --dhcp-option=option:router,"$GATEWAY" \
    --dhcp-option=option:dns-server,"$GATEWAY" \
    --pid-file="$DNSMASQ_PID" \
    --log-facility="$DNSMASQ_LOG" \
    --log-dhcp \
    --port=0
sleep 0.5

# Victim STA on wlan1 + DHCP
cat > "$SUP_CONF" <<EOF
ctrl_interface=/run/arpgtk-tb
network={
    ssid="testnetwork"
    psk="passphrase"
    scan_freq=2412
}
EOF
mkdir -p /run/arpgtk-tb
: > "$SUP_LOG"
wpa_supplicant -B -Dnl80211 -i wlan1 -c "$SUP_CONF" -f "$SUP_LOG"
for _ in $(seq 1 30); do
    iw dev wlan1 link 2>/dev/null | grep -q "Connected to" && break
    sleep 0.5
done
iw dev wlan1 link | grep -q "Connected to" || { echo "victim wlan1 didn't associate. See $SUP_LOG"; exit 1; }

if command -v dhclient >/dev/null 2>&1; then
    dhclient -1 wlan1 >/dev/null 2>&1 || true
elif command -v dhcpcd >/dev/null 2>&1; then
    dhcpcd -1 -t 10 wlan1 >/dev/null 2>&1 || true
fi

VICTIM_IP=$(ip -4 -o addr show wlan1 2>/dev/null | awk '{split($4, a, "/"); print a[1]}')
WLAN0_MAC=$(cat /sys/class/net/wlan0/address)
WLAN2_MAC=$(cat /sys/class/net/wlan2/address)

cat <<EOF

================ Testbed ready ================
  Bridge:       $BR ($GATEWAY/24, DHCP $DHCP_RANGE_LO-$DHCP_RANGE_HI)
  AP iface:     wlan0  ($WLAN0_MAC) -- bridged, channel 1, SSID=testnetwork, PSK=passphrase
  Victim STA:   wlan1  -- DHCP IP=${VICTIM_IP:-<none>}
  Attacker:     wlan2  ($WLAN2_MAC) -- pass to arpgtk
  Spare:        wlan3

  arpgtk examples:
      # Mode 1: GTK-shared check (default, no injection):
      sudo ./arpgtk.py --iface wlan2 --ssid testnetwork --psk passphrase

      # Mode 2: verify against the testbed victim:
      sudo ./arpgtk.py --iface wlan2 --ssid testnetwork --psk passphrase \\
          --verify --target-ip ${VICTIM_IP:-<victim_ip>}

  Cleanup:
      sudo $SCRIPT_DIR/testbed.sh --down

  Notes:
   - If your host has a strict outbound firewall with policy=drop on
     input/forward, DHCP / pings between br0 and the simulated STAs may
     be blocked. The bridge itself works, but L3 traffic into the host's
     IP stack will need an exception for 192.168.99.0/24.
   - All hwsim radios share a simulated medium; perfect signal, no loss.
   - If host DNS resolution breaks during/after a testbed run (the
     dnsmasq on br0 briefly becomes resolv.conf's nameserver), refresh
     your host's primary iface, e.g. \`sudo dhcpcd -n eth0\`.
================================================
EOF
