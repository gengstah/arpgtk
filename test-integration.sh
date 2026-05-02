#!/bin/bash
# test-integration.sh -- functional tests against the hwsim testbed.
#
# Run the testbed first:
#     sudo ./testbed.sh
#
# Then run this script:
#     sudo ./test-integration.sh
#
# Exercises every arpgtk CLI flag/mode that can be exercised in a hwsim
# environment. The two modes are:
#     --check-gtk-shared (default): two parallel associations, GTK byte-compare
#     --verify --target-ip IP:    one CCMP-encrypted from-DS broadcast probe
#                                 + watch managed iface for the bridged reply
#
# Tests that depend on the bridge actually relaying STA-to-attacker reply
# traffic (the --verify reply path, T6) require the host's bridge L3 stack
# to forward 192.168.99.0/24 between br0 and the hwsim STAs. If the host
# has a strict input/forward policy, T6 will report no reply through no
# fault of arpgtk.
set -u

if [ "$(id -u)" != "0" ]; then
    echo "Run as root: sudo $0"; exit 1
fi

cleanup() {
    # Tear down any test-private ifaces that arpgtk may have leaked
    # (e.g. due to a killed test) and remove our scratch files. Only
    # invoked from the top-level script -- not from subshell exits.
    for vif in tstmon tstchk wlan2mon wlan2chk; do
        if [ -d "/sys/class/net/$vif" ]; then
            ip link set "$vif" down 2>/dev/null || true
            iw dev "$vif" del 2>/dev/null || true
        fi
    done
    rm -f /tmp/arpgtk-T*.out 2>/dev/null || true
}
# Trap signals only -- NOT EXIT (which would fire in every $(...) subshell
# and clobber the test driver). Cleanup is invoked explicitly at the bottom.
trap 'cleanup; exit 130' INT TERM

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACK=wlan2
VICTIM=wlan1
SSID=testnetwork
PSK=passphrase
GW_IP=192.168.99.1

ATTACK_MAC=$(cat /sys/class/net/$ATTACK/address)
VICTIM_MAC=$(cat /sys/class/net/$VICTIM/address)
GW_MAC=$(cat /sys/class/net/wlan0/address)

PASS=0; FAIL=0; SKIP=0

ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
no()   { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
note() { echo; echo "[$(date +%H:%M:%S)] $*"; }

# Pull a victim IP from the testbed if the testbed assigned one
VICTIM_IP=$(ip -4 -o addr show $VICTIM 2>/dev/null | awk '{split($4, a, "/"); print a[1]}')
[ -z "$VICTIM_IP" ] && VICTIM_IP=192.168.99.50

note "Attacker $ATTACK ($ATTACK_MAC), victim $VICTIM ($VICTIM_MAC) ip=$VICTIM_IP, AP MAC $GW_MAC"

# --- error-path tests (fast, no association) -------------------------------

note "T1: --verify without --target-ip -> error"
out=$(timeout -k 5 5 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --verify 2>&1) || true
echo "$out" | grep -qE "ERROR:.*--verify requires --target-ip" \
    && ok "T1" || no "T1"

note "T2: --verify with malformed --target-ip -> error"
out=$(timeout -k 5 5 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --verify --target-ip not.an.ip 2>&1) || true
echo "$out" | grep -qE "ERROR:.*not\.an\.ip.*not a valid IP" \
    && ok "T2" || no "T2"

note "T3: invalid --iface -> error with available-ifaces hint"
out=$(timeout -k 5 5 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface nopenope --ssid $SSID --psk $PSK 2>&1) || true
echo "$out" | grep -qE "ERROR:.*nopenope.*not found" \
    && ok "T3" || no "T3"

note "T4: --version prints"
out=$(python3 -u "$SCRIPT_DIR/arpgtk.py" --version 2>&1) || true
echo "$out" | grep -qE "^arpgtk [0-9]+\.[0-9]+\.[0-9]+" \
    && ok "T4" || no "T4 (got: $out)"

# --- check-gtk-shared mode -------------------------------------------------

note "T5: --check-gtk-shared (default chk-iface) -> SHARED verdict, exit 0"
timeout -k 5 60 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --quiet \
    > /tmp/arpgtk-T5.out 2>&1
ec=$?
shared=$(grep -c "GTK IS SHARED" /tmp/arpgtk-T5.out)
if [ "$ec" = "0" ] && [ "$shared" -ge 1 ]; then
    ok "T5 ec=$ec shared=$shared"
else
    no "T5 ec=$ec shared=$shared"
fi

note "T6: --chk-iface custom name (tstchk)"
out=$(timeout -k 5 60 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --chk-iface tstchk --quiet 2>&1)
echo "$out" | grep -q "Comparison iface: tstchk" \
    && echo "$out" | grep -q "GTK IS SHARED" \
    && ok "T6" || no "T6"

note "T7: --bssid pin still produces SHARED verdict"
out=$(timeout -k 5 60 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --bssid $GW_MAC --quiet 2>&1)
echo "$out" | grep -q "GTK IS SHARED" && ok "T7" || no "T7"

note "T8: --ieee80211w 0 (PMF off) still associates and produces SHARED"
out=$(timeout -k 5 60 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --ieee80211w 0 --quiet 2>&1)
echo "$out" | grep -q "GTK IS SHARED" && ok "T8" || no "T8"

note "T9: --supplicant-debug -dd passes through to wpa_supplicant cmdline"
out=$(timeout -k 5 25 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --supplicant-debug --supplicant-debug --quiet 2>&1 | head -20 || true)
echo "$out" | grep -q -- "wpa_supplicant.*-dd" && ok "T9" || no "T9"

# --- verify mode (depends on bridged STA-to-attacker reply path) -----------

note "T10: --verify against live victim -> reply, exit 0"
timeout -k 5 90 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --verify --target-ip $VICTIM_IP --quiet \
    > /tmp/arpgtk-T10.out 2>&1
ec=$?
viable=$(grep -c "Primitive is viable against this target" /tmp/arpgtk-T10.out)
if [ "$ec" = "0" ] && [ "$viable" -ge 1 ]; then
    ok "T10 ec=$ec viable=$viable"
else
    no "T10 ec=$ec viable=$viable -- if viable=0, the bridge isn't relaying STA-to-STA replies (host firewall?)"
fi

note "T11: --verify against unassigned IP -> no reply, exit 2"
timeout -k 5 90 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --verify --target-ip 192.168.99.250 --quiet \
    > /tmp/arpgtk-T11.out 2>&1
ec=$?
no_reply=$(grep -c "no reply from 192.168.99.250" /tmp/arpgtk-T11.out)
if [ "$ec" = "2" ] && [ "$no_reply" -ge 1 ]; then
    ok "T11 ec=$ec no_reply=$no_reply"
else
    no "T11 ec=$ec no_reply=$no_reply"
fi

note "T12: --pn-sample-window honored (0.2s window)"
out=$(timeout -k 5 90 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --verify --target-ip $VICTIM_IP --pn-sample-window 0.2 --quiet 2>&1)
echo "$out" | grep -qE "Sampling AP broadcast PN.*for 0\.2s" \
    && ok "T12" || no "T12"

note "T13: --mon-iface custom name (tstmon)"
iw dev tstmon del 2>/dev/null
out=$(timeout -k 5 90 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK \
    --verify --target-ip $VICTIM_IP --mon-iface tstmon --quiet 2>&1)
echo "$out" | grep -q "Monitor iface tstmon" && ok "T13" || no "T13"

# --- cleanup ---------------------------------------------------------------

note "T14: cleanup completeness -- no leaked state after a normal exit"
# Run arpgtk briefly; verify nothing is left behind:
#   - no arpgtk-XXXXXXXX/ tempdirs (mkdtemp-format only -- ignore
#     `arpgtk-tb-*.log` etc. left by the testbed)
#   - no wpa_supplicant child whose ctrl_interface points at one of our
#     tempdirs
#   - no wlanXmon / wlanXchk / tstmon / tstchk virtual ifaces
count_tmpdirs() {
    find /tmp -maxdepth 1 -mindepth 1 -type d -name 'arpgtk-*' \
        ! -name 'arpgtk-tb*' 2>/dev/null | wc -l
}
PRIOR_TMPDIRS=$(count_tmpdirs)
timeout -k 5 60 python3 -u "$SCRIPT_DIR/arpgtk.py" \
    --iface $ATTACK --ssid $SSID --psk $PSK --quiet \
    > /tmp/arpgtk-T14.out 2>&1
sleep 2  # let teardown finish
POST_TMPDIRS=$(count_tmpdirs)
POST_WPAS=$(pgrep -f "wpa_supplicant.*arpgtk-[a-z0-9_]*/" 2>/dev/null | wc -l)
leaked_mon=0
for vif in wlan2mon wlan2chk tstmon tstchk; do
    [ -d "/sys/class/net/$vif" ] && leaked_mon=$((leaked_mon+1))
done
if [ "$POST_TMPDIRS" -le "$PRIOR_TMPDIRS" ] \
   && [ "$POST_WPAS" = "0" ] \
   && [ "$leaked_mon" = "0" ]; then
    ok "T14 no leaks (tmpdirs ${PRIOR_TMPDIRS}->${POST_TMPDIRS}, supplicants left=${POST_WPAS}, ifaces left=${leaked_mon})"
else
    no "T14 LEAK: tmpdirs ${PRIOR_TMPDIRS}->${POST_TMPDIRS}, supplicants left=${POST_WPAS}, ifaces left=${leaked_mon}"
fi

echo
echo "================ TALLY ================"
echo "PASS: $PASS    FAIL: $FAIL    SKIP: $SKIP"
cleanup
[ "$FAIL" = "0" ] && exit 0 || exit 1
