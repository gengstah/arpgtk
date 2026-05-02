#!/bin/bash
# Build the wpa_supplicant binary airspoof uses.
#
# Produces: ./wpa_supplicant/wpa_supplicant
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$SCRIPT_DIR/wpa_supplicant" ] || [ ! -d "$SCRIPT_DIR/src" ]; then
    echo "ERROR: wpa_supplicant/ or src/ missing from the repo." >&2
    exit 1
fi

cd "$SCRIPT_DIR/wpa_supplicant"
cp defconfig .config
make -j"$(nproc)"

echo
echo "Built: $SCRIPT_DIR/wpa_supplicant/wpa_supplicant"
