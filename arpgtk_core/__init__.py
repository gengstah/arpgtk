"""arpgtk_core: building blocks for the audit tool.

Modules:
    errors     : domain exceptions caught at the CLI boundary.
    frames     : pure 802.11/CCMP/ARP frame builders.
    iface      : managed/monitor virtual iface lifecycle on a single phy.
    session    : wpa_supplicant lifecycle + GTK extraction via GET_GTK.
    sniffer    : monitor-side AP PN sampler (used to pick a safe probe PN).
    discovery  : managed-iface ARP-reply watcher used by --verify.
"""
