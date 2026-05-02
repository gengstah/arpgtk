"""Library exceptions. Caught and translated to sys.exit() at the CLI boundary."""


class AirspoofError(Exception):
    """Base class for any expected arpgtk failure."""


class IfaceError(AirspoofError):
    """Wireless interface setup / introspection failed."""


class SupplicantError(AirspoofError):
    """wpa_supplicant lifecycle / control-interface failure."""


class DiscoveryError(AirspoofError):
    """Target-MAC discovery or primitive verification failed."""


class ForwarderError(AirspoofError):
    """Setting up or tearing down forwarding/NAT/static ARP failed."""


class PreflightError(AirspoofError):
    """Missing dependency / mis-configured environment caught at startup."""
