"""Privacy-preserving IP address geolocation lookup placeholder.

No provider is configured by this module. Public addresses are not sent
anywhere; actual geographic data remains unavailable until a provider is
deliberately configured and its privacy behavior is reviewed.
"""

import ipaddress
from typing import Any


_LOCATION_FIELDS = ("city", "region", "country", "latitude", "longitude", "isp")


def _address_categories(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[str]:
    categories: list[str] = []
    for attribute, category in (
        ("is_private", "private"),
        ("is_loopback", "loopback"),
        ("is_link_local", "link_local"),
        ("is_multicast", "multicast"),
        ("is_reserved", "reserved"),
        ("is_unspecified", "unspecified"),
    ):
        if getattr(address, attribute):
            categories.append(category)
    return categories


def lookup_ip_location(ip_address: str) -> dict[str, Any]:
    """Validate and classify an IP without sending it to an external service.

    Location properties are left ``None`` because no geolocation provider is
    configured. A location, if later supplied by a provider, estimates the
    network endpoint and does not necessarily locate the email sender.
    """
    location = {field: None for field in _LOCATION_FIELDS}
    if not isinstance(ip_address, str):
        return {
            "ip_address": None,
            "is_globally_routable": False,
            "address_categories": [],
            "lookup_status": "invalid",
            "location": location,
            "explanation": "IP address must be supplied as text; no lookup was attempted.",
        }

    candidate = ip_address.strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return {
            "ip_address": candidate,
            "is_globally_routable": False,
            "address_categories": [],
            "lookup_status": "invalid",
            "location": location,
            "explanation": "The value is not a valid IPv4 or IPv6 address; no lookup was attempted.",
        }

    normalized = str(address)
    categories = _address_categories(address)
    globally_routable = address.is_global and not categories
    if not globally_routable:
        return {
            "ip_address": normalized,
            "is_globally_routable": False,
            "address_categories": categories or ["not_globally_routable"],
            "lookup_status": "not_public",
            "location": location,
            "explanation": (
                "This address is not globally routable, so it was not sent to an "
                "external geolocation service."
            ),
        }

    return {
        "ip_address": normalized,
        "is_globally_routable": True,
        "address_categories": [],
        "lookup_status": "not_configured",
        "location": location,
        "explanation": (
            "This is a globally routable address, but no geolocation provider is "
            "configured. No network request was made and no location is available. "
            "Geolocation would estimate a network endpoint, not necessarily the "
            "email sender's physical location."
        ),
    }
