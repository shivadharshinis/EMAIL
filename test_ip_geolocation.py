import unittest

from header_analyzer import analyze_email
from ip_geolocation import lookup_ip_location


class IpGeolocationTests(unittest.TestCase):
    def test_public_ipv4_reports_lookup_unconfigured_without_location(self) -> None:
        result = lookup_ip_location("8.8.8.8")

        self.assertEqual(result["ip_address"], "8.8.8.8")
        self.assertTrue(result["is_globally_routable"])
        self.assertEqual(result["lookup_status"], "not_configured")
        self.assertTrue(all(value is None for value in result["location"].values()))
        self.assertIn("No network request was made", result["explanation"])

    def test_private_ipv4_is_not_sent_for_lookup(self) -> None:
        result = lookup_ip_location("192.168.1.25")

        self.assertFalse(result["is_globally_routable"])
        self.assertIn("private", result["address_categories"])
        self.assertEqual(result["lookup_status"], "not_public")

    def test_loopback_address_is_not_sent_for_lookup(self) -> None:
        result = lookup_ip_location("127.0.0.1")

        self.assertFalse(result["is_globally_routable"])
        self.assertIn("loopback", result["address_categories"])
        self.assertEqual(result["lookup_status"], "not_public")

    def test_ipv6_address_is_validated_and_not_geolocated_without_provider(self) -> None:
        result = lookup_ip_location("2001:4860:4860::8888")

        self.assertEqual(result["ip_address"], "2001:4860:4860::8888")
        self.assertTrue(result["is_globally_routable"])
        self.assertEqual(result["lookup_status"], "not_configured")
        self.assertTrue(all(value is None for value in result["location"].values()))

    def test_malformed_ip_is_returned_as_invalid(self) -> None:
        result = lookup_ip_location("999.4.5.6")

        self.assertEqual(result["ip_address"], "999.4.5.6")
        self.assertFalse(result["is_globally_routable"])
        self.assertEqual(result["lookup_status"], "invalid")
        self.assertTrue(all(value is None for value in result["location"].values()))

    def test_non_public_categories_are_never_eligible_for_lookup(self) -> None:
        cases = (
            ("169.254.1.1", "link_local"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved"),
            ("0.0.0.0", "unspecified"),
        )
        for address, category in cases:
            with self.subTest(address=address):
                result = lookup_ip_location(address)
                self.assertFalse(result["is_globally_routable"])
                self.assertEqual(result["lookup_status"], "not_public")
                self.assertIn(category, result["address_categories"])

    def test_duplicate_received_ips_are_deduplicated_for_geolocation(self) -> None:
        raw_email = """\
From: Alex <alex@example.test>
Received: from first.example ([192.0.2.44]) by mx.example.test
Received: from second.example ([192.0.2.44]) by first.example

Synthetic test message.
"""
        result = analyze_email(raw_email)
        geo = result["fields"]["ip_geolocation"]

        self.assertEqual(len(result["fields"]["received"]), 2)
        self.assertEqual(len(geo["results"]), 1)
        self.assertEqual(geo["results"][0]["ip_address"], "192.0.2.44")
        self.assertEqual(geo["results"][0]["lookup_status"], "not_public")

    def test_no_extractable_ip_has_empty_results_and_explanation(self) -> None:
        result = analyze_email(
            "From: Alex <alex@example.test>\n"
            "Received: from relay.example.test by mx.example.test\n\n"
            "Synthetic test message.\n"
        )

        geo = result["fields"]["ip_geolocation"]
        self.assertEqual(geo["results"], [])
        self.assertIn("No IP address", geo["explanation"])

    def test_public_ip_in_header_is_not_sent_to_unconfigured_provider(self) -> None:
        result = analyze_email(
            "From: Alex <alex@example.test>\n"
            "Received: from relay.example.test ([8.8.8.8]) by mx.example.test\n\n"
            "Synthetic test message.\n"
        )

        lookup = result["fields"]["ip_geolocation"]["results"][0]
        self.assertTrue(lookup["is_globally_routable"])
        self.assertEqual(lookup["lookup_status"], "not_configured")
        self.assertTrue(all(value is None for value in lookup["location"].values()))
        self.assertIn("No external lookup was made", result["fields"]["ip_geolocation"]["explanation"])


if __name__ == "__main__":
    unittest.main()
