import unittest

from threat_intelligence import analyze_threat_indicators


NORMAL_EMAIL = """\
From: Alex <alex@EXAMPLE.test.>
Reply-To: Alex <alex@example.test>
Return-Path: <alex@example.test>
Subject: Team update
Content-Type: text/plain; charset=utf-8

Hello, the project notes are ready.
"""


class ThreatIntelligenceTests(unittest.TestCase):
    def test_normal_synthetic_email_has_normalized_sender_domains(self) -> None:
        result = analyze_threat_indicators(NORMAL_EMAIL)

        self.assertEqual(result["sender_domains"]["from"], ["example.test"])
        self.assertEqual(result["sender_domains"]["reply_to"], ["example.test"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["reputation"]["status"], "not_configured")

    def test_from_reply_to_domain_mismatch_is_review_indicator(self) -> None:
        raw_email = NORMAL_EMAIL.replace(
            "Reply-To: Alex <alex@example.test>",
            "Reply-To: Alex <alex@other.test>",
        )
        result = analyze_threat_indicators(raw_email)

        finding = next(
            item
            for item in result["findings"]
            if item["type"] == "sender_domain_mismatch"
        )
        self.assertEqual(finding["severity"], "warning")
        self.assertIn("not proof", finding["explanation"])
        self.assertEqual(finding["evidence"]["reply_to_domains"], ["other.test"])

    def test_malformed_sender_address_is_reported_without_crashing(self) -> None:
        result = analyze_threat_indicators(
            "From: not-an-email-address\nSubject: Synthetic\n\nHello.\n"
        )

        self.assertIn(
            "malformed_sender_address",
            {item["type"] for item in result["findings"]},
        )

    def test_body_url_is_extracted_without_being_opened(self) -> None:
        result = analyze_threat_indicators(
            "From: Alex <alex@example.test>\n"
            "Content-Type: text/plain\n\n"
            "Read more at https://docs.example.test/guide.\n"
        )

        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(result["urls"][0]["host"], "docs.example.test")
        self.assertEqual(result["url_domains"], ["docs.example.test"])
        self.assertEqual(result["reputation"]["status"], "not_configured")

    def test_visible_html_domain_mismatch_is_flagged_without_visiting_url(self) -> None:
        raw_email = """\
From: Alex <alex@example.test>
Content-Type: text/html; charset=utf-8

<html><body><a href="https://destination.example.test/path">
https://visible.example.test</a></body></html>
"""
        result = analyze_threat_indicators(raw_email)

        finding = next(
            item
            for item in result["findings"]
            if item["type"] == "url_visible_domain_mismatch"
        )
        self.assertEqual(
            finding["evidence"]["visible_host"], "visible.example.test"
        )
        self.assertEqual(
            finding["evidence"]["destination_host"], "destination.example.test"
        )

    def test_userinfo_url_is_flagged_as_structure_not_reputation(self) -> None:
        result = analyze_threat_indicators(
            "From: Alex <alex@example.test>\n"
            "Content-Type: text/plain\n\n"
            "Visit https://trusted.example.test@destination.example.test/path\n"
        )

        finding = next(
            item
            for item in result["findings"]
            if item["type"] == "url_contains_userinfo"
        )
        self.assertEqual(
            finding["evidence"]["actual_host"], "destination.example.test"
        )
        self.assertEqual(result["reputation"]["status"], "not_configured")

    def test_multiple_urls_and_url_domains_are_deduplicated(self) -> None:
        result = analyze_threat_indicators(
            "From: Alex <alex@example.test>\n"
            "Content-Type: text/plain\n\n"
            "https://one.example.test/a https://one.example.test/b "
            "https://two.example.test/c https://one.example.test/a\n"
        )

        self.assertEqual(len(result["urls"]), 3)
        self.assertEqual(
            result["url_domains"],
            ["one.example.test", "two.example.test"],
        )

    def test_empty_email_and_malformed_input_are_safe(self) -> None:
        empty_result = analyze_threat_indicators("")
        invalid_result = analyze_threat_indicators(None)  # type: ignore[arg-type]

        self.assertEqual(empty_result["urls"], [])
        self.assertEqual(empty_result["findings"], [])
        self.assertEqual(
            invalid_result["findings"][0]["type"], "parse_error"
        )
        self.assertEqual(
            invalid_result["reputation"]["status"], "not_configured"
        )

    def test_malformed_domain_is_reported_without_claiming_reputation(self) -> None:
        result = analyze_threat_indicators(
            "From: Alex <alex@bad_domain.test>\n\nSynthetic message.\n"
        )

        self.assertIn(
            "malformed_sender_domain",
            {item["type"] for item in result["findings"]},
        )
        self.assertEqual(result["reputation"]["status"], "not_configured")


if __name__ == "__main__":
    unittest.main()
