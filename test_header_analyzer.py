import unittest

from header_analyzer import analyze_email


NORMAL_EMAIL = """\
From: Alex Example <alex@example.com>
Reply-To: Alex Example <alex@example.com>
Return-Path: <alex@example.com>
Sender: Alex Example <alex@example.com>
Subject: Project update
Date: Tue, 14 Oct 2025 10:00:00 +0000
Message-ID: <normal-1@example.com>
Received: from relay.example.com ([192.0.2.10]) by inbox.example.net
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com;
 dkim=pass header.d=example.com; dmarc=pass header.from=example.com
Received-SPF: pass (mx.example.net: domain of alex@example.com designates 192.0.2.10 as permitted sender)
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello, this is a normal-looking test message.
"""


class HeaderAnalyzerTests(unittest.TestCase):
    def test_normal_looking_email_extracts_headers_without_warning(self) -> None:
        result = analyze_email(NORMAL_EMAIL)

        self.assertEqual(result["fields"]["from"], ["Alex Example <alex@example.com>"])
        self.assertEqual(result["fields"]["reply_to"], ["Alex Example <alex@example.com>"])
        self.assertEqual(result["fields"]["return_path"], ["<alex@example.com>"])
        self.assertEqual(result["fields"]["sender"], ["Alex Example <alex@example.com>"])
        self.assertEqual(result["fields"]["subject"], ["Project update"])
        self.assertEqual(result["fields"]["date"], ["Tue, 14 Oct 2025 10:00:00 +0000"])
        self.assertEqual(result["fields"]["message_id"], ["<normal-1@example.com>"])
        self.assertEqual(result["fields"]["received"][0]["ip_addresses"], ["192.0.2.10"])
        self.assertEqual(result["findings"], [])
        self.assertIn("not proof", result["summary"])

    def test_from_and_reply_to_domain_mismatch_is_a_warning(self) -> None:
        raw_email = """\
From: Alex <alex@example.com>
Reply-To: Alex <alex@attacker.test>
Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass

Please reply.
"""
        result = analyze_email(raw_email)

        codes = {finding["code"] for finding in result["findings"]}
        self.assertIn("from_reply_to_domain_mismatch", codes)
        self.assertTrue(all(finding["severity"] in {"warning", "informational"} for finding in result["findings"]))
        self.assertIn("not proof", result["summary"])

    def test_explicit_spf_failure_is_reported(self) -> None:
        raw_email = """\
From: Alex <alex@example.com>
Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=attacker.test

Test.
"""
        result = analyze_email(raw_email)

        failures = [
            finding
            for finding in result["findings"]
            if finding["code"] == "spf_failure_reported"
        ]
        self.assertEqual(len(failures), 1)
        self.assertEqual(result["fields"]["authentication_checks"][0]["result"], "fail")

    def test_missing_authentication_results_are_not_called_a_failure(self) -> None:
        result = analyze_email("From: Alex <alex@example.com>\n\nTest.\n")

        missing = [
            finding
            for finding in result["findings"]
            if finding["code"] == "authentication_results_missing"
        ]
        self.assertEqual(len(missing), 1)
        self.assertNotIn("spf_failure_reported", {item["code"] for item in result["findings"]})
        self.assertIn("unknown", missing[0]["explanation"])

    def test_partial_authentication_results_are_inconclusive(self) -> None:
        result = analyze_email(
            "From: Alex <alex@example.com>\n"
            "Authentication-Results: mx.example.net; spf=pass\n\nTest.\n"
        )

        self.assertIn(
            "authentication_results_inconclusive",
            {finding["code"] for finding in result["findings"]},
        )

    def test_multiple_from_values_are_flagged_for_review(self) -> None:
        result = analyze_email(
            "From: Alex <alex@example.com>\n"
            "From: Billing <billing@billing.example>\n\nTest.\n"
        )

        self.assertIn(
            "multiple_from_values",
            {finding["code"] for finding in result["findings"]},
        )

    def test_multiple_received_headers_are_preserved_with_ips(self) -> None:
        raw_email = """\
From: Alex <alex@example.com>
Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass
Received: from first.example ([192.0.2.10]) by second.example
Received: from edge.example ([IPv6:2001:db8::1]) by first.example

Test.
"""
        result = analyze_email(raw_email)
        received = result["fields"]["received"]

        self.assertEqual(len(received), 2)
        self.assertIn("from first.example", received[0]["raw"])
        self.assertEqual(received[0]["ip_addresses"], ["192.0.2.10"])
        self.assertIn("from edge.example", received[1]["raw"])
        self.assertEqual(received[1]["ip_addresses"], ["2001:db8::1"])


if __name__ == "__main__":
    unittest.main()
