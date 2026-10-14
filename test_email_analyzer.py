import unittest

from email_analyzer import analyze_email_message


HAM_EMAIL = """\
From: Alex Example <alex@example.com>
Reply-To: Alex Example <alex@example.com>
Return-Path: <alex@example.com>
Subject: Meeting notes
Date: Tue, 14 Oct 2025 10:00:00 +0000
Message-ID: <meeting-1@example.com>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hi team, attached are the notes from our project meeting.
"""

SPAM_EMAIL = """\
From: Offers <deals@promo.example>
Reply-To: Offers <deals@promo.example>
Return-Path: <deals@promo.example>
Subject: Claim your free prize now
Date: Tue, 14 Oct 2025 10:00:00 +0000
Message-ID: <offer-1@promo.example>
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Claim your free prize now! Click here to claim your limited-time cash reward.
Act immediately to receive your free prize.
"""


class UnifiedEmailAnalyzerTests(unittest.TestCase):
    def test_ham_email_is_classified_legitimate(self) -> None:
        result = analyze_email_message(HAM_EMAIL)

        self.assertEqual(result["ml_prediction"], "legitimate")
        self.assertEqual(result["ml_label"], 0)
        self.assertIsInstance(result["forensic_findings"], list)
        self.assertIsInstance(result["forensic_summary"], str)
        self.assertIn("classifier predicts legitimate", result["overall_assessment"])

    def test_spam_email_is_classified_spam(self) -> None:
        result = analyze_email_message(SPAM_EMAIL.encode("utf-8"))

        self.assertEqual(result["ml_prediction"], "spam")
        self.assertEqual(result["ml_label"], 1)
        self.assertIsInstance(result["forensic_findings"], list)

    def test_header_findings_are_included_separately_from_ml(self) -> None:
        raw_email = HAM_EMAIL.replace(
            "Reply-To: Alex Example <alex@example.com>",
            "Reply-To: Alex Example <alex@other.example>",
        )
        result = analyze_email_message(raw_email)

        self.assertEqual(result["ml_label"], 0)
        codes = {finding["code"] for finding in result["forensic_findings"]}
        self.assertIn("from_reply_to_domain_mismatch", codes)
        self.assertIn("while header analysis", result["overall_assessment"])
        self.assertIn("neither overrides", result["overall_assessment"])

    def test_empty_message_is_handled_without_crashing(self) -> None:
        result = analyze_email_message("")

        self.assertIn(result["ml_label"], {0, 1})
        self.assertIn(result["ml_prediction"], {"spam", "legitimate"})
        self.assertIsInstance(result["forensic_findings"], list)
        self.assertTrue(result["limitations"])

    def test_invalid_input_type_is_reported_as_unavailable(self) -> None:
        result = analyze_email_message(None)  # type: ignore[arg-type]

        self.assertEqual(result["ml_prediction"], "unavailable")
        self.assertIsNone(result["ml_label"])
        self.assertIn(
            "forensic_analysis_unavailable",
            {finding["code"] for finding in result["forensic_findings"]},
        )


if __name__ == "__main__":
    unittest.main()
