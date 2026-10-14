import unittest

from forensic_report import format_forensic_report
from risk_assessment import build_risk_assessment


class ForensicReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assessment = build_risk_assessment(
            {
                "ml_prediction": "legitimate",
                "ml_label": 0,
                "forensic_findings": [
                    {
                        "code": "from_reply_to_domain_mismatch",
                        "severity": "warning",
                        "explanation": "Do not print arbitrary evidence.",
                    }
                ],
                "header_fields": {
                    "ip_geolocation": {
                        "results": [
                            {
                                "ip_address": "192.168.1.10",
                                "is_globally_routable": False,
                                "lookup_status": "not_public",
                                "address_categories": ["private"],
                                "location": {"city": "must not be invented"},
                            }
                        ],
                        "explanation": "Private.",
                    }
                },
                "threat_intelligence_findings": [
                    {
                        "type": "url_visible_domain_mismatch",
                        "severity": "warning",
                        "explanation": "Sensitive body details must not show.",
                        "evidence": {"raw_email_body": "UNIQUE_SYNTHETIC_BODY_SECRET"},
                    }
                ],
                "threat_intelligence": {
                    "reputation": {"status": "not_configured"}
                },
            }
        )

    def test_report_contains_required_sections(self) -> None:
        report = format_forensic_report(self.assessment)

        for section in (
            "Overall review priority:",
            "ML prediction",
            "Important findings by source",
            "Header forensics:",
            "Local threat indicators:",
            "IP information",
            "Recommended next action",
            "Limitations and uncertainty",
        ):
            with self.subTest(section=section):
                self.assertIn(section, report)
        self.assertIn("192.168.1.10: not_public", report)
        self.assertIn("location not available", report)

    def test_report_does_not_render_body_or_arbitrary_evidence(self) -> None:
        report = format_forensic_report(self.assessment)

        self.assertNotIn("UNIQUE_SYNTHETIC_BODY_SECRET", report)
        self.assertNotIn("Sensitive body details", report)
        self.assertNotIn("must not be invented", report)

    def test_report_is_deterministic(self) -> None:
        first = format_forensic_report(self.assessment)
        second = format_forensic_report(self.assessment)

        self.assertEqual(first, second)

    def test_malformed_assessment_still_formats_safely(self) -> None:
        report = format_forensic_report(None)

        self.assertIn("Overall review priority: Inconclusive", report)
        self.assertIn("IP lookup status: unavailable.", report)


if __name__ == "__main__":
    unittest.main()
