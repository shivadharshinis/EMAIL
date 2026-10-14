import unittest

from risk_assessment import build_risk_assessment


def analysis_result(
    ml_prediction: str = "legitimate",
    header_findings: list[dict[str, object]] | None = None,
    threat_findings: list[dict[str, object]] | None = None,
    header_fields: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "ml_prediction": ml_prediction,
        "ml_label": 1 if ml_prediction == "spam" else 0,
        "forensic_findings": header_findings if header_findings is not None else [],
        "header_fields": header_fields
        if header_fields is not None
        else {"ip_geolocation": {"results": [], "explanation": "No IP found."}},
        "threat_intelligence_findings": threat_findings
        if threat_findings is not None
        else [],
        "threat_intelligence": {
            "findings": threat_findings or [],
            "reputation": {"status": "not_configured"},
        },
    }


class RiskAssessmentTests(unittest.TestCase):
    def test_normal_email_has_low_priority(self) -> None:
        result = build_risk_assessment(analysis_result())

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["ml_prediction"], "legitimate")
        self.assertEqual(result["header_findings"], [])
        self.assertEqual(result["threat_findings"], [])
        self.assertEqual(result["ip_information"]["lookup_status"], "no_ip_found")

    def test_spam_prediction_alone_is_medium_not_proof(self) -> None:
        result = build_risk_assessment(analysis_result(ml_prediction="spam"))

        self.assertEqual(result["risk_level"], "Medium")
        self.assertTrue(any("not proof" in reason for reason in result["risk_reasons"]))

    def test_sender_domain_mismatch_is_a_single_medium_indicator(self) -> None:
        data = analysis_result(
            header_findings=[
                {
                    "code": "from_reply_to_domain_mismatch",
                    "severity": "warning",
                    "explanation": "Synthetic.",
                }
            ],
            threat_findings=[
                {
                    "type": "sender_domain_mismatch",
                    "severity": "warning",
                    "explanation": "Synthetic.",
                }
            ],
        )
        result = build_risk_assessment(data)

        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(len(result["risk_reasons"]), 1)
        self.assertIn("may explain", result["risk_reasons"][0])

    def test_suspicious_url_is_heuristic_and_yields_medium(self) -> None:
        result = build_risk_assessment(
            analysis_result(
                threat_findings=[
                    {
                        "type": "url_visible_domain_mismatch",
                        "severity": "warning",
                        "explanation": "Synthetic URL mismatch.",
                    }
                ]
            )
        )

        self.assertEqual(result["risk_level"], "Medium")
        self.assertIn("heuristic", result["risk_reasons"][0])

    def test_two_independent_warning_types_raise_priority_to_high(self) -> None:
        result = build_risk_assessment(
            analysis_result(
                header_findings=[
                    {"code": "spf_failure_reported", "severity": "warning"}
                ],
                threat_findings=[
                    {"type": "url_visible_domain_mismatch", "severity": "warning"}
                ],
            )
        )

        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(len(result["risk_reasons"]), 2)
        self.assertIn("Prioritize manual review", result["recommended_action"])

    def test_missing_ip_geolocation_does_not_invent_location(self) -> None:
        result = build_risk_assessment(
            analysis_result(header_fields={"ip_geolocation": None})
        )

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["ip_information"]["lookup_status"], "unavailable")
        self.assertEqual(result["ip_information"]["addresses"], [])
        self.assertTrue(
            any(
                "IP geolocation is not configured" in item
                for item in result["limitations"]
            )
        )

    def test_missing_or_malformed_core_analysis_is_inconclusive(self) -> None:
        for data in (
            {},
            None,
            analysis_result(ml_prediction="unavailable"),
            {
                "ml_prediction": "legitimate",
                "ml_label": 0,
                "forensic_findings": "malformed",
                "threat_intelligence_findings": [],
            },
        ):
            with self.subTest(data=data):
                result = build_risk_assessment(data)
                self.assertEqual(result["risk_level"], "Inconclusive")
                self.assertTrue(result["risk_reasons"])
                self.assertTrue(result["recommended_action"])

    def test_private_ip_not_treated_as_public_attacker_location(self) -> None:
        result = build_risk_assessment(
            analysis_result(
                header_fields={
                    "ip_geolocation": {
                        "results": [
                            {
                                "ip_address": "192.168.1.10",
                                "is_globally_routable": False,
                                "lookup_status": "not_public",
                                "address_categories": ["private"],
                            }
                        ],
                        "explanation": "Private address.",
                    }
                }
            )
        )

        self.assertEqual(result["ip_information"]["addresses"][0]["lookup_status"], "not_public")
        self.assertIn("Private, loopback", " ".join(result["limitations"]))


if __name__ == "__main__":
    unittest.main()
