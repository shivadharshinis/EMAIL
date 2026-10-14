"""Synthetic API tests. These tests never send email or make network requests."""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from api import app


SYNTHETIC_EMAIL = """\
From: Alex Example <alex@example.test>
Subject: Meeting notes
Content-Type: text/plain; charset=utf-8

Hi team, here are the synthetic meeting notes.
"""


class EmailAnalysisApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_root_endpoint_returns_project_and_api_status(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        self.assertIn("Email Threat Detection", response.json()["project"])

    def test_health_endpoint_reports_model_modules_and_unconfigured_providers(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["model"]["exists"])
        self.assertTrue(body["model"]["loadable"])
        self.assertTrue(all(body["analysis_modules"].values()))
        self.assertEqual(body["providers"]["ip_geolocation"], "not_configured")
        self.assertEqual(body["providers"]["threat_reputation"], "not_configured")
        self.assertNotIn("C:\\", response.text)

    def test_valid_analysis_returns_compatible_separate_result_fields(self) -> None:
        response = self.client.post("/analyze", json={"raw_email": SYNTHETIC_EMAIL})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn(body["ml_prediction"], {"spam", "legitimate"})
        self.assertIn(body["ml_label"], {0, 1})
        self.assertIsInstance(body["forensic_findings"], list)
        self.assertIsInstance(body["ip_information"]["addresses"], list)
        self.assertEqual(body["threat_reputation"]["status"], "not_configured")
        self.assertIn(body["risk_assessment"]["risk_level"], {
            "Low", "Medium", "High", "Inconclusive"
        })
        self.assertIn("EMAIL FORENSIC REVIEW", body["forensic_report"])
        self.assertNotIn("raw_email", body)
        self.assertNotIn("Hi team, here are the synthetic meeting notes.", response.text)

    def test_analysis_adds_existing_sender_authentication_and_url_evidence(self) -> None:
        raw_email = """\
From: Alex <alex@example.test>
Reply-To: Alex <reply@example.test>
Return-Path: <bounce@example.test>
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Received: from relay.example.test ([192.0.2.25]) by mx.example.test
Content-Type: text/plain; charset=utf-8

Synthetic details at https://docs.example.test/guide.
"""
        response = self.client.post("/analyze", json={"raw_email": raw_email})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["sender_addresses"]["from"][0]["address"], "alex@example.test")
        self.assertEqual(body["sender_addresses"]["reply_to"][0]["address"], "reply@example.test")
        self.assertEqual(body["authentication_checks"][0]["method"], "spf")
        self.assertEqual(body["authentication_checks"][0]["result"], "pass")
        self.assertEqual(body["detected_urls"][0]["host"], "docs.example.test")

    def test_missing_or_empty_raw_email_is_rejected(self) -> None:
        missing = self.client.post("/analyze", json={})
        empty = self.client.post("/analyze", json={"raw_email": " \n "})

        self.assertEqual(missing.status_code, 422)
        self.assertEqual(empty.status_code, 422)
        self.assertNotIn("input", missing.text)

    def test_oversized_email_is_rejected_with_payload_too_large(self) -> None:
        response = self.client.post(
            "/analyze",
            json={"raw_email": "x" * (1024 * 1024 + 1)},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json()["detail"],
            "raw_email exceeds the 1 MiB size limit.",
        )

    def test_malformed_json_and_invalid_request_types_are_safe(self) -> None:
        malformed = self.client.post(
            "/analyze",
            content=b'{"raw_email": ',
            headers={"content-type": "application/json"},
        )
        wrong_type = self.client.post("/analyze", json={"raw_email": ["not", "text"]})

        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(malformed.json(), {"detail": "Malformed JSON request."})
        self.assertEqual(wrong_type.status_code, 422)
        self.assertNotIn("not", wrong_type.text)

    def test_internal_error_response_does_not_echo_email_or_traceback(self) -> None:
        secret_marker = "SYNTHETIC_PRIVATE_BODY_MARKER"
        with patch("api.analyze_email_message", side_effect=RuntimeError(secret_marker)):
            response = self.client.post(
                "/analyze",
                json={"raw_email": f"Subject: test\n\n{secret_marker}"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(secret_marker, response.text)
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("C:\\Users", response.text)

    def test_malformed_analyzer_result_fails_safely(self) -> None:
        with patch("api.analyze_email_message", return_value={"ml_prediction": "spam"}):
            response = self.client.post("/analyze", json={"raw_email": SYNTHETIC_EMAIL})

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {"detail": "Email analysis failed. No message content was stored."},
        )


if __name__ == "__main__":
    unittest.main()
