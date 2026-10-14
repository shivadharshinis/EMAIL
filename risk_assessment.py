"""Transparent, cautious risk-priority rules for analyzer output."""

from typing import Any


_FINDING_CATEGORIES = {
    "from_reply_to_domain_mismatch": "sender_domain_mismatch",
    "from_return_path_domain_mismatch": "sender_domain_mismatch",
    "sender_domain_mismatch": "sender_domain_mismatch",
    "spf_failure_reported": "authentication_failure",
    "dkim_failure_reported": "authentication_failure",
    "dmarc_failure_reported": "authentication_failure",
    "url_visible_domain_mismatch": "visible_url_mismatch",
    "url_contains_userinfo": "url_userinfo",
    "malformed_sender_address": "malformed_sender",
    "malformed_sender_domain": "malformed_sender",
    "malformed_url": "malformed_url",
    "multiple_from_values": "multiple_sender_values",
    "multiple_reply_to_values": "multiple_sender_values",
    "multiple_return_path_values": "multiple_sender_values",
}

_REASON_TEXT = {
    "ml_spam_prediction": "The existing text classifier predicts spam; this is a review signal, not proof of fraud.",
    "sender_domain_mismatch": "Sender-related domains differ; forwarding or mail-system configuration may explain this.",
    "authentication_failure": "An email authentication result explicitly reports a failure; verify it with a trusted receiving system.",
    "visible_url_mismatch": "A URL's visible domain differs from its link destination; this is a heuristic that warrants review.",
    "url_userinfo": "A URL uses user-information syntax that can obscure its destination; inspect it without opening it.",
    "malformed_sender": "A sender-related address or domain is malformed and could not be reliably interpreted.",
    "malformed_url": "A URL-like value did not have a reliably parseable host.",
    "multiple_sender_values": "Multiple sender-related values are present and warrant context-specific review.",
    "other_header_warning": "Header forensics reported a warning that warrants review.",
    "other_threat_warning": "Local threat-indicator checks reported a warning that warrants review.",
}

_BASE_LIMITATIONS = [
    "Risk levels are explainable review priorities, not probabilities, proof of fraud, or automated verdicts.",
    "The spam classifier was trained for SpamAssassin spam-versus-ham classification; it does not establish phishing, business email compromise, or impersonation.",
    "Local domain and URL indicators are heuristics. Live reputation checking is not configured.",
    "IP geolocation is not configured. Private, loopback, and other non-public addresses are not public attacker locations.",
    "Missing authentication results are not treated as evidence of maliciousness.",
]


def _as_findings(value: Any) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(value, list):
        return [], False
    return [item for item in value if isinstance(item, dict)], True


def _finding_category(finding: dict[str, Any], source: str) -> str:
    code = finding.get("code") if source == "header" else finding.get("type")
    if isinstance(code, str) and code in _FINDING_CATEGORIES:
        return _FINDING_CATEGORIES[code]
    return "other_header_warning" if source == "header" else "other_threat_warning"


def _ip_information(analysis_result: dict[str, Any]) -> dict[str, Any]:
    fields = analysis_result.get("header_fields")
    if not isinstance(fields, dict):
        return {
            "addresses": [],
            "lookup_status": "unavailable",
            "explanation": "The header analyzer did not expose IP geolocation results.",
        }

    geo = fields.get("ip_geolocation")
    if not isinstance(geo, dict):
        return {
            "addresses": [],
            "lookup_status": "unavailable",
            "explanation": "IP geolocation results are missing or malformed.",
        }

    results = geo.get("results")
    if not isinstance(results, list):
        return {
            "addresses": [],
            "lookup_status": "unavailable",
            "explanation": "IP geolocation results are missing or malformed.",
        }

    addresses: list[dict[str, Any]] = []
    statuses: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        ip_address = result.get("ip_address")
        status = result.get("lookup_status")
        if isinstance(ip_address, str) and isinstance(status, str):
            addresses.append(
                {
                    "ip_address": ip_address,
                    "is_globally_routable": result.get("is_globally_routable"),
                    "lookup_status": status,
                    "address_categories": result.get("address_categories", []),
                }
            )
            statuses.add(status)
    unique_addresses: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in addresses:
        key = (item["ip_address"], item["lookup_status"])
        if key not in seen:
            unique_addresses.append(item)
            seen.add(key)

    if not unique_addresses:
        lookup_status = "no_ip_found"
    elif len(statuses) == 1:
        lookup_status = next(iter(statuses))
    else:
        lookup_status = "mixed"
    return {
        "addresses": unique_addresses,
        "lookup_status": lookup_status,
        "explanation": str(geo.get("explanation", "")),
    }


def build_risk_assessment(analysis_result: Any) -> dict[str, Any]:
    """Build a report-ready assessment from ``analyze_email_message`` output.

    Rules: a spam prediction or a single warning sets Medium review priority;
    High requires at least two distinct meaningful signal categories across
    the model and warnings after equivalent header/threat domain-mismatch
    findings are deduplicated. A missing/unavailable prediction or missing
    core finding lists is Inconclusive. No numerical confidence or probability
    is calculated.
    """
    if not isinstance(analysis_result, dict):
        analysis_result = {}

    ml_prediction = analysis_result.get("ml_prediction")
    ml_label = analysis_result.get("ml_label")
    if ml_prediction not in {"spam", "legitimate"}:
        ml_prediction = "unavailable"
        ml_label = None
    elif ml_label not in {0, 1}:
        ml_label = 1 if ml_prediction == "spam" else 0

    header_findings, has_header_data = _as_findings(
        analysis_result.get("forensic_findings")
    )
    threat_findings = analysis_result.get("threat_intelligence_findings")
    threat_data_present = isinstance(threat_findings, list)
    if not threat_data_present:
        threat_object = analysis_result.get("threat_intelligence")
        if isinstance(threat_object, dict):
            threat_findings = threat_object.get("findings")
            threat_data_present = isinstance(threat_findings, list)
    threat_findings, _ = _as_findings(threat_findings)

    ip_information = _ip_information(analysis_result)
    reasons_by_category: dict[str, str] = {}
    warning_categories: set[str] = set()

    if ml_prediction == "spam":
        reasons_by_category["ml_spam_prediction"] = _REASON_TEXT["ml_spam_prediction"]

    for finding in header_findings:
        if finding.get("severity") != "warning":
            continue
        category = _finding_category(finding, "header")
        warning_categories.add(category)
        reasons_by_category.setdefault(category, _REASON_TEXT[category])

    for finding in threat_findings:
        if finding.get("severity") != "warning":
            continue
        category = _finding_category(finding, "threat")
        warning_categories.add(category)
        reasons_by_category.setdefault(category, _REASON_TEXT[category])

    assessment_available = (
        ml_prediction != "unavailable"
        and has_header_data
        and threat_data_present
    )
    if not assessment_available:
        risk_level = "Inconclusive"
        recommended_action = (
            "Restore or rerun the unavailable analysis component before relying "
            "on an overall review priority."
        )
        reasons = [
            "One or more required analysis outputs are missing, malformed, or unavailable."
        ]
    else:
        independent_categories = set(warning_categories)
        if ml_prediction == "spam":
            independent_categories.add("ml_spam_prediction")

        if len(independent_categories) >= 2:
            risk_level = "High"
            recommended_action = (
                "Prioritize manual review. Verify the message through trusted "
                "channels and inspect the reported headers and URLs without opening "
                "untrusted links."
            )
        elif independent_categories:
            risk_level = "Medium"
            recommended_action = (
                "Review the indicated evidence in context. Do not treat the "
                "classifier or a single heuristic as proof."
            )
        else:
            risk_level = "Low"
            recommended_action = (
                "No configured warning was identified; handle using normal "
                "email-safety practices because this is not a safety guarantee."
            )
        reasons = [
            reasons_by_category[key] for key in sorted(reasons_by_category)
        ]
        if not reasons:
            reasons = ["No configured warning signals were present in the supplied analysis."]

    limitations = list(_BASE_LIMITATIONS)
    threat_object = analysis_result.get("threat_intelligence")
    reputation = (
        threat_object.get("reputation")
        if isinstance(threat_object, dict)
        else None
    )
    if not isinstance(reputation, dict) or reputation.get("status") != "configured":
        limitations.append("No live threat-intelligence provider response is available.")

    return {
        "ml_prediction": ml_prediction,
        "ml_label": ml_label,
        "header_findings": header_findings,
        "ip_information": ip_information,
        "threat_findings": threat_findings,
        "risk_level": risk_level,
        "risk_reasons": reasons,
        "recommended_action": recommended_action,
        "limitations": limitations,
    }
