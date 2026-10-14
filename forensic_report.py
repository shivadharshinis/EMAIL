"""Deterministic, privacy-conscious plain-text forensic report formatting."""

import ipaddress
import re
from typing import Any


_ALLOWED_LEVELS = {"Low", "Medium", "High", "Inconclusive"}
_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_-]{1,80}$")
_ALLOWED_ML = {"spam", "legitimate", "unavailable"}


def _safe_lines(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item.replace("\r", " ").replace("\n", " ")[:240]
        for item in value
        if isinstance(item, str)
    ]


def format_forensic_report(assessment: Any) -> str:
    """Format an assessment without rendering raw email or arbitrary evidence."""
    if not isinstance(assessment, dict):
        assessment = {}

    level = assessment.get("risk_level")
    if level not in _ALLOWED_LEVELS:
        level = "Inconclusive"
    ml_prediction = assessment.get("ml_prediction")
    if ml_prediction not in _ALLOWED_ML:
        ml_prediction = "unavailable"

    reasons = _safe_lines(assessment.get("risk_reasons"))
    action = assessment.get("recommended_action")
    if not isinstance(action, str):
        action = "Restore missing analysis data and review the message manually."
    action = action.replace("\r", " ").replace("\n", " ")[:300]
    limitations = _safe_lines(assessment.get("limitations"))

    lines = [
        "EMAIL FORENSIC REVIEW",
        "=====================",
        f"Overall review priority: {level}",
        "",
        "ML prediction",
        "-------------",
        ml_prediction,
        "",
        "Important findings by source",
        "----------------------------",
    ]

    header_findings = assessment.get("header_findings")
    if isinstance(header_findings, list) and header_findings:
        lines.append("Header forensics:")
        for finding in header_findings:
            if not isinstance(finding, dict):
                continue
            code = finding.get("code")
            severity = finding.get("severity")
            if isinstance(code, str) and _SAFE_IDENTIFIER.fullmatch(code):
                safe_severity = severity if severity in {"warning", "informational"} else "unspecified"
                lines.append(f"  - [{safe_severity}] {code}")
    else:
        lines.append("Header forensics: no reported findings.")

    threat_findings = assessment.get("threat_findings")
    if isinstance(threat_findings, list) and threat_findings:
        lines.append("Local threat indicators:")
        for finding in threat_findings:
            if not isinstance(finding, dict):
                continue
            indicator_type = finding.get("type")
            severity = finding.get("severity")
            if isinstance(indicator_type, str) and _SAFE_IDENTIFIER.fullmatch(indicator_type):
                safe_severity = severity if severity in {"warning", "informational"} else "unspecified"
                lines.append(f"  - [{safe_severity}] {indicator_type}")
    else:
        lines.append("Local threat indicators: no reported findings.")

    lines.extend(["", "IP information", "--------------"])
    ip_information = assessment.get("ip_information")
    if not isinstance(ip_information, dict):
        lines.append("IP lookup status: unavailable.")
        lines.append("No location has been inferred.")
    else:
        status = ip_information.get("lookup_status")
        safe_status = status if isinstance(status, str) and _SAFE_IDENTIFIER.fullmatch(status) else "unavailable"
        lines.append(f"IP lookup status: {safe_status}.")
        addresses = ip_information.get("addresses")
        valid_addresses: list[tuple[str, str]] = []
        if isinstance(addresses, list):
            for item in addresses:
                if not isinstance(item, dict):
                    continue
                raw_ip = item.get("ip_address")
                lookup_status = item.get("lookup_status")
                if not isinstance(raw_ip, str) or not isinstance(lookup_status, str):
                    continue
                try:
                    normalized_ip = str(ipaddress.ip_address(raw_ip))
                except ValueError:
                    continue
                if _SAFE_IDENTIFIER.fullmatch(lookup_status):
                    valid_addresses.append((normalized_ip, lookup_status))
        if valid_addresses:
            for address, lookup_status in valid_addresses:
                lines.append(f"  - {address}: {lookup_status}; location not available.")
        else:
            lines.append("No validated IP lookup result is available.")
        lines.append("IP geolocation estimates a network endpoint, not necessarily the sender's location.")

    lines.extend(["", "Risk reasons", "------------"])
    if reasons:
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append("No specific risk reasons were supplied.")

    lines.extend(
        [
            "",
            "Recommended next action",
            "-----------------------",
            action,
            "",
            "Limitations and uncertainty",
            "----------------------------",
        ]
    )
    if limitations:
        lines.extend(f"- {limitation}" for limitation in limitations)
    else:
        lines.append("- Assessment is incomplete or lacks supplied limitations.")
    lines.extend(
        [
            "- Local indicators and classifier output are not proof of malicious activity.",
            "- This report does not include the raw message body or full email content.",
        ]
    )
    return "\n".join(lines)
