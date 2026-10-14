"""Cautious, standard-library-only email header analysis."""

import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import getaddresses
from typing import Any

from ip_geolocation import lookup_ip_location


_SENDER_HEADERS = ("From", "Reply-To", "Return-Path", "Sender")
_AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-z][a-z0-9_-]*)\b", re.IGNORECASE
)
_IPV4_CANDIDATE_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f:.]*(?![0-9A-Fa-f:])")
_IPV6_MARKED_RE = re.compile(r"\bIPv6:\s*([0-9A-Fa-f:]+)", re.IGNORECASE)
_AUTH_PASS_RESULTS = {"pass"}
_AUTH_FAIL_RESULTS = {"fail"}


def _header_values(message: Message, name: str) -> list[str]:
    return [str(value).strip() for value in message.get_all(name, [])]


def _addresses(values: list[str]) -> list[dict[str, str]]:
    parsed: list[dict[str, str]] = []
    for display_name, address in getaddresses(values):
        display_name = display_name.strip()
        address = address.strip()
        if address or display_name:
            parsed.append({"display_name": display_name, "address": address})
    return parsed


def _domains(addresses: list[dict[str, str]]) -> set[str]:
    domains: set[str] = set()
    for item in addresses:
        address = item["address"]
        if "@" not in address:
            continue
        domain = address.rsplit("@", 1)[1].strip().rstrip(".").casefold()
        if domain:
            domains.add(domain)
    return domains


def _extract_ips(text: str) -> list[str]:
    found: list[str] = []
    candidates = _IPV4_CANDIDATE_RE.findall(text)
    marked_ipv6 = _IPV6_MARKED_RE.findall(text)
    candidates.extend(marked_ipv6)
    unmarked_text = _IPV6_MARKED_RE.sub(" ", text)
    candidates.extend(_IPV6_CANDIDATE_RE.findall(unmarked_text))
    for candidate in candidates:
        try:
            normalized = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if normalized not in found:
            found.append(normalized)
    return found


def _add_finding(
    findings: list[dict[str, str]], severity: str, code: str, explanation: str
) -> None:
    findings.append(
        {"severity": severity, "code": code, "explanation": explanation}
    )


def _auth_results(
    auth_headers: list[str], spf_headers: list[str]
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for header in auth_headers:
        for method, result in _AUTH_RESULT_RE.findall(header):
            results.append(
                {
                    "method": method.casefold(),
                    "result": result.casefold(),
                    "source": "Authentication-Results",
                }
            )
    for header in spf_headers:
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9_-]*)", header)
        if match:
            results.append(
                {
                    "method": "spf",
                    "result": match.group(1).casefold(),
                    "source": "Received-SPF",
                }
            )
    return results


def _parse_message(raw_email: str | bytes) -> Message:
    if isinstance(raw_email, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw_email)
    if isinstance(raw_email, str):
        return Parser(policy=policy.default).parsestr(raw_email)
    raise TypeError("raw_email must be str or bytes")


def analyze_email(raw_email: str | bytes) -> dict[str, Any]:
    """Parse an email and return extracted headers and cautious review findings.

    Findings identify evidence to review; they do not determine whether a
    message is malicious or whether an authentication result is trustworthy.
    """
    findings: list[dict[str, str]] = []
    try:
        message = _parse_message(raw_email)
    except (TypeError, ValueError, UnicodeError) as error:
        explanation = f"Email could not be parsed: {type(error).__name__}: {error}"
        return {
            "fields": {
                "from": [],
                "reply_to": [],
                "return_path": [],
                "sender": [],
                "subject": [],
                "date": [],
                "message_id": [],
                "received": [],
                "authentication_results": [],
                "received_spf": [],
                "ip_geolocation": {
                    "results": [],
                    "explanation": "No IP address could be extracted because the message could not be parsed.",
                },
            },
            "findings": [
                {
                    "severity": "warning",
                    "code": "parse_error",
                    "explanation": explanation,
                }
            ],
            "summary": "The message could not be parsed; header analysis is incomplete.",
        }

    raw_fields = {
        "from": _header_values(message, "From"),
        "reply_to": _header_values(message, "Reply-To"),
        "return_path": _header_values(message, "Return-Path"),
        "sender": _header_values(message, "Sender"),
        "subject": _header_values(message, "Subject"),
        "date": _header_values(message, "Date"),
        "message_id": _header_values(message, "Message-ID"),
    }
    received_headers = _header_values(message, "Received")
    auth_headers = _header_values(message, "Authentication-Results")
    spf_headers = _header_values(message, "Received-SPF")

    fields: dict[str, Any] = {
        **raw_fields,
        "received": [
            {"raw": header, "ip_addresses": _extract_ips(header)}
            for header in received_headers
        ],
        "authentication_results": auth_headers,
        "received_spf": spf_headers,
    }
    unique_ips: list[str] = []
    for received in fields["received"]:
        for ip_address in received["ip_addresses"]:
            if ip_address not in unique_ips:
                unique_ips.append(ip_address)
    geolocation_results = [lookup_ip_location(ip) for ip in unique_ips]
    fields["ip_geolocation"] = {
        "results": geolocation_results,
        "explanation": (
            "No IP address could be extracted from Received headers."
            if not geolocation_results
            else (
                "Results only classify addresses. No external lookup was made; "
                "a geolocation estimate, if later configured, would describe a "
                "network endpoint and not necessarily the sender's physical location."
            )
        ),
    }

    parsed_addresses = {
        header.casefold().replace("-", "_"): _addresses(raw_fields[header.casefold().replace("-", "_")])
        for header in _SENDER_HEADERS
    }
    fields["sender_addresses"] = parsed_addresses

    from_domains = _domains(parsed_addresses["from"])
    reply_domains = _domains(parsed_addresses["reply_to"])
    return_path_domains = _domains(parsed_addresses["return_path"])
    if from_domains and reply_domains and from_domains != reply_domains:
        _add_finding(
            findings,
            "warning",
            "from_reply_to_domain_mismatch",
            "The From and Reply-To domains differ; this can be legitimate, but warrants review.",
        )
    if from_domains and return_path_domains and from_domains != return_path_domains:
        _add_finding(
            findings,
            "warning",
            "from_return_path_domain_mismatch",
            "The From and Return-Path domains differ; forwarding and mailing systems can cause this, so it is not proof of abuse.",
        )

    for header_name in _SENDER_HEADERS:
        key = header_name.casefold().replace("-", "_")
        values = raw_fields[key]
        address_count = len(parsed_addresses[key])
        if len(values) > 1 or address_count > 1:
            _add_finding(
                findings,
                "warning",
                f"multiple_{key}_values",
                f"{header_name} contains {len(values)} header value(s) and {address_count} parsed address value(s); review the message context.",
            )

    auth_results = _auth_results(auth_headers, spf_headers)
    fields["authentication_checks"] = auth_results
    for check in auth_results:
        if check["result"] in _AUTH_FAIL_RESULTS:
            _add_finding(
                findings,
                "warning",
                f"{check['method']}_failure_reported",
                f"{check['source']} explicitly reports {check['method'].upper()}={check['result']}; this is a reported result, not by itself a final verdict on the message.",
            )

    if not auth_headers:
        _add_finding(
            findings,
            "informational",
            "authentication_results_missing",
            "No Authentication-Results header is present; authentication status is unknown or only partly reported, not necessarily failed.",
        )
    reported_methods = {check["method"] for check in auth_results}
    expected_methods = {"spf", "dkim", "dmarc"}
    if (
        not auth_results
        or not expected_methods.issubset(reported_methods)
        or any(
            check["result"] not in _AUTH_PASS_RESULTS | _AUTH_FAIL_RESULTS
            for check in auth_results
        )
    ):
        _add_finding(
            findings,
            "informational",
            "authentication_results_inconclusive",
            "One or more SPF, DKIM, or DMARC results are missing or do not report pass/fail; the available results are incomplete or inconclusive.",
        )

    if findings:
        summary = (
            f"Found {len(findings)} header item(s) that may warrant review. "
            "These signals are not proof that the message is malicious."
        )
    else:
        summary = (
            "No configured header warning was identified. This is not proof that "
            "the message is safe."
        )

    return {"fields": fields, "findings": findings, "summary": summary}
