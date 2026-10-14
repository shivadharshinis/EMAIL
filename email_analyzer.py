"""Combine the saved spam classifier with cautious header-forensics findings."""

import codecs
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import joblib
from sklearn.pipeline import Pipeline

from header_analyzer import analyze_email
from forensic_report import format_forensic_report
from risk_assessment import build_risk_assessment
from threat_intelligence import analyze_threat_indicators


MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_spam_model.joblib"

LIMITATIONS = [
    "The classifier was trained for SpamAssassin spam-versus-ham classification; it does not establish phishing, business email compromise, or impersonation detection.",
    "The classifier uses subject and body text only; forensic header findings are not model features.",
    "Header mismatches and missing authentication results are review signals, not proof of malicious activity.",
    "Headers may be missing, malformed, or forged, and authentication headers are most useful when added by a trusted receiving system.",
    "IP addresses extracted from Received headers do not identify the human sender, their device, or exact location.",
    "This component does not perform geolocation lookups or external verification.",
]

_HTML_BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
    "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
    "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol",
    "p", "pre", "section", "table", "td", "th", "tr", "ul",
}


class _ReadableHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._ignored_tags.append(tag)
        elif not self._ignored_tags and tag in _HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self._ignored_tags and tag in _HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_tags:
            if tag == self._ignored_tags[-1]:
                self._ignored_tags.pop()
        elif tag in _HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored_tags:
            self.parts.append(data)


def _parse_email(raw_email: str | bytes) -> Message:
    if isinstance(raw_email, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw_email)
    if isinstance(raw_email, str):
        return Parser(policy=policy.default).parsestr(raw_email)
    raise TypeError("raw_email must be str or bytes")


def _decode_body_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        content = part.get_payload()
        return content if isinstance(content, str) else ""

    charset = part.get_content_charset() or "utf-8"
    try:
        codec = codecs.lookup(charset)
    except LookupError:
        codec = codecs.lookup("utf-8")
    try:
        return payload.decode(codec.name)
    except UnicodeError:
        return payload.decode(codec.name, errors="replace")


def _html_to_text(content: str) -> str:
    parser = _ReadableHTML()
    parser.feed(content)
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line)


def _extract_body(message: Message) -> str:
    plain_part = message.get_body(preferencelist=("plain",))
    if plain_part is not None:
        return _decode_body_part(plain_part).strip()

    html_part = message.get_body(preferencelist=("html",))
    if html_part is not None:
        return _html_to_text(_decode_body_part(html_part)).strip()

    if message.get_content_maintype() == "text":
        content = _decode_body_part(message)
        if message.get_content_subtype() == "html":
            return _html_to_text(content).strip()
        return content.strip()
    return ""


@lru_cache(maxsize=1)
def _load_pipeline() -> Pipeline:
    loaded = joblib.load(MODEL_PATH)
    if not isinstance(loaded, Pipeline):
        raise TypeError("Saved model is not a scikit-learn Pipeline.")
    return loaded


def _empty_forensics(explanation: str) -> dict[str, Any]:
    return {
        "findings": [
            {
                "severity": "warning",
                "code": "forensic_analysis_unavailable",
                "explanation": explanation,
            }
        ],
        "summary": "Header analysis could not be completed.",
    }


def _add_assessment(result: dict[str, Any]) -> dict[str, Any]:
    assessment = build_risk_assessment(result)
    result["risk_assessment"] = assessment
    result["forensic_report"] = format_forensic_report(assessment)
    return result


def _overall_assessment(
    ml_prediction: str,
    forensic_findings: list[dict[str, Any]],
    threat_findings: list[dict[str, Any]] | None = None,
) -> str:
    threat_findings = threat_findings or []
    has_header_warning = any(
        finding.get("severity") == "warning" for finding in forensic_findings
    )
    has_threat_warning = any(
        finding.get("severity") == "warning" for finding in threat_findings
    )
    has_warning = has_header_warning or has_threat_warning
    if ml_prediction == "unavailable":
        return (
            "The text classifier could not provide a prediction. Review any "
            "header-forensics and local threat indicators separately; no combined "
            "verdict is available."
        )
    if ml_prediction == "spam" and has_warning:
        return (
            "The text classifier predicts spam, and header-forensics or local "
            "threat-indicator evidence also includes items to review. These are "
            "separate signals, not proof of malicious activity."
        )
    if ml_prediction == "legitimate" and has_warning:
        return (
            "The text classifier predicts legitimate/ham, while header analysis "
            "or local threat-indicator analysis flags items to review. The signals "
            "disagree; neither overrides the other or proves the message safe or malicious."
        )
    if ml_prediction == "spam":
        return (
            "The text classifier predicts spam, while header-forensics and local "
            "threat-indicator analysis found no configured warning. The independent "
            "signals do not confirm one another."
        )
    return (
        "The text classifier predicts legitimate/ham, and header-forensics and "
        "local threat-indicator analysis found no configured warning. This does "
        "not prove the message is safe."
    )


def analyze_email_message(raw_email: str | bytes) -> dict[str, Any]:
    """Return an ML prediction and independent email-header forensic findings.

    The function neither stores nor logs the supplied email content. If the
    message cannot be parsed, the classifier is unavailable for that message;
    if the model cannot be loaded, forensic analysis can still be returned.
    """
    try:
        message = _parse_email(raw_email)
    except (TypeError, ValueError, UnicodeError) as error:
        forensic = _empty_forensics(
            f"Email could not be parsed: {type(error).__name__}."
        )
        return _add_assessment({
            "ml_prediction": "unavailable",
            "ml_label": None,
            "forensic_findings": forensic["findings"],
            "forensic_summary": forensic["summary"],
            "header_fields": {
                "received": [],
                "ip_geolocation": {
                    "results": [],
                    "explanation": "No IP information is available because the message could not be parsed.",
                },
            },
            "threat_intelligence_findings": [
                {
                    "type": "parse_error",
                    "severity": "warning",
                    "explanation": "Threat indicators could not be analyzed because the input could not be parsed.",
                    "evidence": {},
                }
            ],
            "threat_intelligence": {
                "sender_domains": {"from": [], "reply_to": [], "return_path": []},
                "urls": [],
                "url_domains": [],
                "reputation": {
                    "status": "not_configured",
                    "provider": None,
                    "explanation": "No live threat-intelligence provider is configured; no external request was made.",
                },
                "summary": "Local threat-indicator analysis is incomplete because the input could not be parsed.",
            },
            "overall_assessment": (
                "No classifier prediction is available because the input could not "
                "be parsed. Header-forensics and threat-indicator analysis are also incomplete."
            ),
            "limitations": LIMITATIONS.copy(),
        })

    try:
        subject_value = message.get("Subject")
        subject = str(subject_value).strip() if subject_value is not None else ""
        body = _extract_body(message)
    except (LookupError, UnicodeError, ValueError, TypeError):
        subject = ""
        body = ""

    text = (subject + " " + body).strip()

    try:
        pipeline = _load_pipeline()
        prediction = int(pipeline.predict([text])[0])
        if prediction not in {0, 1}:
            raise ValueError("Saved pipeline returned a label other than 0 or 1.")
        ml_label: int | None = prediction
        ml_prediction = "spam" if prediction == 1 else "legitimate"
    except (OSError, ValueError, TypeError, EOFError, ImportError, AttributeError):
        ml_label = None
        ml_prediction = "unavailable"

    try:
        forensic = analyze_email(raw_email)
        forensic_findings = forensic.get("findings", [])
        forensic_summary = forensic.get(
            "summary", "Header analyzer did not provide a summary."
        )
    except (TypeError, ValueError, UnicodeError, LookupError):
        forensic = _empty_forensics("The existing header analyzer could not parse the input.")
        forensic_findings = forensic["findings"]
        forensic_summary = forensic["summary"]

    try:
        threat_result = analyze_threat_indicators(raw_email)
        threat_findings = threat_result.get("findings", [])
    except (TypeError, ValueError, UnicodeError, LookupError):
        threat_result = {
            "sender_domains": {"from": [], "reply_to": [], "return_path": []},
            "urls": [],
            "url_domains": [],
            "findings": [
                {
                    "type": "analysis_unavailable",
                    "severity": "warning",
                    "explanation": "Local threat-indicator analysis could not be completed.",
                    "evidence": {},
                }
            ],
            "reputation": {
                "status": "not_configured",
                "provider": None,
                "explanation": "No live threat-intelligence provider is configured; no external request was made.",
            },
            "summary": "Local threat-indicator analysis could not be completed.",
        }
        threat_findings = threat_result["findings"]

    result = {
        "ml_prediction": ml_prediction,
        "ml_label": ml_label,
        "forensic_findings": forensic_findings,
        "forensic_summary": forensic_summary,
        "header_fields": forensic.get("fields", {}),
        "threat_intelligence_findings": threat_findings,
        "threat_intelligence": threat_result,
        "overall_assessment": _overall_assessment(
            ml_prediction, forensic_findings, threat_findings
        ),
        "limitations": LIMITATIONS.copy(),
    }
    return _add_assessment(result)
