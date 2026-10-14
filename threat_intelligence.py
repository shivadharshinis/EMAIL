"""Local-only email domain and URL indicators; no reputation provider calls."""

import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit


_SENDER_HEADERS = ("From", "Reply-To", "Return-Path")
_URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


def _raw_header_values(message: Message, header_name: str) -> list[str]:
    target = header_name.casefold()
    return [
        str(value).strip()
        for name, value in message.raw_items()
        if name.casefold() == target
    ]


class _BodyHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []
        self._ignored_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in {"script", "style"}:
            self._ignored_tags.append(tag)
        elif tag == "a" and not self._ignored_tags:
            self._anchor_href = attributes.get("href")
            self._anchor_text = []
        elif tag in {"br", "p", "div", "li", "tr", "td", "h1", "h2", "h3"}:
            self.text_parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_tags:
            if tag == self._ignored_tags[-1]:
                self._ignored_tags.pop()
        elif tag == "a" and self._anchor_href is not None:
            self.links.append((self._anchor_href.strip(), "".join(self._anchor_text).strip()))
            self._anchor_href = None
            self._anchor_text = []
        elif tag in {"p", "div", "li", "tr", "td", "h1", "h2", "h3"}:
            self.text_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored_tags:
            self.text_parts.append(data)
            if self._anchor_href is not None:
                self._anchor_text.append(data)


def _parse_message(raw_email: str | bytes) -> Message:
    if isinstance(raw_email, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw_email)
    if isinstance(raw_email, str):
        return Parser(policy=policy.default).parsestr(raw_email)
    raise TypeError("raw_email must be str or bytes")


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return value if isinstance(value, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _body_content(message: Message) -> tuple[str, list[tuple[str, str]]]:
    plain = message.get_body(preferencelist=("plain",))
    if plain is not None:
        return _decode_part(plain), []

    html = message.get_body(preferencelist=("html",))
    if html is not None:
        parser = _BodyHTMLParser()
        parser.feed(_decode_part(html))
        parser.close()
        return "".join(parser.text_parts), parser.links

    if message.get_content_maintype() == "text":
        content = _decode_part(message)
        if message.get_content_subtype() == "html":
            parser = _BodyHTMLParser()
            parser.feed(content)
            parser.close()
            return "".join(parser.text_parts), parser.links
        return content, []
    return "", []


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".")
    if not candidate or candidate.startswith("[") or candidate.endswith("]"):
        return None
    try:
        ascii_domain = candidate.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return None
    if len(ascii_domain) > 253:
        return None
    labels = ascii_domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_domain


def _sender_domains(
    message: Message, findings: list[dict[str, Any]]
) -> dict[str, list[str]]:
    domains_by_header: dict[str, list[str]] = {}
    for header_name in _SENDER_HEADERS:
        domains: list[str] = []
        values = _raw_header_values(message, header_name)
        for display_name, address in getaddresses(values):
            address = address.strip()
            if not address or address.count("@") != 1:
                if address or display_name.strip():
                    findings.append(
                        {
                            "type": "malformed_sender_address",
                            "severity": "warning",
                            "explanation": (
                                f"A {header_name} value could not be reliably parsed "
                                "as an email address; review the raw value."
                            ),
                            "evidence": {"header": header_name, "value": address or display_name.strip()},
                        }
                    )
                continue
            local_part, raw_domain = address.rsplit("@", 1)
            domain = _normalize_domain(raw_domain)
            if not local_part.strip() or domain is None:
                findings.append(
                    {
                        "type": "malformed_sender_domain",
                        "severity": "warning",
                        "explanation": (
                            f"A {header_name} address has a domain that is not a "
                            "well-formed DNS-style domain; this syntax warning is "
                            "not proof of malicious activity."
                        ),
                        "evidence": {"header": header_name, "value": address},
                    }
                )
                continue
            if domain not in domains:
                domains.append(domain)
        domains_by_header[header_name.casefold().replace("-", "_")] = domains

    from_domains = set(domains_by_header["from"])
    for header_name, key in (("Reply-To", "reply_to"), ("Return-Path", "return_path")):
        comparison_domains = set(domains_by_header[key])
        if from_domains and comparison_domains and from_domains != comparison_domains:
            findings.append(
                {
                    "type": "sender_domain_mismatch",
                    "severity": "warning",
                    "explanation": (
                        f"From and {header_name} domains differ; forwarding and "
                        "mailing configurations can explain this, so it warrants "
                        "review but is not proof of malicious activity."
                    ),
                    "evidence": {
                        "from_domains": sorted(from_domains),
                        f"{key}_domains": sorted(comparison_domains),
                    },
                }
            )
    return domains_by_header


def _strip_url_punctuation(value: str) -> str:
    return value.rstrip(_TRAILING_URL_PUNCTUATION)


def _url_host(value: str) -> tuple[str | None, bool, bool]:
    candidate = value.strip()
    if candidate.casefold().startswith("www."):
        candidate = "http://" + candidate
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        has_userinfo = parsed.username is not None or parsed.password is not None
    except ValueError:
        return None, False, False
    if not host:
        return None, has_userinfo, False
    try:
        normalized = str(ipaddress.ip_address(host))
        return normalized, has_userinfo, True
    except ValueError:
        normalized = _normalize_domain(host)
        return normalized, has_userinfo, normalized is not None


def _visible_host(value: str) -> str | None:
    candidate = value.strip().strip("<>()[]{}.,;:!?")
    if not candidate:
        return None
    if candidate.casefold().startswith("www.") or "://" in candidate:
        host, _, valid = _url_host(candidate)
        return host if valid else None
    if "@" in candidate or "/" in candidate or " " in candidate:
        return None
    return _normalize_domain(candidate)


def _extract_urls(body_text: str, html_links: list[tuple[str, str]]) -> list[dict[str, Any]]:
    urls: list[dict[str, Any]] = []

    def add_url(raw_url: str, source: str, visible_text: str | None = None) -> None:
        url = _strip_url_punctuation(raw_url.strip())
        if not url:
            return
        host, has_userinfo, valid_host = _url_host(url)
        record: dict[str, Any] = {
            "url": url,
            "host": host,
            "source": source,
        }
        if visible_text is not None:
            record["visible_text"] = visible_text
        if not any(existing["url"] == url for existing in urls):
            urls.append(record)

    for match in _URL_RE.findall(body_text):
        add_url(match, "body_text")
    for href, visible_text in html_links:
        if re.match(r"(?i)^(?:https?://|www\.)", href.strip()):
            add_url(href, "html_href", visible_text)

    return urls


def _url_findings(
    urls: list[dict[str, Any]], links: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for url in urls:
        host, has_userinfo, valid_host = _url_host(url["url"])
        if has_userinfo and host:
            findings.append(
                {
                    "type": "url_contains_userinfo",
                    "severity": "warning",
                    "explanation": (
                        "The URL includes user-information before its actual host, "
                        "a structure that can obscure the destination; review it "
                        "without opening the URL."
                    ),
                    "evidence": {"url": url["url"], "actual_host": host},
                }
            )
        elif not valid_host:
            findings.append(
                {
                    "type": "malformed_url",
                    "severity": "warning",
                    "explanation": "A URL-like value has no reliably parseable host; review it without opening it.",
                    "evidence": {"url": url["url"]},
                }
            )

    for href, visible_text in links:
        visible_host = _visible_host(visible_text)
        href_host, _, href_valid = _url_host(href)
        if visible_host and href_host and href_valid and visible_host != href_host:
            findings.append(
                {
                    "type": "url_visible_domain_mismatch",
                    "severity": "warning",
                    "explanation": (
                        "The visible link text names a different host from the link "
                        "destination; this comparison is a review indicator, not proof."
                    ),
                    "evidence": {
                        "visible_host": visible_host,
                        "destination_host": href_host,
                    },
                }
            )

    return findings


def analyze_threat_indicators(raw_email: str | bytes) -> dict[str, Any]:
    """Return local sender-domain and URL indicators without network access."""
    empty_result: dict[str, Any] = {
        "sender_domains": {"from": [], "reply_to": [], "return_path": []},
        "urls": [],
        "url_domains": [],
        "findings": [],
        "reputation": {
            "status": "not_configured",
            "provider": None,
            "explanation": "No live threat-intelligence provider is configured; no external request was made.",
        },
        "summary": "",
    }
    try:
        message = _parse_message(raw_email)
    except (TypeError, ValueError, UnicodeError) as error:
        empty_result["findings"] = [
            {
                "type": "parse_error",
                "severity": "warning",
                "explanation": f"Email could not be parsed: {type(error).__name__}.",
                "evidence": {},
            }
        ]
        empty_result["summary"] = (
            "Local threat-indicator analysis is incomplete because the message could not be parsed."
        )
        return empty_result

    findings: list[dict[str, Any]] = []
    sender_domains = _sender_domains(message, findings)
    body_text, html_links = _body_content(message)
    urls = _extract_urls(body_text, html_links)
    findings.extend(_url_findings(urls, html_links))
    unique_url_domains: list[str] = []
    for url in urls:
        if url["host"] and url["host"] not in unique_url_domains:
            unique_url_domains.append(url["host"])

    empty_result["sender_domains"] = sender_domains
    empty_result["urls"] = urls
    empty_result["url_domains"] = unique_url_domains
    empty_result["findings"] = findings
    if findings:
        empty_result["summary"] = (
            f"Found {len(findings)} local heuristic indicator(s) for review. "
            "No live reputation check was performed, and these indicators do not "
            "establish malicious intent."
        )
    else:
        empty_result["summary"] = (
            "No configured local heuristic indicator was identified. Live "
            "reputation checking is not configured, so this is not a safety verdict."
        )
    return empty_result
