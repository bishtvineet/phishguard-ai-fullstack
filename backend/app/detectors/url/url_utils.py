import html
import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Optional, Set, Tuple
from urllib.parse import urlsplit

from app.core.config import settings
from app.detectors.sender.domain_utils import _extractor
from app.schemas.analysis import Finding, FindingSeverity

# Bounded regex for opening <a> tag href attributes (resilience against unclosed/malformed tags)
_ANCHOR_HREF_RE = re.compile(
    r"""<a\b[^>]*?\bhref\s*=\s*(?P<quote>["'])(https?://[^\s"'<>]+)(?P=quote)""",
    re.IGNORECASE,
)

# Plain text URL regex
_PLAIN_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Punctuation commonly attached to plain-text URLs at end of sentences
_TRAILING_PUNCTUATION = ".,;:!?)[]}>\"'"


class SafeHTMLAnchorExtractor(HTMLParser):
    """Parses HTML document bodies to extract HTTP/HTTPS href targets from anchor tags."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() == "a":
            for attr_name, attr_val in attrs:
                if attr_name.lower() == "href" and attr_val:
                    unescaped = html.unescape(attr_val.strip())
                    if unescaped.lower().startswith(("http://", "https://")):
                        self.urls.append(unescaped)


@dataclass(frozen=True)
class ParsedURLComponents:
    raw_url: str
    normalized_url: str
    scheme: str
    netloc: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    subdomain: str
    registered_domain: str
    domain_label: str
    suffix: str
    is_ip: bool
    is_global_ip: bool
    has_userinfo: bool


def validate_and_normalize_url(url: str) -> Tuple[Optional[ParsedURLComponents], bool]:
    """Validates structural authority and port constraints, then applies conservative normalization.
    
    Returns:
        (components, is_malformed)
    """
    try:
        parts = urlsplit(url)
    except (ValueError, AttributeError):
        return None, True

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None, False

    netloc = parts.netloc
    if not netloc:
        return None, True

    # Userinfo presence
    has_userinfo = "@" in netloc

    # Hostname extraction & bracket validation
    try:
        hostname = parts.hostname
    except ValueError:
        return None, True

    if not hostname:
        return None, True

    hostname = hostname.lower()

    # Port extraction and validation
    explicit_port = None
    try:
        explicit_port = parts.port
    except ValueError:
        # Non-numeric or invalid port
        return None, True

    if explicit_port is not None and not (1 <= explicit_port <= 65535):
        return None, True

    # IP address validation
    is_ip = False
    is_global_ip = False
    # Strip brackets for IPv6 address object validation
    host_to_test = hostname[1:-1] if (hostname.startswith("[") and hostname.endswith("]")) else hostname
    try:
        ip_obj = ipaddress.ip_address(host_to_test)
        is_ip = True
        is_global_ip = ip_obj.is_global
    except ValueError:
        is_ip = False

    # Conservative normalization:
    # 1. Strip default ports
    effective_port = explicit_port
    if (scheme == "http" and explicit_port == 80) or (scheme == "https" and explicit_port == 443):
        effective_port = None

    reconstructed_netloc = hostname
    if effective_port is not None:
        reconstructed_netloc = f"{hostname}:{effective_port}"
    if has_userinfo:
        userinfo = netloc.split("@")[0]
        reconstructed_netloc = f"{userinfo}@{reconstructed_netloc}"

    # 2. Strip single trailing slash ONLY on bare root paths
    path = parts.path
    if path == "/" and not parts.query and not parts.fragment:
        path = ""

    normalized_url = f"{scheme}://{reconstructed_netloc}{path}"
    if parts.query:
        normalized_url += f"?{parts.query}"
    if parts.fragment:
        normalized_url += f"#{parts.fragment}"

    # Offline PSL decomposition
    subdomain = ""
    domain_label = ""
    suffix = ""
    registered_domain = ""

    if not is_ip:
        ext = _extractor(hostname)
        subdomain = ext.subdomain.lower()
        domain_label = ext.domain.lower()
        suffix = ext.suffix.lower()
        if domain_label and suffix:
            registered_domain = f"{domain_label}.{suffix}"
        elif domain_label:
            registered_domain = domain_label

    components = ParsedURLComponents(
        raw_url=url,
        normalized_url=normalized_url,
        scheme=scheme,
        netloc=reconstructed_netloc,
        hostname=hostname,
        port=explicit_port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        subdomain=subdomain,
        registered_domain=registered_domain,
        domain_label=domain_label,
        suffix=suffix,
        is_ip=is_ip,
        is_global_ip=is_global_ip,
        has_userinfo=has_userinfo,
    )
    return components, False


def extract_urls(
    body: Optional[str],
    additional_urls: Optional[List[str]] = None,
) -> Tuple[List[ParsedURLComponents], List[Finding]]:
    """Extracts, validates, deduplicates, and caps HTTP/HTTPS URLs from email body and additional_urls."""
    raw_candidates: List[str] = []
    limit_findings: List[Finding] = []

    # 1. Explicit additional URLs
    if additional_urls:
        for u in additional_urls:
            if isinstance(u, str) and u.strip().lower().startswith(("http://", "https://")):
                raw_candidates.append(u.strip())

    if body:
        # 2. HTML anchor extraction (Pass A: HTMLParser)
        parser = SafeHTMLAnchorExtractor()
        try:
            parser.feed(body)
            parser.close()
            raw_candidates.extend(parser.urls)
        except Exception:
            pass

        # 3. Tag-level regex extraction (Pass B: guarantees recovery of valid anchors around malformed tags)
        for match in _ANCHOR_HREF_RE.finditer(body):
            raw_candidates.append(html.unescape(match.group(2).strip()))

        # 4. Plain-text regex extraction (Pass C: plain-text URLs in body)
        for match in _PLAIN_TEXT_URL_RE.finditer(body):
            raw_url = match.group(0).rstrip(_TRAILING_PUNCTUATION)
            raw_candidates.append(html.unescape(raw_url))

    # Deduplicate raw candidates preserving discovery order
    seen_raw: Set[str] = set()
    unique_candidates: List[str] = []
    for candidate in raw_candidates:
        if candidate not in seen_raw:
            seen_raw.add(candidate)
            unique_candidates.append(candidate)

    # Validate, normalize, and enforce length boundaries
    parsed_urls: List[ParsedURLComponents] = []
    seen_normalized: Set[str] = set()
    has_malformed = False
    has_excessive_length = False

    for candidate in unique_candidates:
        if len(candidate) > settings.url.MAX_URL_LENGTH:
            has_excessive_length = True
            continue

        components, is_malformed = validate_and_normalize_url(candidate)
        if is_malformed:
            has_malformed = True
            continue

        if components and components.normalized_url not in seen_normalized:
            seen_normalized.add(components.normalized_url)
            parsed_urls.append(components)

    if has_malformed:
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_SYNTAX_MALFORMED",
                description="One or more URLs in the message contained malformed authorities, unclosed brackets, or invalid ports.",
                severity=FindingSeverity.INFO,
            )
        )

    if has_excessive_length:
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_EXCESSIVE_LENGTH",
                description=f"One or more URLs exceeded the maximum length bound ({settings.url.MAX_URL_LENGTH} characters) and were omitted.",
                severity=FindingSeverity.LOW,
            )
        )

    # Enforce global evaluation cap
    if len(parsed_urls) > settings.url.MAX_URLS_TO_ANALYZE:
        parsed_urls = parsed_urls[: settings.url.MAX_URLS_TO_ANALYZE]
        limit_findings.append(
            Finding(
                analyzer="url",
                indicator="URL_EVALUATION_CAP_EXCEEDED",
                description=f"Total extracted URLs exceeded the evaluation cap. Analysis was bounded to the first {settings.url.MAX_URLS_TO_ANALYZE} unique URLs.",
                severity=FindingSeverity.INFO,
            )
        )

    return parsed_urls, limit_findings