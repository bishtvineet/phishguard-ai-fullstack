import re
from typing import List, Set

from app.core.config import settings
from app.detectors.sender.domain_utils import is_lookalike_of_trusted_domain
from app.detectors.url.url_utils import ParsedURLComponents, extract_urls
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity

_DOUBLE_ENCODING_RE = re.compile(r"%25[0-9a-fA-F]{2}")


class URLAnalyzer:
    """Evaluates URLs extracted from email bodies and additional parameters using deterministic heuristics."""

    def __init__(self, config=settings):
        self.config = config.url
        self.trusted_domains = config.TRUSTED_DOMAINS
        # Extract brand names from trusted domains (e.g., 'paypal' from 'paypal.com')
        self.trusted_brands = {d.split(".")[0].lower() for d in self.trusted_domains}

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        parsed_urls, limit_findings = extract_urls(request.body, request.additional_urls)
        return self.analyze_parsed(parsed_urls, limit_findings)

    def analyze_parsed(
        self, parsed_urls: List[ParsedURLComponents], limit_findings: List[Finding]
    ) -> List[Finding]:
        findings: List[Finding] = list(limit_findings)

        # Track (indicator, target_key) to deduplicate findings across multiple URLs
        seen_indicator_targets: Set[tuple] = set()

        for u in parsed_urls:
            # 1. Userinfo / embedded credentials
            if u.has_userinfo:
                key = ("URL_USERINFO_CREDENTIAL_EMBEDDED", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_USERINFO_CREDENTIAL_EMBEDDED",
                            description=f"URL '{u.raw_url}' embeds authentication credentials or userinfo syntax ('@') before the hostname to obscure the destination.",
                            severity=FindingSeverity.HIGH,
                        )
                    )

            # 2. IP literal hostnames
            if u.is_ip:
                if u.is_global_ip:
                    key = ("URL_IP_LITERAL_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_IP_LITERAL_HOST",
                                description=f"URL uses a raw public IP literal host '{u.hostname}' rather than a registered domain name.",
                                severity=FindingSeverity.MEDIUM,
                            )
                        )
                else:
                    key = ("URL_NON_GLOBAL_IP_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_NON_GLOBAL_IP_HOST",
                                description=f"URL points to a non-global, private, or documentation IP address '{u.hostname}'.",
                                severity=FindingSeverity.INFO,
                            )
                        )

            # Domain-based checks (only if not an IP address)
            if not u.is_ip and u.registered_domain:
                is_legit_brand_domain = u.registered_domain in self.trusted_domains

                # 3. Lookalike domain check (skip if it is an exact legitimate trusted domain)
                if not is_legit_brand_domain:
                    is_lookalike = False
                    for trusted_domain in self.trusted_domains:
                        trusted_label = trusted_domain.split(".")[0]
                        if is_lookalike_of_trusted_domain(u.domain_label, trusted_label):
                            is_lookalike = True
                            break

                    if is_lookalike:
                        key = ("URL_LOOKALIKE_DOMAIN", u.registered_domain)
                        if key not in seen_indicator_targets:
                            seen_indicator_targets.add(key)
                            findings.append(
                                Finding(
                                    analyzer="url",
                                    indicator="URL_LOOKALIKE_DOMAIN",
                                    description=f"URL registered domain '{u.registered_domain}' appears to mimic a trusted brand via typosquatting or character substitution.",
                                    severity=FindingSeverity.HIGH,
                                )
                            )

                # 4. Brand name in unrelated subdomain (only if registered domain is NOT legitimate brand property)
                if not is_legit_brand_domain and u.subdomain:
                    # Tokenize subdomain across dots and hyphens
                    sub_tokens = set(re.split(r"[.-]", u.subdomain))
                    matched_brands = sub_tokens.intersection(self.trusted_brands)
                    if matched_brands:
                        key = ("URL_BRAND_NAME_IN_UNRELATED_DOMAIN", u.hostname)
                        if key not in seen_indicator_targets:
                            seen_indicator_targets.add(key)
                            findings.append(
                                Finding(
                                    analyzer="url",
                                    indicator="URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
                                    description=f"URL hostname '{u.hostname}' places trusted brand name(s) {sorted(matched_brands)} into a subdomain of an unrelated domain '{u.registered_domain}'.",
                                    severity=FindingSeverity.HIGH,
                                )
                            )

                # 5. Punycode check
                if "xn--" in u.hostname:
                    key = ("URL_PUNYCODE_HOST", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_PUNYCODE_HOST",
                                description=f"URL hostname '{u.hostname}' uses Punycode encoding (IDN).",
                                severity=FindingSeverity.INFO,
                            )
                        )

                # 6. Suspicious TLD check (weak signal)
                if u.suffix in self.config.SUSPICIOUS_TLDS:
                    key = ("URL_SUSPICIOUS_TLD", u.suffix)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_SUSPICIOUS_TLD",
                                description=f"URL uses top-level domain '.{u.suffix}', which has a statistically elevated association with abuse infrastructure.",
                                severity=FindingSeverity.LOW,
                            )
                        )

            # 7. Obfuscation: double-percent encoding
            full_raw_path = f"{u.path}?{u.query}" if u.query else u.path
            if _DOUBLE_ENCODING_RE.search(full_raw_path):
                key = ("URL_SUSPICIOUS_OBFUSCATION", u.normalized_url)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_SUSPICIOUS_OBFUSCATION",
                            description=f"URL '{u.raw_url}' contains double percent-encoding, commonly used to evade pattern security filters.",
                            severity=FindingSeverity.MEDIUM,
                        )
                    )

            # 8. Insecure HTTP on credential-related path
            if u.scheme == "http":
                path_and_query = f"{u.path} {u.query}"
                if self.config.CREDENTIAL_PATH_PATTERN.search(path_and_query):
                    key = ("URL_INSECURE_HTTP_CREDENTIAL_PATH", u.hostname)
                    if key not in seen_indicator_targets:
                        seen_indicator_targets.add(key)
                        findings.append(
                            Finding(
                                analyzer="url",
                                indicator="URL_INSECURE_HTTP_CREDENTIAL_PATH",
                                description=f"URL '{u.raw_url}' requests authentication or sensitive operations over plaintext HTTP.",
                                severity=FindingSeverity.LOW,
                            )
                        )

            # 9. Unusual port check
            if u.port is not None and u.port not in self.config.STANDARD_PORTS:
                key = ("URL_UNUSUAL_PORT", f"{u.hostname}:{u.port}")
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_UNUSUAL_PORT",
                            description=f"URL connects to a non-standard web port '{u.port}'.",
                            severity=FindingSeverity.LOW,
                        )
                    )

            # 10. High path depth (weak signal)
            path_segments = [seg for seg in u.path.split("/") if seg]
            if len(path_segments) >= self.config.MAX_PATH_DEPTH:
                key = ("URL_HIGH_PATH_DEPTH", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_HIGH_PATH_DEPTH",
                            description=f"URL '{u.raw_url}' exhibits excessive path nesting ({len(path_segments)} levels).",
                            severity=FindingSeverity.LOW,
                        )
                    )

            # 11. Embedded redirect parameter check
            if u.query and self.config.REDIRECT_PARAM_PATTERN.search(f"?{u.query}"):
                key = ("URL_REDIRECT_PARAMETER_PRESENT", u.hostname)
                if key not in seen_indicator_targets:
                    seen_indicator_targets.add(key)
                    findings.append(
                        Finding(
                            analyzer="url",
                            indicator="URL_REDIRECT_PARAMETER_PRESENT",
                            description=f"URL '{u.raw_url}' contains an embedded target URL parameter commonly utilized in open redirection chains.",
                            severity=FindingSeverity.INFO,
                        )
                    )

        return findings


url_analyzer = URLAnalyzer()