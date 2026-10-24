from typing import List, Optional
from app.core.config import settings
from app.detectors.sender.domain_utils import (
    ParsedDomain,
    parse_and_normalize_email_domain,
    is_lookalike_of_trusted_domain,
)
from app.schemas.analysis import AnalysisRequest, AuthStatus, Finding, FindingSeverity


class SenderAnalyzer:
    """Evaluates sender identity, domain structures, and authentication records."""

    def __init__(self, config=settings):
        self.config = config

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []

        sender_parsed = parse_and_normalize_email_domain(request.sender_email)
        if not sender_parsed:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SENDER_SYNTAX_MALFORMED",
                    description="Sender email address could not be safely parsed into a valid domain.",
                    severity=FindingSeverity.HIGH,
                )
            )
            return findings

        # 1. Structural domain rules
        self._check_ip_literal(sender_parsed, findings)
        self._check_punycode(sender_parsed, findings)
        self._check_brand_in_subdomain(sender_parsed, findings)
        self._check_lookalike_domains(sender_parsed, findings)
        self._check_suspicious_labels(sender_parsed, findings)
        self._check_subdomain_depth(sender_parsed, findings)

        # 2. Reply-To relationship
        if request.reply_to:
            self._check_reply_to_mismatch(sender_parsed, request.reply_to, findings)

        # 3. Authentication evaluation (SPF, DKIM, DMARC) with correlation safeguards
        self._evaluate_authentication(request, findings)

        return findings

    def _check_ip_literal(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="IP_LITERAL_SENDER_DOMAIN",
                    description=f"Sender domain is a raw IP literal ({parsed.registered_domain}) rather than a named host.",
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_punycode(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.has_punycode:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="PUNYCODE_DOMAIN",
                    description=(
                        f"Sender domain uses internationalized (Punycode) encoding ({parsed.normalized_ascii}). "
                        "While standard for non-Latin scripts, it can be abused for visual spoofing."
                    ),
                    severity=FindingSeverity.INFO,
                )
            )

    def _check_brand_in_subdomain(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal or not parsed.subdomain:
            return

        # Tokenize subdomain labels across both dot and hyphen delimiters
        # to detect hyphen-delimited brand lures without naive substring collisions (e.g., 'snapple')
        subdomain_tokens = set()
        for label in parsed.subdomain.lower().split("."):
            subdomain_tokens.update(label.split("-"))

        for trusted in self.config.TRUSTED_DOMAINS:
            brand_label = trusted.split(".")[0]
            if parsed.registered_domain == trusted:
                continue

            if brand_label in subdomain_tokens or trusted in parsed.subdomain.lower():
                findings.append(
                    Finding(
                        analyzer="sender",
                        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
                        description=(
                            f"Trusted brand name '{brand_label}' appears in a subdomain label, "
                            f"but the registered domain is '{parsed.registered_domain}'."
                        ),
                        severity=FindingSeverity.MEDIUM,
                    )
                )
                break

    def _check_lookalike_domains(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            return

        candidate_label = parsed.domain.lower()

        for trusted in self.config.TRUSTED_DOMAINS:
            trusted_label = trusted.split(".")[0]
            # Skip if exact brand domain or valid subdomain of it
            if parsed.registered_domain == trusted:
                return

            if is_lookalike_of_trusted_domain(candidate_label, trusted_label):
                findings.append(
                    Finding(
                        analyzer="sender",
                        indicator="LOOKALIKE_TRUSTED_DOMAIN",
                        description=(
                            f"Sender domain label '{parsed.domain}' closely resembles trusted brand '{trusted}' "
                            "via character substitution or edit distance."
                        ),
                        severity=FindingSeverity.HIGH,
                    )
                )
                return

    def _check_suspicious_labels(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.is_ip_literal:
            return

        domain_lower = parsed.domain.lower()
        matched_keywords = [
            kw for kw in self.config.SUSPICIOUS_DOMAIN_KEYWORDS if kw in domain_lower and kw != domain_lower
        ]

        if matched_keywords and "-" in domain_lower:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SUSPICIOUS_DOMAIN_LABEL",
                    description=(
                        f"Sender domain label '{parsed.domain}' contains sensitive action keywords "
                        f"({', '.join(matched_keywords)}) in a hyphenated pattern."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )

    def _check_subdomain_depth(self, parsed: ParsedDomain, findings: List[Finding]) -> None:
        if parsed.subdomain_depth >= self.config.MAX_UNSUSPICIOUS_SUBDOMAIN_DEPTH:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SUSPICIOUS_SUBDOMAIN_DEPTH",
                    description=(
                        f"Sender domain has an unusually deep subdomain structure ({parsed.subdomain_depth} levels). "
                        "Deep nesting can obscure the actual registered domain."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )

    def _check_reply_to_mismatch(
        self, sender_parsed: ParsedDomain, reply_to_str: str, findings: List[Finding]
    ) -> None:
        reply_parsed = parse_and_normalize_email_domain(reply_to_str)
        if not reply_parsed:
            return

        # Same registered domain (e.g., mail.paypal.com and paypal.com)
        if sender_parsed.registered_domain == reply_parsed.registered_domain:
            return

        # Reply-To belongs to an authorized bulk mailing or CRM service
        if reply_parsed.registered_domain in self.config.WELL_KNOWN_BULK_SENDERS:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="REPLY_TO_BULK_PROVIDER",
                    description=(
                        f"Reply-To domain '{reply_parsed.registered_domain}' differs from sender, "
                        "but matches a recognized bulk mailing or support service provider."
                    ),
                    severity=FindingSeverity.INFO,
                )
            )
            return

        # Unrelated domains
        findings.append(
            Finding(
                analyzer="sender",
                indicator="REPLY_TO_DOMAIN_MISMATCH",
                description=(
                    f"Reply-To address points to an unrelated domain ('{reply_parsed.registered_domain}') "
                    f"instead of the sender domain ('{sender_parsed.registered_domain}')."
                ),
                severity=FindingSeverity.MEDIUM,
            )
        )

    def _evaluate_authentication(self, request: AnalysisRequest, findings: List[Finding]) -> None:
        auth = request.authentication
        dmarc_failed = auth.dmarc == AuthStatus.FAIL

        # DMARC Evaluation
        if dmarc_failed:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="DMARC_POLICY_FAILED",
                    description=(
                        "Email explicitly failed reported DMARC policy validation, indicating failure "
                        "of domain alignment across SPF or DKIM mechanisms."
                    ),
                    severity=FindingSeverity.HIGH,
                )
            )

        # SPF Evaluation
        if auth.spf == AuthStatus.FAIL:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="SPF_AUTHENTICATION_FAILED",
                    description="Sending server is not authorized under the domain's published SPF policy.",
                    severity=FindingSeverity.INFO if dmarc_failed else FindingSeverity.MEDIUM,
                )
            )

        # DKIM Evaluation
        if auth.dkim == AuthStatus.FAIL:
            findings.append(
                Finding(
                    analyzer="sender",
                    indicator="DKIM_AUTHENTICATION_FAILED",
                    description="Cryptographic DKIM signature failed verification or was absent when required.",
                    severity=FindingSeverity.INFO if dmarc_failed else FindingSeverity.MEDIUM,
                )
            )


sender_analyzer = SenderAnalyzer()