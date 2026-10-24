from typing import List, Optional, Set
from app.core.config import settings
from app.detectors.content.text_utils import NormalizedText, normalize_content_text
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity


class ContentAnalyzer:
    """Evaluates email subject and body content using explainable heuristics."""

    def __init__(self, config=settings):
        self.config = config.content

    def analyze(self, request: AnalysisRequest) -> List[Finding]:
        findings: List[Finding] = []

        norm_subject = normalize_content_text(request.subject)
        norm_body = normalize_content_text(request.body)

        # 1. Pre-normalization obfuscation check
        self._check_obfuscation(norm_subject, norm_body, findings)

        # 2. Heuristic pattern checks
        self._check_urgency(norm_subject, norm_body, findings)
        self._check_credentials(norm_subject, norm_body, findings)
        self._check_financial_lures(norm_subject, norm_body, findings)
        self._check_authority_impersonation(norm_subject, norm_body, findings)
        self._check_generic_salutation(norm_body, findings)

        return findings

    def _determine_location(self, in_subject: bool, in_body: bool) -> str:
        if in_subject and in_body:
            return "Detected in both subject line and email body"
        if in_subject:
            return "Subject line"
        return "Email body"

    def _check_obfuscation(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = subject.has_zero_width_obfuscation
        in_body = body.has_zero_width_obfuscation

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            total_count = subject.zero_width_count + body.zero_width_count
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_SUSPICIOUS_OBFUSCATION",
                    description=(
                        f"{location}: Contains hidden zero-width or formatting characters "
                        f"({total_count} detected) commonly used to evade text security filters."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_urgency(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.URGENCY_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.URGENCY_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_URGENCY_PRESSURE",
                    description=(
                        f"{location}: Language exerts psychological time pressure or threatens account suspension "
                        "to compel immediate recipient action."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_credentials(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.CREDENTIAL_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.CREDENTIAL_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_CREDENTIAL_SOLICITATION",
                    description=(
                        f"{location}: Contains an actionable request soliciting passwords, PINs, or "
                        "account authentication credentials."
                    ),
                    severity=FindingSeverity.HIGH,
                )
            )

    def _check_financial_lures(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.FINANCIAL_LURE_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.FINANCIAL_LURE_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_FINANCIAL_LURE",
                    description=(
                        f"{location}: Contains lures regarding unexpected financial windfalls, unclaimed prizes, "
                        "or pending refunds."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_authority_impersonation(
        self,
        subject: NormalizedText,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        in_subj = bool(self.config.AUTHORITY_PATTERN.search(subject.cleaned_text))
        in_body = bool(self.config.AUTHORITY_PATTERN.search(body.cleaned_text))

        if in_subj or in_body:
            location = self._determine_location(in_subj, in_body)
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_AUTHORITY_IMPERSONATION",
                    description=(
                        f"{location}: Employs formal corporate IT support, investigation units, or compliance "
                        "department titles to establish false authority."
                    ),
                    severity=FindingSeverity.MEDIUM,
                )
            )

    def _check_generic_salutation(
        self,
        body: NormalizedText,
        findings: List[Finding],
    ) -> None:
        if not body.cleaned_text:
            return

        # Restrict check to introductory offset window
        intro_sample = body.cleaned_text[: self.config.SALUTATION_MAX_OFFSET]
        if self.config.SALUTATION_PATTERN.search(intro_sample):
            findings.append(
                Finding(
                    analyzer="content",
                    indicator="CONTENT_GENERIC_SALUTATION",
                    description=(
                        "Email body: Uses an impersonal salutation (e.g., 'Dear Customer') rather than addressing "
                        "the recipient by name, typical of mass automated phishing campaigns."
                    ),
                    severity=FindingSeverity.LOW,
                )
            )


content_analyzer = ContentAnalyzer()