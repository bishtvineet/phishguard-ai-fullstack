import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from app.core.config import settings
from app.schemas.analysis import AnalysisRequest, Finding, FindingSeverity, RiskCategory

_QUOTED_RE = re.compile(r"'([^']+)'")
_PAREN_RE = re.compile(r"\(([^)]+)\)")
_IDENTITY_INDICATORS = {
    "LOOKALIKE_TRUSTED_DOMAIN",
    "BRAND_NAME_IN_UNRELATED_DOMAIN",
    "URL_LOOKALIKE_DOMAIN",
    "URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
}


def extract_normalized_target(finding: Finding) -> str:
    """Deterministically extracts the target entity from a finding description or structured target field."""
    if finding.target:
        return finding.target.strip().lower()

    desc = finding.description

    if finding.analyzer == "sender":
        # Prioritize explicit registered domain label if stated
        m_reg = re.search(r"registered domain is '([^']+)'", desc)
        if m_reg:
            return m_reg.group(1).strip().lower()

        # Otherwise take the last quoted token (representing domain/infrastructure rather than brand)
        all_quotes = _QUOTED_RE.findall(desc)
        if all_quotes:
            return all_quotes[-1].strip().lower()

        # Check for parenthesized target (e.g., IP literal: (192.168.1.1))
        all_parens = _PAREN_RE.findall(desc)
        if all_parens:
            return all_parens[-1].strip().lower()

        return "global_fallback"

    elif finding.analyzer == "url":
        all_quotes = _QUOTED_RE.findall(desc)
        if all_quotes:
            first_quote = all_quotes[0].strip().lower()
            if first_quote.startswith(("http://", "https://")):
                try:
                    parts = urlsplit(first_quote)
                    return parts.netloc.lower() or first_quote
                except Exception:
                    return first_quote
            return first_quote
        return "global_fallback"

    elif finding.analyzer == "content":
        if desc.startswith("Subject line:"):
            return "subject"
        elif desc.startswith("Email body:"):
            return "body"
        elif desc.startswith("Detected in both"):
            return "both"
        return "global_fallback"

    return "global_fallback"


class RiskAssessor:
    """Evaluates findings across all detection engines to compute deterministic risk scores."""

    def __init__(self, config=settings.scoring):
        self.config = config

    def evaluate(
        self, request: AnalysisRequest, findings: List[Finding]
    ) -> Tuple[Optional[int], RiskCategory, str]:
        # 1. Check Inconclusive Gate
        if self._is_inconclusive(request, findings):
            summary = (
                "Insufficient content and telemetry provided to perform a conclusive assessment. "
                "The email body and subject lacked analyzable data."
            )
            return None, RiskCategory.INCONCLUSIVE, summary

        # 2. Exact Deduplication
        deduped_findings: List[Finding] = []
        seen_exact: Set[Tuple[str, str, str]] = set()

        for f in findings:
            target = extract_normalized_target(f)
            exact_key = (f.analyzer, f.indicator, target)
            if exact_key not in seen_exact:
                seen_exact.add(exact_key)
                deduped_findings.append(f)

        if not deduped_findings:
            summary = (
                "Analysis completed with 0 weighted risk indicators detected. "
                "Note: A score of 0 indicates that no known heuristic anomalies were observed, "
                "but it does not prove an email is completely safe. Always verify unexpected communications independently."
            )
            return 0, RiskCategory.LOW_RISK, summary

        # 3. Indicator Grouping & Scoring
        indicator_groups: Dict[str, Dict] = {}
        severity_rank = {
            FindingSeverity.INFO: 0,
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
        }
        severity_weights = {
            FindingSeverity.INFO: self.config.WEIGHT_INFO,
            FindingSeverity.LOW: self.config.WEIGHT_LOW,
            FindingSeverity.MEDIUM: self.config.WEIGHT_MEDIUM,
            FindingSeverity.HIGH: self.config.WEIGHT_HIGH,
        }

        for f in deduped_findings:
            ind = f.indicator
            target = extract_normalized_target(f)

            if ind not in indicator_groups:
                indicator_groups[ind] = {
                    "max_severity": f.severity,
                    "targets": {target},
                }
            else:
                curr_max = indicator_groups[ind]["max_severity"]
                if severity_rank[f.severity] > severity_rank[curr_max]:
                    indicator_groups[ind]["max_severity"] = f.severity
                indicator_groups[ind]["targets"].add(target)

        raw_score = 0
        for ind, data in indicator_groups.items():
            base_wt = severity_weights[data["max_severity"]]
            distinct_count = len(data["targets"])
            repeat_count = max(0, distinct_count - 1)
            repeat_bonus = min(self.config.MAX_REPEAT_BONUS, repeat_count * self.config.REPEAT_STEP)
            raw_score += (base_wt + repeat_bonus)

        # 4. Single-Fire Synergies
        present_indicators = set(indicator_groups.keys())
        fired_synergies: List[str] = []

        # Synergy 1: Identity Spoofing + Credential Solicitation
        if bool(present_indicators.intersection(_IDENTITY_INDICATORS)) and (
            "CONTENT_CREDENTIAL_SOLICITATION" in present_indicators
        ):
            raw_score += self.config.SYNERGY_IDENTITY_CREDENTIAL
            fired_synergies.append("Identity Mimicry & Credential Solicitation")

        # Synergy 2: Urgency Pressure + Financial Lure
        if (
            "CONTENT_URGENCY_PRESSURE" in present_indicators
            and "CONTENT_FINANCIAL_LURE" in present_indicators
        ):
            raw_score += self.config.SYNERGY_URGENCY_FINANCIAL
            fired_synergies.append("Urgency Pressure & Financial Lure")

        # Synergy 3: Insecure Credential Path + Credential Solicitation
        if (
            "URL_INSECURE_HTTP_CREDENTIAL_PATH" in present_indicators
            and "CONTENT_CREDENTIAL_SOLICITATION" in present_indicators
        ):
            raw_score += self.config.SYNERGY_INSECURE_CREDENTIAL
            fired_synergies.append("Unencrypted Insecure Credential Collection")

        # 5. Clamping [0, 100]
        final_score = max(0, min(100, raw_score))

        # 6. Threshold Mapping
        if final_score >= self.config.THRESHOLD_HIGH_RISK:
            category = RiskCategory.HIGH_RISK
        elif final_score >= self.config.THRESHOLD_SUSPICIOUS:
            category = RiskCategory.SUSPICIOUS
        else:
            category = RiskCategory.LOW_RISK

        # 7. Summary Narrative
        if final_score == 0:
            summary = (
                f"Analysis completed with {len(deduped_findings)} informational finding(s) and 0 weighted risk score. "
                "Note: A score of 0 indicates that no known heuristic anomalies were observed, "
                "but it does not prove an email is completely safe. Always verify unexpected communications independently."
            )
        else:
            synergy_text = f" Compound risk modifiers applied: {', '.join(fired_synergies)}." if fired_synergies else ""
            summary = (
                f"Analysis completed with {len(deduped_findings)} indicator(s) resulting in a risk score of {final_score}/100 ({category.value})."
                f"{synergy_text}"
            )

        return final_score, category, summary

    def _is_inconclusive(self, request: AnalysisRequest, findings: List[Finding]) -> bool:
        """Determines if the payload lacks sufficient substance across all analyzers."""
        if len(findings) > 0:
            return False

        has_no_subject = not request.subject or request.subject.strip() == ""
        has_minimal_body = not request.body or len(request.body.strip()) < 10
        has_no_urls = not request.additional_urls or len(request.additional_urls) == 0

        return has_no_subject and has_minimal_body and has_no_urls


risk_assessor = RiskAssessor()