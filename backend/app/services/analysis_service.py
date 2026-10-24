from app.detectors.content.analyzer import content_analyzer
from app.detectors.ml.analyzer import ml_url_analyzer
from app.detectors.sender.analyzer import sender_analyzer
from app.detectors.url.analyzer import url_analyzer
from app.detectors.url.url_utils import extract_urls
from app.schemas.analysis import AnalysisRequest, AnalysisResponse
from app.services.risk_assessor import risk_assessor


class AnalysisService:
    """Orchestrates email analysis components and coordinates centralized risk evaluation."""

    def __init__(
        self,
        sender_engine=sender_analyzer,
        content_engine=content_analyzer,
        url_engine=url_analyzer,
        ml_url_engine=ml_url_analyzer,
        assessor=risk_assessor,
    ):
        self.sender_engine = sender_engine
        self.content_engine = content_engine
        self.url_engine = url_engine
        self.ml_url_engine = ml_url_engine
        self.assessor = assessor

    def analyze_email(self, request: AnalysisRequest) -> AnalysisResponse:
        """Evaluates submitted email data across Sender, Content, URL, and ML modules and scores risk."""
        # 1. Execute sender and content analyzers
        sender_findings = self.sender_engine.analyze(request)
        content_findings = self.content_engine.analyze(request)

        # 2. Shared single-pass URL extraction
        parsed_urls, limit_findings = extract_urls(request.body, request.additional_urls)

        # 3. Deterministic URL heuristic analysis
        url_findings = self.url_engine.analyze_parsed(parsed_urls, limit_findings)

        # 4. Machine learning URL inference (safe fallback if inactive)
        ml_url_findings = self.ml_url_engine.analyze_urls(parsed_urls)

        all_findings = sender_findings + content_findings + url_findings + ml_url_findings

        # 5. Synthesize risk score, category, and narrative
        risk_score, risk_category, summary = self.assessor.evaluate(request, all_findings)

        # 6. Assemble actionable security recommendations
        recommendations = [
            "Verify suspicious emails through known, out-of-band communication channels.",
            "Do not click unverified links or supply credentials on unknown websites.",
        ]

        if any(f.indicator in ("LOOKALIKE_TRUSTED_DOMAIN", "BRAND_NAME_IN_UNRELATED_DOMAIN") for f in sender_findings):
            recommendations.append(
                "Sender domain appears deceptive or mimics a well-known brand. Check the domain spelling carefully."
            )

        if any(f.indicator == "DMARC_POLICY_FAILED" for f in sender_findings):
            recommendations.append(
                "Message failed domain alignment (DMARC). The email may be forged or sent by an unauthorized mail relay."
            )

        if any(f.indicator == "CONTENT_CREDENTIAL_SOLICITATION" for f in content_findings):
            recommendations.append(
                "Never enter passwords, PINs, or security credentials via links received in unverified emails."
            )

        if any(f.indicator == "CONTENT_URGENCY_PRESSURE" for f in content_findings):
            recommendations.append(
                "Be cautious of artificial deadlines or threats of account suspension; independently confirm account status."
            )

        if any(f.indicator == "CONTENT_FINANCIAL_LURE" for f in content_findings):
            recommendations.append(
                "Do not respond to unexpected financial claims, prizes, wire distributions, or refund notifications."
            )

        if any(f.indicator in ("URL_USERINFO_CREDENTIAL_EMBEDDED", "URL_IP_LITERAL_HOST") for f in url_findings):
            recommendations.append(
                "The email contains links directing to raw IP addresses or obscured hostnames. Avoid opening these links."
            )

        if any(f.indicator in ("URL_BRAND_NAME_IN_UNRELATED_DOMAIN", "URL_LOOKALIKE_DOMAIN") for f in url_findings):
            recommendations.append(
                "Links in this message appear to imitate legitimate services using deceptive domain names. Check destination URLs carefully before interacting."
            )

        if any(f.indicator == "URL_INSECURE_HTTP_CREDENTIAL_PATH" for f in url_findings):
            recommendations.append(
                "Links requesting authentication or account access use unencrypted connections (HTTP). Never enter credentials over unencrypted connections."
            )

        if any(f.indicator == "ML_URL_SUSPICIOUS_LEXICAL_ANOMALY" for f in ml_url_findings):
            recommendations.append(
                "One or more links show statistical anomalies common to phishing attacks. Exercise extreme caution."
            )

        return AnalysisResponse(
            risk_score=risk_score,
            risk_category=risk_category,
            summary=summary,
            findings=all_findings,
            recommendations=recommendations,
        )


analysis_service = AnalysisService()