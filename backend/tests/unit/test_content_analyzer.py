from app.detectors.content.analyzer import content_analyzer
from app.schemas.analysis import AnalysisRequest, FindingSeverity


def test_clean_corporate_email_emits_no_findings():
    req = AnalysisRequest(
        sender_email="colleague@company.com",
        subject="Project Standup Notes",
        body="Hi Team, please find attached the meeting notes from today's discussion. See you tomorrow at 10 AM.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_urgency_pressure_detected():
    req = AnalysisRequest(
        sender_email="notice@alerts-domain.com",
        subject="Urgent Action Required",
        body="Your account will be suspended within 24 hours if action is not taken.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_URGENCY_PRESSURE" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_URGENCY_PRESSURE")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "Email body" in finding.description


def test_credential_solicitation_detected():
    req = AnalysisRequest(
        sender_email="security@portal-auth.com",
        subject="Security Notification",
        body="Please confirm your password to restore immediate access.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_CREDENTIAL_SOLICITATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_CREDENTIAL_SOLICITATION")
    assert finding.severity == FindingSeverity.HIGH


def test_financial_lures_tax_refund_pending_and_pending_tax_refund():
    # Case A: 'tax refund pending'
    req_a = AnalysisRequest(
        sender_email="irs-notice@irs-rebate.com",
        subject="Tax notification",
        body="You have a tax refund pending from your previous filing.",
    )
    findings_a = content_analyzer.analyze(req_a)
    assert "CONTENT_FINANCIAL_LURE" in [f.indicator for f in findings_a]

    # Case B: 'pending tax refund'
    req_b = AnalysisRequest(
        sender_email="irs-notice@irs-rebate.com",
        subject="Tax notification",
        body="You have a pending tax refund waiting for wire disbursement.",
    )
    findings_b = content_analyzer.analyze(req_b)
    assert "CONTENT_FINANCIAL_LURE" in [f.indicator for f in findings_b]


def test_authority_impersonation_detected():
    req = AnalysisRequest(
        sender_email="dispatch@internal-desk.com",
        subject="Ticket Update",
        body="This is an urgent ticket escalation from the IT Support Desk.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_AUTHORITY_IMPERSONATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_AUTHORITY_IMPERSONATION")
    assert finding.severity == FindingSeverity.MEDIUM


def test_generic_salutation_detected():
    req = AnalysisRequest(
        sender_email="newsletter@generic-promo.com",
        subject="Important Service Notice",
        body="Dear Customer, we are making routine modifications to our terms.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_GENERIC_SALUTATION" in indicators
    finding = next(f for f in findings if f.indicator == "CONTENT_GENERIC_SALUTATION")
    assert finding.severity == FindingSeverity.LOW


def test_suspicious_obfuscation_detected():
    req = AnalysisRequest(
        sender_email="alert@deceptive-inbox.com",
        subject="Account notice",
        body="Please r\u200bes\u200bet your password immediately.",
    )
    findings = content_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "CONTENT_SUSPICIOUS_OBFUSCATION" in indicators
    assert "CONTENT_CREDENTIAL_SOLICITATION" in indicators


def test_location_attribution_both_subject_and_body():
    req = AnalysisRequest(
        sender_email="service@warning.com",
        subject="Final notice: immediate action",
        body="Your account will be suspended within 24 hours.",
    )
    findings = content_analyzer.analyze(req)
    finding = next(f for f in findings if f.indicator == "CONTENT_URGENCY_PRESSURE")
    assert "Detected in both subject line and email body" in finding.description


def test_false_positive_safeguards_pin_shipping_shopping():
    req = AnalysisRequest(
        sender_email="orders@ecommerce-hub.com",
        subject="Order Confirmation",
        body="Your tracking PIN is 1234. Your shopping cart has shipped via ground shipping.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_false_positive_safeguards_pinpoint():
    req = AnalysisRequest(
        sender_email="lead@devteam.com",
        subject="Post-Mortem Review",
        body="Let's pinpoint the exact root cause in tomorrow's standup meeting.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0


def test_false_positive_safeguards_legitimate_billing_invoice():
    req = AnalysisRequest(
        sender_email="billing@cloudprovider.com",
        subject="Monthly Cloud Billing Statement",
        body="Please find attached the monthly invoice for your standard cloud usage.",
    )
    findings = content_analyzer.analyze(req)
    assert len(findings) == 0