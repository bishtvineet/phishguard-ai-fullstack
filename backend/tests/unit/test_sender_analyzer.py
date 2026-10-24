from app.detectors.sender.analyzer import sender_analyzer
from app.schemas.analysis import AnalysisRequest, AuthStatus, EmailAuthenticationInput, FindingSeverity


def test_clean_trusted_domain_emits_no_findings():
    req = AnalysisRequest(sender_email="security@paypal.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_legitimate_subdomain_of_trusted_domain_emits_no_findings():
    req = AnalysisRequest(sender_email="support@mail.paypal.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_brand_in_subdomain_detected():
    req = AnalysisRequest(sender_email="security@paypal.com.attacker.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "attacker.com" in finding.description


def test_lookalike_trusted_domain_detected():
    req = AnalysisRequest(sender_email="alert@paypa1.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "LOOKALIKE_TRUSTED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "LOOKALIKE_TRUSTED_DOMAIN")
    assert finding.severity == FindingSeverity.HIGH


def test_legitimate_hyphenated_domain_false_positive_safeguard():
    req = AnalysisRequest(sender_email="contact@e-commerce-shop.com")
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_legitimate_bulk_provider_reply_to():
    req = AnalysisRequest(
        sender_email="billing@acme-corp.com",
        reply_to="support@zendesk.com",
    )
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "REPLY_TO_BULK_PROVIDER" in indicators
    assert "REPLY_TO_DOMAIN_MISMATCH" not in indicators
    finding = next(f for f in findings if f.indicator == "REPLY_TO_BULK_PROVIDER")
    assert finding.severity == FindingSeverity.INFO


def test_unrelated_reply_to_mismatch():
    req = AnalysisRequest(
        sender_email="security@mybank.com",
        reply_to="attacker@random-inbox.com",
    )
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "REPLY_TO_DOMAIN_MISMATCH" in indicators
    finding = next(f for f in findings if f.indicator == "REPLY_TO_DOMAIN_MISMATCH")
    assert finding.severity == FindingSeverity.MEDIUM


def test_missing_or_unknown_authentication_produces_no_penalty():
    req = AnalysisRequest(
        sender_email="service@acme-corp.com",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.UNKNOWN,
            dkim=AuthStatus.UNKNOWN,
            dmarc=AuthStatus.UNKNOWN,
        ),
    )
    findings = sender_analyzer.analyze(req)
    assert len(findings) == 0


def test_correlated_authentication_failure_avoids_triple_counting():
    req = AnalysisRequest(
        sender_email="spoofed@victim-domain.com",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.FAIL,
            dmarc=AuthStatus.FAIL,
        ),
    )
    findings = sender_analyzer.analyze(req)
    indicators = {f.indicator: f for f in findings}

    assert "DMARC_POLICY_FAILED" in indicators
    assert indicators["DMARC_POLICY_FAILED"].severity == FindingSeverity.HIGH

    # Correlated SPF and DKIM failures should be downgraded to INFO
    assert "SPF_AUTHENTICATION_FAILED" in indicators
    assert indicators["SPF_AUTHENTICATION_FAILED"].severity == FindingSeverity.INFO
    assert "DKIM_AUTHENTICATION_FAILED" in indicators
    assert indicators["DKIM_AUTHENTICATION_FAILED"].severity == FindingSeverity.INFO


def test_punycode_domain_detected():
    req = AnalysisRequest(sender_email="info@xn--pple-43d.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "PUNYCODE_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "PUNYCODE_DOMAIN")
    assert finding.severity == FindingSeverity.INFO


def test_ip_literal_sender_detected():
    req = AnalysisRequest(sender_email="admin@[192.0.2.1]")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "IP_LITERAL_SENDER_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "IP_LITERAL_SENDER_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM

def test_brand_in_subdomain_hyphenated_detected():
    # Detects hyphen-bounded brand lures in unrelated subdomains
    req = AnalysisRequest(sender_email="alert@login-paypal-verification.attacker.com")
    findings = sender_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    finding = next(f for f in findings if f.indicator == "BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert finding.severity == FindingSeverity.MEDIUM
    assert "paypal" in finding.description
    assert "attacker.com" in finding.description


def test_brand_in_subdomain_false_positive_safeguards():
    # Ensures words embedding a brand name as a substring (e.g. 'snapple', 'pineapples') do not trigger
    req_snapple = AnalysisRequest(sender_email="promotions@snapple-beverages.attacker.com")
    findings_snapple = sender_analyzer.analyze(req_snapple)
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" not in [f.indicator for f in findings_snapple]

    req_pineapples = AnalysisRequest(sender_email="orders@pineapples.organic-store.com")
    findings_pineapples = sender_analyzer.analyze(req_pineapples)
    assert "BRAND_NAME_IN_UNRELATED_DOMAIN" not in [f.indicator for f in findings_pineapples]