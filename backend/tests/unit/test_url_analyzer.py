from app.detectors.url.analyzer import url_analyzer
from app.schemas.analysis import AnalysisRequest, FindingSeverity


def test_clean_legitimate_brand_urls_produce_no_findings():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Check these docs",
        body="See https://developer.apple.com/documentation and https://aws.amazon.com/console",
    )
    findings = url_analyzer.analyze(req)
    assert len(findings) == 0


def test_brand_in_subdomain_of_unrelated_domain_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Security Notice",
        body="Login at https://paypal.com.attacker-portal.net/login immediately.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_BRAND_NAME_IN_UNRELATED_DOMAIN" in indicators
    f = next(f for f in findings if f.indicator == "URL_BRAND_NAME_IN_UNRELATED_DOMAIN")
    assert f.severity == FindingSeverity.HIGH


def test_brand_in_path_or_query_does_not_trigger_brand_domain_findings():
    # Brand appears in path and query, but host is unrelated news/github site
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="News & Code",
        body="Read https://technews.org/articles/paypal-report and https://github.com/apple/swift",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_BRAND_NAME_IN_UNRELATED_DOMAIN" not in indicators
    assert "URL_LOOKALIKE_DOMAIN" not in indicators


def test_lookalike_typosquatting_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Account Update",
        body="Visit https://paypa1.com/verify to update details.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_LOOKALIKE_DOMAIN" in indicators
    f = next(f for f in findings if f.indicator == "URL_LOOKALIKE_DOMAIN")
    assert f.severity == FindingSeverity.HIGH


def test_userinfo_credential_embedded_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Invoice",
        body="Open http://google.com@attacker-site.com/invoice.pdf",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_USERINFO_CREDENTIAL_EMBEDDED" in indicators
    f = next(f for f in findings if f.indicator == "URL_USERINFO_CREDENTIAL_EMBEDDED")
    assert f.severity == FindingSeverity.HIGH


def test_ip_literal_host_public_vs_non_global():
    # Public IPv4 (93.184.216.34) and public IPv6 ([2606:2800:220:1:248:1893:25c8:1946])
    req_pub = AnalysisRequest(
        sender_email="user@example.com",
        subject="IP Host",
        body="Visit http://93.184.216.34/portal and http://[2606:2800:220:1:248:1893:25c8:1946]/portal",
    )
    findings_pub = url_analyzer.analyze(req_pub)
    pub_indicators = [f.indicator for f in findings_pub]
    assert "URL_IP_LITERAL_HOST" in pub_indicators
    f_pub = next(f for f in findings_pub if f.indicator == "URL_IP_LITERAL_HOST")
    assert f_pub.severity == FindingSeverity.MEDIUM

    # Non-global: RFC 5737 documentation IPv4 (198.51.100.24) and private IPv4 (192.168.1.1)
    req_priv = AnalysisRequest(
        sender_email="user@example.com",
        subject="Doc IP",
        body="Check http://198.51.100.24/test and http://192.168.1.1/admin",
    )
    findings_priv = url_analyzer.analyze(req_priv)
    priv_indicators = [f.indicator for f in findings_priv]
    assert "URL_NON_GLOBAL_IP_HOST" in priv_indicators
    assert "URL_IP_LITERAL_HOST" not in priv_indicators
    f_priv = next(f for f in findings_priv if f.indicator == "URL_NON_GLOBAL_IP_HOST")
    assert f_priv.severity == FindingSeverity.INFO


def test_insecure_http_on_credential_path_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Login link",
        body="Go to http://legacy-portal.org/auth/login.php to sign in.",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_INSECURE_HTTP_CREDENTIAL_PATH" in indicators
    f = next(f for f in findings if f.indicator == "URL_INSECURE_HTTP_CREDENTIAL_PATH")
    assert f.severity == FindingSeverity.LOW


def test_port_policy_8080_exempt_and_unusual_port_detected():
    # Port 8080 is standard under policy -> no finding
    req_8080 = AnalysisRequest(
        sender_email="user@example.com",
        subject="Web app",
        body="See http://staging.internal.com:8080/dashboard",
    )
    findings_8080 = url_analyzer.analyze(req_8080)
    assert not any(f.indicator == "URL_UNUSUAL_PORT" for f in findings_8080)

    # Port 8443 is non-standard -> triggers URL_UNUSUAL_PORT
    req_8443 = AnalysisRequest(
        sender_email="user@example.com",
        subject="Secure node",
        body="See https://staging.internal.com:8443/dashboard",
    )
    findings_8443 = url_analyzer.analyze(req_8443)
    assert any(f.indicator == "URL_UNUSUAL_PORT" for f in findings_8443)
    f = next(f for f in findings_8443 if f.indicator == "URL_UNUSUAL_PORT")
    assert f.severity == FindingSeverity.LOW


def test_suspicious_tld_and_punycode_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Deals",
        body="Get deals at http://free-promo.xyz/deal and http://xn--pple-43d.com/store",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_SUSPICIOUS_TLD" in indicators
    assert "URL_PUNYCODE_HOST" in indicators


def test_double_percent_encoding_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Encoded link",
        body="Check http://phish-target.com/%252e%252e/login",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_SUSPICIOUS_OBFUSCATION" in indicators
    f = next(f for f in findings if f.indicator == "URL_SUSPICIOUS_OBFUSCATION")
    assert f.severity == FindingSeverity.MEDIUM


def test_redirect_parameter_detected():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="SSO Login",
        body="Login via https://sso.example.com/oauth?redirect_uri=https://app.example.com/callback",
    )
    findings = url_analyzer.analyze(req)
    indicators = [f.indicator for f in findings]
    assert "URL_REDIRECT_PARAMETER_PRESENT" in indicators
    f = next(f for f in findings if f.indicator == "URL_REDIRECT_PARAMETER_PRESENT")
    assert f.severity == FindingSeverity.INFO


def test_finding_deduplication_across_multiple_urls():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Multiple Links",
        body=(
            "Click https://paypal.com.attacker.com/login and "
            "also https://paypal.com.attacker.com/settings or "
            "https://paypal.com.attacker.com/terms"
        ),
    )
    findings = url_analyzer.analyze(req)
    brand_sub_findings = [f for f in findings if f.indicator == "URL_BRAND_NAME_IN_UNRELATED_DOMAIN"]
    # Exactly one deduplicated finding for the hostname
    assert len(brand_sub_findings) == 1