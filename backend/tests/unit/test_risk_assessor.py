from app.schemas.analysis import (
    AnalysisRequest,
    AuthStatus,
    EmailAuthenticationInput,
    Finding,
    FindingSeverity,
    RiskCategory,
)
from app.services.risk_assessor import extract_normalized_target, risk_assessor


def test_target_extraction_precedence_on_sender_brand_subdomain():
    # Description contains both brand 'paypal' and registered domain 'attacker-a.com'
    finding = Finding(
        analyzer="sender",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="Trusted brand 'paypal' appears in a subdomain label, but the registered domain is 'attacker-a.com'.",
        severity=FindingSeverity.MEDIUM,
    )
    target = extract_normalized_target(finding)
    assert target == "attacker-a.com"


def test_target_extraction_fallback_on_unquoted_text():
    finding = Finding(
        analyzer="sender",
        indicator="SUSPICIOUS_SUBDOMAIN_DEPTH",
        description="Sender domain has an unusually deep subdomain structure with no quotes.",
        severity=FindingSeverity.LOW,
    )
    target = extract_normalized_target(finding)
    assert target == "global_fallback"


def test_cross_analyzer_collision_resolves_highest_severity_and_repeat_bonus():
    # Sender emits MEDIUM (18 pts), URL emits HIGH (35 pts) on distinct targets
    f1 = Finding(
        analyzer="sender",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="Trusted brand 'paypal' appears in a subdomain label, but the registered domain is 'attacker-a.com'.",
        severity=FindingSeverity.MEDIUM,
    )
    f2 = Finding(
        analyzer="url",
        indicator="BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="URL hostname 'paypal.com.attacker-b.com' places trusted brand into a subdomain.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Test", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, [f1, f2])
    # Base weight 35 (max of MEDIUM, HIGH) + 2 (1 repeat) = 37 pts
    assert score == 37
    assert category == RiskCategory.SUSPICIOUS


def test_exact_duplicate_findings_do_not_add_repeat_bonus():
    f1 = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' closely resembles trusted brand 'paypal.com'.",
        severity=FindingSeverity.HIGH,
    )
    f2 = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' closely resembles trusted brand 'paypal.com'.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@paypa1.com", subject="Test", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, [f1, f2])
    assert score == 35  # Exact duplicate ignored


def test_repeat_bonus_capped_at_maximum():
    # 5 distinct targets under URL_SUSPICIOUS_TLD
    findings = [
        Finding(
            analyzer="url",
            indicator="URL_SUSPICIOUS_TLD",
            description=f"URL uses top-level domain '.{tld}'.",
            severity=FindingSeverity.LOW,
        )
        for tld in ["xyz", "top", "buzz", "rest", "club"]
    ]
    req = AnalysisRequest(sender_email="user@example.com", subject="Deals", body="Valid length body content")
    score, category, _ = risk_assessor.evaluate(req, findings)
    # Base weight 7 + min(6, 4 * 2) = 7 + 6 = 13 pts
    assert score == 13
    assert category == RiskCategory.LOW_RISK


def test_all_info_findings_produce_zero_score_with_disclaimer():
    f1 = Finding(
        analyzer="url",
        indicator="URL_PUNYCODE_HOST",
        description="URL hostname 'xn--pple-43d.com' uses Punycode encoding.",
        severity=FindingSeverity.INFO,
    )
    f2 = Finding(
        analyzer="url",
        indicator="URL_REDIRECT_PARAMETER_PRESENT",
        description="URL 'https://sso.com' contains redirect parameter.",
        severity=FindingSeverity.INFO,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Login", body="Valid length body content")
    score, category, summary = risk_assessor.evaluate(req, [f1, f2])
    assert score == 0
    assert category == RiskCategory.LOW_RISK
    assert "0 weighted risk score" in summary
    assert "does not prove an email is completely safe" in summary


def test_synergy_identity_and_credential_fires_once():
    f_sender = Finding(
        analyzer="sender",
        indicator="LOOKALIKE_TRUSTED_DOMAIN",
        description="Sender domain label 'paypa1' mimics paypal.com.",
        severity=FindingSeverity.HIGH,
    )
    f_url = Finding(
        analyzer="url",
        indicator="URL_BRAND_NAME_IN_UNRELATED_DOMAIN",
        description="URL hostname 'paypal.com.attacker.com' mimics paypal.",
        severity=FindingSeverity.HIGH,
    )
    f_cred = Finding(
        analyzer="content",
        indicator="CONTENT_CREDENTIAL_SOLICITATION",
        description="Email body: Contains actionable credential request.",
        severity=FindingSeverity.HIGH,
    )
    req = AnalysisRequest(sender_email="user@paypa1.com", subject="Alert", body="Please enter password")
    score, category, summary = risk_assessor.evaluate(req, [f_sender, f_url, f_cred])
    # Base: 35 + 35 + 35 = 105. Synergy SYN_IDENTITY_CREDENTIAL fires once (+15) -> 120 -> clamped to 100
    assert score == 100
    assert category == RiskCategory.HIGH_RISK
    assert "Identity Mimicry & Credential Solicitation" in summary


def test_synergy_urgency_and_financial_fires_once():
    f_urg = Finding(
        analyzer="content",
        indicator="CONTENT_URGENCY_PRESSURE",
        description="Email body: Immediate action required.",
        severity=FindingSeverity.MEDIUM,
    )
    f_fin = Finding(
        analyzer="content",
        indicator="CONTENT_FINANCIAL_LURE",
        description="Email body: Unclaimed funds available.",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(sender_email="user@example.com", subject="Funds", body="Claim your funds immediately")
    score, category, summary = risk_assessor.evaluate(req, [f_urg, f_fin])
    # 18 + 18 + 10 = 46 pts
    assert score == 46
    assert category == RiskCategory.SUSPICIOUS
    assert "Urgency Pressure & Financial Lure" in summary


def test_threshold_boundaries():
    req = AnalysisRequest(sender_email="user@example.com", subject="Test", body="Valid length body content")

    # Score 24 -> LOW_RISK
    # 1 Medium (18 pts) + 1 Low (7 pts) with distinct repeat target on Low:
    # Or 2 Lows (7 + 7 = 14) + 5 repeat bonus = not 24.
    # Craft exactly 24: 1 Medium (18) + 3 repeat targets on that Medium (repeat bonus = 3 * 2 = 6) -> 18 + 6 = 24!
    f_24 = [
        Finding(analyzer="url", indicator="M", description=f"Host '{i}.com'", severity=FindingSeverity.MEDIUM)
        for i in range(4)  # 1 base (18) + 3 repeats (6) = 24
    ]
    score_24, cat_24, _ = risk_assessor.evaluate(req, f_24)
    assert score_24 == 24
    assert cat_24 == RiskCategory.LOW_RISK

    # Score 25 -> SUSPICIOUS: 1 Medium (18) + 1 Low (7) = 25
    score_25, cat_25, _ = risk_assessor.evaluate(
        req,
        [
            Finding(analyzer="url", indicator="M", description="Host 'a.com'", severity=FindingSeverity.MEDIUM),
            Finding(analyzer="url", indicator="L", description="Host 'b.com'", severity=FindingSeverity.LOW),
        ],
    )
    assert score_25 == 25
    assert cat_25 == RiskCategory.SUSPICIOUS

    # Score 59 -> SUSPICIOUS:
    # 1 High (35) + 3 repeats on High (max repeat bonus = 6) = 41
    # 1 Medium (18) = 18
    # Total = 41 + 18 = 59
    f_59 = [
        Finding(analyzer="url", indicator="H", description="Host '1.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '2.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '3.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="H", description="Host '4.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="M", description="Host 'm.com'", severity=FindingSeverity.MEDIUM),
    ]
    score_59, cat_59, _ = risk_assessor.evaluate(req, f_59)
    assert score_59 == 59
    assert cat_59 == RiskCategory.SUSPICIOUS

    # Score 60 -> HIGH_RISK:
    # 1 High (35) + 1 Medium (18) + 1 Low (7) = 60
    f_60 = [
        Finding(analyzer="url", indicator="H", description="Host 'h.com'", severity=FindingSeverity.HIGH),
        Finding(analyzer="url", indicator="M", description="Host 'm.com'", severity=FindingSeverity.MEDIUM),
        Finding(analyzer="url", indicator="L", description="Host 'l.com'", severity=FindingSeverity.LOW),
    ]
    score_60, cat_60, _ = risk_assessor.evaluate(req, f_60)
    assert score_60 == 60
    assert cat_60 == RiskCategory.HIGH_RISK


def test_inconclusive_on_empty_content_with_no_findings():
    req = AnalysisRequest(sender_email="user@example.com", subject="", body="hi")
    score, category, summary = risk_assessor.evaluate(req, [])
    assert score is None
    assert category == RiskCategory.INCONCLUSIVE
    assert "Insufficient content" in summary


def test_mismatched_reply_to_with_empty_content_is_not_inconclusive():
    # Minimal body and empty subject, but findings exist (REPLY_TO_DOMAIN_MISMATCH)
    f = Finding(
        analyzer="sender",
        indicator="REPLY_TO_DOMAIN_MISMATCH",
        description="Reply-To address points to an unrelated domain ('attacker.com').",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(
        sender_email="user@legit.com",
        reply_to="attacker@attacker.com",
        subject="",
        body="hi",
    )
    score, category, _ = risk_assessor.evaluate(req, [f])
    assert score == 18
    assert category == RiskCategory.LOW_RISK


def test_sender_ip_literal_with_empty_body_scores_exact_eighteen():
    f = Finding(
        analyzer="sender",
        indicator="IP_LITERAL_SENDER_DOMAIN",
        description="Sender domain is a raw IP literal (192.168.1.1) rather than a named host.",
        severity=FindingSeverity.MEDIUM,
    )
    req = AnalysisRequest(sender_email="user@[192.168.1.1]", subject="", body="")
    score, category, _ = risk_assessor.evaluate(req, [f])
    assert score == 18
    assert category == RiskCategory.LOW_RISK


def test_neutral_authentication_unknown_and_none_scores_zero():
    req = AnalysisRequest(
        sender_email="user@example.com",
        subject="Meeting Notes",
        body="Attached are the notes from our sprint planning meeting.",
        authentication=EmailAuthenticationInput(
            spf=AuthStatus.UNKNOWN,
            dkim=AuthStatus.NONE,
            dmarc=AuthStatus.UNKNOWN,
        ),
    )
    score, category, _ = risk_assessor.evaluate(req, [])
    assert score == 0
    assert category == RiskCategory.LOW_RISK