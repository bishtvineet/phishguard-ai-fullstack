from app.detectors.sender.domain_utils import (
    parse_and_normalize_email_domain,
    compute_levenshtein_distance,
    is_lookalike_of_trusted_domain,
)


def test_parse_domain_standard_clean():
    parsed = parse_and_normalize_email_domain("user@paypal.com")
    assert parsed is not None
    assert parsed.registered_domain == "paypal.com"
    assert parsed.domain == "paypal"
    assert parsed.suffix == "com"
    assert parsed.subdomain == ""
    assert parsed.subdomain_depth == 0
    assert not parsed.is_ip_literal
    assert not parsed.has_punycode


def test_parse_domain_strips_trailing_dns_dot_and_case():
    parsed = parse_and_normalize_email_domain("Alerts@Mail.Google.Com.")
    assert parsed is not None
    assert parsed.normalized_ascii == "mail.google.com"
    assert parsed.registered_domain == "google.com"
    assert parsed.subdomain == "mail"
    assert parsed.subdomain_depth == 1


def test_parse_domain_subdomain_spoofing():
    parsed = parse_and_normalize_email_domain("security@paypal.com.attacker.com")
    assert parsed is not None
    assert parsed.registered_domain == "attacker.com"
    assert parsed.subdomain == "paypal.com"
    assert parsed.subdomain_depth == 2


def test_parse_domain_ip_literal():
    parsed = parse_and_normalize_email_domain("admin@[192.0.2.1]")
    assert parsed is not None
    assert parsed.is_ip_literal is True
    assert parsed.registered_domain == "192.0.2.1"


def test_parse_domain_punycode():
    parsed = parse_and_normalize_email_domain("info@xn--pple-43d.com")
    assert parsed is not None
    assert parsed.has_punycode is True
    assert parsed.suffix == "com"


def test_levenshtein_distance():
    assert compute_levenshtein_distance("paypal", "paypal") == 0
    assert compute_levenshtein_distance("paypal", "paypa1") == 1
    assert compute_levenshtein_distance("google", "g00gle") == 2
    assert compute_levenshtein_distance("apple", "bpple") == 1


def test_lookalike_trusted_domain():
    # 1-char substitution or edit distance
    assert is_lookalike_of_trusted_domain("paypa1", "paypal") is True
    assert is_lookalike_of_trusted_domain("pypal", "paypal") is True
    assert is_lookalike_of_trusted_domain("paypals", "paypal") is True
    assert is_lookalike_of_trusted_domain("micros0ft", "microsoft") is True

    # Exact match must return False
    assert is_lookalike_of_trusted_domain("paypal", "paypal") is False
    assert is_lookalike_of_trusted_domain("google", "google") is False

    # Significant length differences must return False (false positive safeguard)
    assert is_lookalike_of_trusted_domain("paypalservices", "paypal") is False
    assert is_lookalike_of_trusted_domain("pal", "paypal") is False

def test_parse_domain_multi_part_tld_offline():
    # Verifies offline Public Suffix List correctly handles multi-part ccTLDs
    parsed = parse_and_normalize_email_domain("billing@service.amazon.co.uk")
    assert parsed is not None
    assert parsed.registered_domain == "amazon.co.uk"
    assert parsed.domain == "amazon"
    assert parsed.suffix == "co.uk"
    assert parsed.subdomain == "service"