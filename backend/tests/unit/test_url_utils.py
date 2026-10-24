from app.detectors.url.url_utils import extract_urls, validate_and_normalize_url


def test_malformed_interleaved_anchors_extracts_both_valid_urls():
    # Exactly tests the user scenario: valid1 and valid2 around broken unclosed anchor
    html_body = "<a href=\"https://valid1.com\">click<a href='unclosed... <a href=\"https://valid2.com\">next</a>"
    parsed_urls, limit_findings = extract_urls(body=html_body)
    urls = [u.normalized_url for u in parsed_urls]
    assert "https://valid1.com" in urls
    assert "https://valid2.com" in urls
    assert len([u for u in urls if u == "https://valid1.com"]) == 1
    assert len([u for u in urls if u == "https://valid2.com"]) == 1


def test_unsupported_schemes_rejected():
    body = (
        "<a href='javascript:alert(1)'>JS</a>"
        "<a href='mailto:support@test.com'>Mail</a>"
        "<a href='tel:+123456789'>Tel</a>"
        "<a href='data:text/html,test'>Data</a>"
        "<a href='#local-anchor'>Fragment</a>"
    )
    parsed_urls, _ = extract_urls(body=body)
    assert len(parsed_urls) == 0


def test_scheme_less_strings_in_plain_text_ignored():
    body = "Visit google.com/search or portal.internal/login for info."
    parsed_urls, _ = extract_urls(body=body)
    assert len(parsed_urls) == 0


def test_authority_validation_malformed_ports():
    # Out of range port (> 65535)
    components, is_malformed = validate_and_normalize_url("http://example.com:99999/test")
    assert is_malformed is True
    assert components is None

    # Non-numeric port
    components, is_malformed = validate_and_normalize_url("http://example.com:abc/test")
    assert is_malformed is True
    assert components is None

    # Port 0 (invalid)
    components, is_malformed = validate_and_normalize_url("http://example.com:0/test")
    assert is_malformed is True
    assert components is None


def test_authority_validation_unclosed_ipv6():
    components, is_malformed = validate_and_normalize_url("http://[2606:2800:220:1/path")
    assert is_malformed is True
    assert components is None


def test_conservative_normalization_preserves_semantics():
    # Strips default port 80 on HTTP and root trailing slash
    c1, _ = validate_and_normalize_url("HTTP://EXAMPLE.COM:80/")
    assert c1.normalized_url == "http://example.com"

    # Strips default port 443 on HTTPS
    c2, _ = validate_and_normalize_url("HTTPS://EXAMPLE.COM:443/")
    assert c2.normalized_url == "https://example.com"

    # Retains port 8080 (standard alternate HTTP port)
    c3, _ = validate_and_normalize_url("http://example.com:8080/")
    assert c3.normalized_url == "http://example.com:8080"

    # Preserves directory trailing slash
    c4, _ = validate_and_normalize_url("https://example.com/dir/")
    assert c4.normalized_url == "https://example.com/dir/"

    # Preserves raw query percent-encoding
    c5, _ = validate_and_normalize_url("https://example.com/api?param=%2F%26%3D")
    assert c5.normalized_url == "https://example.com/api?param=%2F%26%3D"


def test_offline_psl_decomposition():
    c, _ = validate_and_normalize_url("https://auth.portal.amazon.co.uk/path")
    assert c.domain_label == "amazon"
    assert c.suffix == "co.uk"
    assert c.registered_domain == "amazon.co.uk"
    assert c.subdomain == "auth.portal"


def test_url_length_limit():
    long_url = "https://example.com/" + ("a" * 2050)
    parsed_urls, findings = extract_urls(body="", additional_urls=[long_url])
    assert len(parsed_urls) == 0
    assert any(f.indicator == "URL_EXCESSIVE_LENGTH" for f in findings)


def test_url_evaluation_cap():
    many_urls = [f"https://example.com/page{i}" for i in range(60)]
    parsed_urls, findings = extract_urls(body="", additional_urls=many_urls)
    assert len(parsed_urls) == 50
    assert any(f.indicator == "URL_EVALUATION_CAP_EXCEEDED" for f in findings)