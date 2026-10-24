import math
import pytest

from app.ml.features import FEATURE_NAMES, extract_lexical_features


def test_feature_names_count_and_uniqueness():
    assert len(FEATURE_NAMES) == 14
    assert len(set(FEATURE_NAMES)) == 14


def test_extract_lexical_features_returns_none_for_invalid_urls():
    assert extract_lexical_features("") is None
    assert extract_lexical_features("not-a-url") is None
    assert extract_lexical_features("javascript:alert(1)") is None
    assert extract_lexical_features("ftp://ftp.example.com/file.txt") is None


def test_extract_lexical_features_returns_correct_length_and_finite_numbers():
    features = extract_lexical_features("https://www.example.com/path/to/page?param1=value&param2=123#section")
    assert features is not None
    assert len(features) == 14
    for val in features:
        assert isinstance(val, (int, float))
        assert math.isfinite(val)


def test_url_length_feature():
    url = "http://example.com/test"
    features = extract_lexical_features(url)
    assert features is not None
    # Feature 0: length_url
    assert features[0] == float(len(url))


def test_ip_address_detection_features():
    ip_url = "http://192.168.1.1/login"
    features = extract_lexical_features(ip_url)
    assert features is not None
    # Feature 11: has_ip_host
    assert features[11] == 1.0


def test_non_ip_hostname_features():
    domain_url = "https://accounts.google.com/signin"
    features = extract_lexical_features(domain_url)
    assert features is not None
    # Feature 11: has_ip_host
    assert features[11] == 0.0


def test_https_feature():
    https_url = "https://security-update.com/verify"
    features_https = extract_lexical_features(https_url)
    assert features_https is not None
    # Feature 13: is_https
    assert features_https[13] == 1.0

    http_url = "http://security-update.com/verify"
    features_http = extract_lexical_features(http_url)
    assert features_http is not None
    # Feature 13: is_https
    assert features_http[13] == 0.0


def test_at_symbol_detection():
    tricky_url = "http://legit.com@phishing.site/login"
    features = extract_lexical_features(tricky_url)
    assert features is not None
    # Feature 12: has_at_symbol
    assert features[12] == 1.0

    clean_url = "http://phishing.site/login"
    features_clean = extract_lexical_features(clean_url)
    assert features_clean is not None
    assert features_clean[12] == 0.0


def test_subdomain_depth_and_hyphen_features():
    multi_sub_url = "http://login.secure-portal.update.example.co.uk/path"
    features = extract_lexical_features(multi_sub_url)
    assert features is not None
    # Feature 4: count_hyphens
    assert features[4] >= 1.0
    # Feature 10: subdomain_depth
    assert features[10] >= 2.0