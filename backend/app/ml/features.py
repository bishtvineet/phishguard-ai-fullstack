import math
from collections import Counter
from typing import List, Optional

from app.detectors.url.url_utils import validate_and_normalize_url

# Ordered schema of the 14 offline lexical URL features
FEATURE_NAMES: List[str] = [
    "length_url",
    "length_host",
    "length_path",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_digits_url",
    "ratio_digits_host",
    "entropy_host",
    "subdomain_depth",
    "has_ip_host",
    "has_at_symbol",
    "is_https",
]


def compute_shannon_entropy(text: str) -> float:
    """Computes Shannon entropy (base 2) for a given string.

    Returns 0.0 for empty or single-character strings. All outputs are finite floats >= 0.0.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return float(entropy)


def extract_lexical_features(url: str) -> Optional[List[float]]:
    """Extracts a fixed 14-element numerical feature vector from a raw URL string.

    Reuses validate_and_normalize_url for parsing, scheme checks, and offline domain decomposition.

    Returns:
        List[float] matching FEATURE_NAMES ordering if the URL is structurally valid.
        None if the URL is malformed, has an unsupported scheme, or cannot be parsed.
    """
    if not isinstance(url, str) or not url.strip():
        return None

    components, is_malformed = validate_and_normalize_url(url.strip())
    if is_malformed or components is None:
        return None

    norm_url = components.normalized_url
    hostname = components.hostname
    path = components.path

    # Subdomain depth: count dot-separated segments in subdomain; 0 if empty
    subdomain_depth = (
        float(len(components.subdomain.split(".")))
        if components.subdomain
        else 0.0
    )

    # Host digit ratio: safely bounded against empty host
    host_len = len(hostname)
    digits_host = sum(c.isdigit() for c in hostname)
    ratio_digits_host = float(digits_host / host_len) if host_len > 0 else 0.0

    # Shannon entropy of hostname
    entropy_host = compute_shannon_entropy(hostname)

    features: List[float] = [
        float(len(norm_url)),                                   # 1. length_url
        float(host_len),                                        # 2. length_host
        float(len(path)),                                       # 3. length_path
        float(norm_url.count(".")),                             # 4. count_dots
        float(norm_url.count("-")),                             # 5. count_hyphens
        float(norm_url.count("_")),                             # 6. count_underscores
        float(path.count("/")),                                 # 7. count_slashes
        float(sum(c.isdigit() for c in norm_url)),              # 8. count_digits_url
        ratio_digits_host,                                      # 9. ratio_digits_host
        entropy_host,                                           # 10. entropy_host
        subdomain_depth,                                        # 11. subdomain_depth
        1.0 if components.is_ip else 0.0,                       # 12. has_ip_host
        1.0 if components.has_userinfo else 0.0,                 # 13. has_at_symbol
        1.0 if components.scheme == "https" else 0.0,           # 14. is_https
    ]

    return features