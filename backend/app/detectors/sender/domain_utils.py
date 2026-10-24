import ipaddress
from dataclasses import dataclass
from typing import Optional
import idna
import tldextract

# Initialize extractor with local cache/offline PSL snapshot
_extractor = tldextract.TLDExtract(cache_dir=None)

SUBSTITUTION_MAP = {
    "0": "o",
    "1": "l",
    "l": "i",
    "vv": "w",
    "rn": "m",
    "5": "s",
}


@dataclass(frozen=True)
class ParsedDomain:
    raw_domain: str
    normalized_ascii: str
    is_ip_literal: bool
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    subdomain_depth: int
    has_punycode: bool


def parse_and_normalize_email_domain(email_str: str) -> Optional[ParsedDomain]:
    """Parses, cleans, and normalizes an email address's domain portion."""
    if not email_str or "@" not in email_str:
        return None

    email_cleaned = email_str.strip()
    parts = email_cleaned.rsplit("@", 1)
    if len(parts) != 2:
        return None

    raw_domain = parts[1].strip()

    # Remove optional trailing DNS root dot
    if raw_domain.endswith("."):
        raw_domain = raw_domain[:-1]

    if not raw_domain:
        return None

    # Check for IP-literal: e.g., [192.0.2.1] or bare IP
    ip_candidate = raw_domain.strip("[]")
    is_ip = False
    try:
        ipaddress.ip_address(ip_candidate)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        return ParsedDomain(
            raw_domain=raw_domain,
            normalized_ascii=ip_candidate.lower(),
            is_ip_literal=True,
            subdomain="",
            domain=ip_candidate,
            suffix="",
            registered_domain=ip_candidate,
            subdomain_depth=0,
            has_punycode=False,
        )

    # Normalize through IDNA (Punycode conversion)
    try:
        normalized_ascii = idna.encode(raw_domain.lower()).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        normalized_ascii = raw_domain.lower()

    has_punycode = "xn--" in normalized_ascii

    ext = _extractor(normalized_ascii)
    subdomain = ext.subdomain
    domain = ext.domain
    suffix = ext.suffix

    if domain and suffix:
        registered_domain = f"{domain}.{suffix}"
    elif "." in normalized_ascii:
        # Fallback for synthetic/testing TLDs like .example or .test not on the public suffix list
        labels = normalized_ascii.split(".")
        registered_domain = ".".join(labels[-2:])
        domain = labels[-2]
        suffix = labels[-1]
        subdomain = ".".join(labels[:-2])
    else:
        registered_domain = normalized_ascii
        domain = normalized_ascii
        suffix = ""
        subdomain = ""

    subdomain_depth = len(subdomain.split(".")) if subdomain else 0

    return ParsedDomain(
        raw_domain=raw_domain,
        normalized_ascii=normalized_ascii,
        is_ip_literal=False,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=registered_domain,
        subdomain_depth=subdomain_depth,
        has_punycode=has_punycode,
    )


def compute_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard edit distance between two strings."""
    if len(s1) < len(s2):
        return compute_levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_leet_substitutions(label: str) -> str:
    """Converts common lookalike leet characters into standard Latin equivalents."""
    res = label.lower()
    for k, v in SUBSTITUTION_MAP.items():
        res = res.replace(k, v)
    return res


def is_lookalike_of_trusted_domain(candidate_label: str, trusted_label: str) -> bool:
    """Evaluates whether a candidate domain label is a deceptive lookalike of a trusted label.
    
    Returns False if exact match or if lengths differ by more than 1 character.
    """
    candidate = candidate_label.lower()
    trusted = trusted_label.lower()

    if candidate == trusted:
        return False

    if abs(len(candidate) - len(trusted)) > 1:
        return False

    if normalize_leet_substitutions(candidate) == trusted:
        return True

    dist = compute_levenshtein_distance(candidate, trusted)
    return dist == 1