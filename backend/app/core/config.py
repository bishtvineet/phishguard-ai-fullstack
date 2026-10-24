import re
from dataclasses import dataclass, field
from typing import Pattern, Set


@dataclass(frozen=True)
class ContentAnalysisSettings:
    """Centralized regex patterns and thresholds for content heuristic detection."""

    URGENCY_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(within\s+\d+\s+(?:hours?|days?)|immediate(?:ly)?\s+action|account\s+will\s+be\s+suspended|final\s+notice|immediate\s+suspension)\b",
            re.IGNORECASE,
        )
    )

    CREDENTIAL_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(verify|confirm|reset|update|enter)\b[\w\s]{0,20}\b(password|passcode|pin|login\s+credentials|secret\s+key)\b",
            re.IGNORECASE,
        )
    )

    FINANCIAL_LURE_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(unclaimed\s+(?:funds?|assets?|inheritance)|lottery\s+winner|wire\s+transfer\s+reward|crypto\s+giveaway|tax\s+refund\s+pending|pending\s+tax\s+refund)\b",
            re.IGNORECASE,
        )
    )

    AUTHORITY_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(it\s+support\s+desk|account\s+investigation\s+unit|security\s+dispatch\s+team|legal\s+compliance\s+department)\b",
            re.IGNORECASE,
        )
    )

    SALUTATION_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"^(?:dear\s+(?:customer|user|member|client|sir\s*/\s*madam|account\s+holder))\b",
            re.IGNORECASE,
        )
    )

    SALUTATION_MAX_OFFSET: int = 100


@dataclass(frozen=True)
class URLAnalysisSettings:
    """Centralized configuration, patterns, and thresholds for URL analysis."""

    SUSPICIOUS_TLDS: Set[str] = field(
        default_factory=lambda: {
            "top",
            "xyz",
            "fit",
            "rest",
            "buzz",
            "cfd",
            "sbs",
            "club",
            "work",
            "surf",
        }
    )

    STANDARD_PORTS: Set[int] = field(
        default_factory=lambda: {80, 443, 8080}
    )

    MAX_URLS_TO_ANALYZE: int = 50
    MAX_URL_LENGTH: int = 2048
    MAX_PATH_DEPTH: int = 6

    CREDENTIAL_PATH_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"\b(login|signin|account|verify|password|auth|billing)\b",
            re.IGNORECASE,
        )
    )

    REDIRECT_PARAM_PATTERN: Pattern = field(
        default_factory=lambda: re.compile(
            r"[?&](?:next|redirect|redirect_uri|url|dest|destination|target)=https?://",
            re.IGNORECASE,
        )
    )


@dataclass(frozen=True)
class RiskScoringSettings:
    """Weights, repeat steps, and thresholds for centralized risk assessment."""

    WEIGHT_HIGH: int = 35
    WEIGHT_MEDIUM: int = 18
    WEIGHT_LOW: int = 7
    WEIGHT_INFO: int = 0

    REPEAT_STEP: int = 2
    MAX_REPEAT_BONUS: int = 6

    SYNERGY_IDENTITY_CREDENTIAL: int = 15
    SYNERGY_URGENCY_FINANCIAL: int = 10
    SYNERGY_INSECURE_CREDENTIAL: int = 10

    THRESHOLD_SUSPICIOUS: int = 25
    THRESHOLD_HIGH_RISK: int = 60


@dataclass(frozen=True)
class AppSettings:
    """Aggregated configuration for all detection engines."""

    # Sender Analysis Settings
    TRUSTED_DOMAINS: Set[str] = field(
        default_factory=lambda: {
            "paypal.com",
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
        }
    )

    SUSPICIOUS_DOMAIN_KEYWORDS: Set[str] = field(
        default_factory=lambda: {
            "verify",
            "verification",
            "secure",
            "security",
            "login",
            "signin",
            "update",
            "billing",
            "account",
            "support",
            "banking",
        }
    )

    WELL_KNOWN_BULK_SENDERS: Set[str] = field(
        default_factory=lambda: {
            "sendgrid.net",
            "mailchimp.com",
            "amazonses.com",
            "zendesk.com",
            "salesforce.com",
            "hubspot.com",
            "mailgun.org",
        }
    )

    MAX_UNSUSPICIOUS_SUBDOMAIN_DEPTH: int = 4

    # Sub-Engine Settings
    content: ContentAnalysisSettings = field(default_factory=ContentAnalysisSettings)
    url: URLAnalysisSettings = field(default_factory=URLAnalysisSettings)
    scoring: RiskScoringSettings = field(default_factory=RiskScoringSettings)


settings = AppSettings()