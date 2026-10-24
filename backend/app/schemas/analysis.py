import re
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

# RFC 5322-compliant structural pattern supporting both domain hostnames and bracketed IP literals
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+|\[[a-zA-Z0-9:.]+\])$"
)


class AuthStatus(str, Enum):
    """Represents the evaluation state of email authentication mechanisms.
    
    PASS: Explicitly authenticated (cryptographic signature or SPF match succeeded).
    FAIL: Explicitly failed authentication (hard or soft failure).
    NONE: Record was evaluated, but no policy or signature was published.
    UNKNOWN: Information is unavailable, stripped by upstream relays, or unverifiable.
             Carries zero negative score penalty.
    """
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    UNKNOWN = "unknown"


class RiskCategory(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    INCONCLUSIVE = "Inconclusive"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    analyzer: str = Field(..., min_length=1, max_length=50, description="Analyzer identifier (e.g., sender, content, url, ml)")
    indicator: str = Field(..., min_length=1, max_length=100, description="Machine-readable indicator code")
    description: str = Field(..., min_length=1, max_length=500, description="Explainable finding for non-technical users")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO, description="Severity rating of this specific indicator")
    target: Optional[str] = Field(default=None, max_length=255, description="Normalized entity target for deduplication and repeat scoring")


class EmailAuthenticationInput(BaseModel):
    spf: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported SPF verification outcome")
    dkim: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported DKIM verification outcome")
    dmarc: AuthStatus = Field(default=AuthStatus.UNKNOWN, description="Reported DMARC verification outcome")


class AnalysisRequest(BaseModel):
    sender_email: str = Field(
        ...,
        min_length=3,
        max_length=320,
        description="Sender email address from header or envelope",
    )
    reply_to: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=320,
        description="Optional Reply-To header address",
    )
    subject: str = Field(
        default="",
        max_length=998,
        description="Email subject line (RFC 5322 line limit)",
    )
    body: str = Field(
        default="",
        max_length=100_000,
        description="Raw email body text (capped at 100,000 characters)",
    )
    additional_urls: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="Optional list of user-provided URLs (maximum 50 items)",
    )
    authentication: EmailAuthenticationInput = Field(
        default_factory=EmailAuthenticationInput,
        description="Optional email authentication outcomes",
    )

    @field_validator("sender_email", "reply_to")
    @classmethod
    def validate_email_syntax(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value_stripped = value.strip()
        if not EMAIL_REGEX.match(value_stripped):
            raise ValueError(f"'{value}' is not a valid email address syntax.")
        return value_stripped

    @field_validator("additional_urls")
    @classmethod
    def validate_url_lengths(cls, urls: List[str]) -> List[str]:
        for url in urls:
            if len(url) > 2048:
                raise ValueError("Individual URL exceeds maximum allowed length of 2048 characters.")
        return urls


class AnalysisResponse(BaseModel):
    risk_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Synthesized risk score (0-100). Must be None if risk_category is Inconclusive.",
    )
    risk_category: RiskCategory = Field(..., description="Overall qualitative assessment verdict")
    summary: str = Field(..., min_length=1, max_length=1000, description="High-level narrative of the assessment")
    findings: List[Finding] = Field(default_factory=list, description="Granular evidence collected across analyzers")
    recommendations: List[str] = Field(default_factory=list, description="Actionable security guidance tailored to findings")

    @model_validator(mode="after")
    def verify_score_category_cohesion(self) -> "AnalysisResponse":
        if self.risk_category == RiskCategory.INCONCLUSIVE:
            if self.risk_score is not None:
                raise ValueError("risk_score must be None when risk_category is 'Inconclusive'.")
        else:
            if self.risk_score is None:
                raise ValueError(f"risk_score is required when risk_category is '{self.risk_category.value}'.")
        return self