import html
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import List, Tuple

# Targeted invisible/zero-width formatting codepoints commonly used for filter evasion
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space / BOM
    "\u00ad",  # Soft hyphen
}

# Regex to safely strip closed script/style tags and their internal content in fallback mode
_SCRIPT_STYLE_BLOCK_RE = re.compile(
    r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL
)

# Hardened fallback regex: matches an opening <script>, <style>, or <noscript> tag
# whether delimited by '>' or truncated/incomplete at EOF, and conservatively
# suppresses all ambiguous trailing content through EOF without speculative resumption.
_UNCLOSED_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript)\b(?:[^>]*>|[^>]*$).*$", re.IGNORECASE | re.DOTALL
)

_TAG_STRIP_RE = re.compile(r"<[^>]+>")


class SafeHTMLTextExtractor(HTMLParser):
    """Parses HTML document bodies into plain text.
    
    Suppresses content inside <script>, <style>, and <noscript> tags,
    unescapes HTML entities, and separates tag boundaries with whitespace.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._suppress_depth = 0
        self._text_fragments: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() in ("script", "style", "noscript"):
            self._suppress_depth += 1

    def handle_endtag(self, tag: str):
        if tag.lower() in ("script", "style", "noscript"):
            if self._suppress_depth > 0:
                self._suppress_depth -= 1

    def handle_data(self, data: str):
        if self._suppress_depth == 0 and data:
            self._text_fragments.append(data)

    def get_text(self) -> str:
        return " ".join(self._text_fragments)

    @property
    def has_unclosed_suppressed_block(self) -> bool:
        return self._suppress_depth > 0


@dataclass(frozen=True)
class NormalizedText:
    raw_text: str
    cleaned_text: str
    has_zero_width_obfuscation: bool
    zero_width_count: int


def scan_and_strip_zero_width(text: str) -> Tuple[str, bool, int]:
    """Inspects raw text for invisible/zero-width codepoints before removing them.
    
    Returns (cleaned_text, is_suspicious, count).
    """
    if not text:
        return "", False, 0

    count = 0
    clean_chars = []
    has_intra_word_obfuscation = False

    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            count += 1
            # Check if placed between alphanumeric word characters (e.g., p\u200Bw\u200Bd)
            if 0 < i < len(text) - 1:
                prev_char = text[i - 1]
                next_char = text[i + 1]
                if prev_char.isalnum() and next_char.isalnum():
                    has_intra_word_obfuscation = True
        else:
            clean_chars.append(ch)

    is_suspicious = count >= 2 or has_intra_word_obfuscation
    return "".join(clean_chars), is_suspicious, count


def _sanitize_html_fallback(html_content: str) -> str:
    """Deterministic fallback sanitizer for severely malformed HTML markup.
    
    1. Strips closed <script>, <style>, and <noscript> blocks with their content.
    2. Conservatively suppresses any unclosed or truncated opening tag and its
       trailing content through EOF.
    3. Strips remaining HTML tag markers.
    4. Unescapes HTML entities.
    """
    # 1. Strip properly closed blocks
    sanitized = _SCRIPT_STYLE_BLOCK_RE.sub(" ", html_content)
    # 2. Suppress unclosed or truncated opening tags and trailing remainder through EOF
    sanitized = _UNCLOSED_SCRIPT_STYLE_RE.sub(" ", sanitized)
    # 3. Strip remaining HTML tags
    sanitized = _TAG_STRIP_RE.sub(" ", sanitized)
    # 4. Unescape entities
    return html.unescape(sanitized)


def strip_html_safely(html_content: str) -> str:
    """Strips HTML markup and unescapes entities safely.
    
    Uses SafeHTMLTextExtractor. If parsing fails on malformed input, it invokes
    _sanitize_html_fallback to ensure script/style content is never leaked.
    """
    if not html_content or "<" not in html_content:
        return html.unescape(html_content) if html_content else ""

    parser = SafeHTMLTextExtractor()
    try:
        parser.feed(html_content)
        parser.close()
        raw_result = parser.get_text()
    except Exception:
        raw_result = _sanitize_html_fallback(html_content)

    # Clean and collapse multi-space gaps caused by adjacent tag transitions
    return re.sub(r"\s+", " ", raw_result).strip()


def normalize_content_text(text: str) -> NormalizedText:
    """Performs end-to-end normalization on an email text field (subject or body).
    
    1. Scans and strips zero-width codepoints.
    2. Strips HTML markup and resolves entities safely.
    3. Normalizes Unicode via NFKD decomposition.
    4. Collapses whitespace.
    """
    if not text:
        return NormalizedText(
            raw_text="",
            cleaned_text="",
            has_zero_width_obfuscation=False,
            zero_width_count=0,
        )

    # 1. Zero-width character scan and purge
    no_zw_text, has_obfuscation, zw_count = scan_and_strip_zero_width(text)

    # 2. HTML stripping and entity unescaping
    plain_text = strip_html_safely(no_zw_text)

    # 3. Unicode NFKD normalization
    normalized_unicode = unicodedata.normalize("NFKD", plain_text)

    # 4. Whitespace cleanup (preserve case in cleaned_text; regex checks can match lower/case-insensitively)
    collapsed_whitespace = re.sub(r"\s+", " ", normalized_unicode).strip()

    return NormalizedText(
        raw_text=text,
        cleaned_text=collapsed_whitespace,
        has_zero_width_obfuscation=has_obfuscation,
        zero_width_count=zw_count,
    )