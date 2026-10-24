from app.detectors.content.text_utils import (
    _sanitize_html_fallback,
    normalize_content_text,
    scan_and_strip_zero_width,
    strip_html_safely,
)


def test_plain_text_normalization():
    raw = "   Please   verify    your   account immediately.   "
    res = normalize_content_text(raw)
    assert res.cleaned_text == "Please verify your account immediately."
    assert not res.has_zero_width_obfuscation
    assert res.zero_width_count == 0


def test_html_stripping_and_entities():
    html_input = "<p>Hello &amp; welcome! Click <a href='https://test.com'>here</a> &quot;now&quot;.</p>"
    text = strip_html_safely(html_input)
    assert "Hello & welcome!" in text
    assert 'here "now".' in text
    assert "<p>" not in text
    assert "<a" not in text


def test_html_script_and_style_exclusion():
    html_input = (
        "<html><head>"
        "<style>body { color: red; } .password { display: none; }</style>"
        "<script>var secret_token = '12345'; alert('verify password');</script>"
        "</head><body><p>Legitimate account notice.</p></body></html>"
    )
    res = normalize_content_text(html_input)
    assert "Legitimate account notice." in res.cleaned_text
    assert "color: red" not in res.cleaned_text
    assert "secret_token" not in res.cleaned_text
    assert "alert('verify password')" not in res.cleaned_text


def test_malformed_html_handling():
    # Broken/unclosed tags and truncated markers must not expose script body or crash
    malformed_input = (
        "<div><b>Important notice:</b> <script>malicious_code();</script>"
        "<p unclosed attribute='test>Your invoice is ready. <a href='broken"
    )
    res = normalize_content_text(malformed_input)
    assert "Important notice:" in res.cleaned_text
    assert "Your invoice is ready." in res.cleaned_text
    assert "malicious_code" not in res.cleaned_text


def test_zero_width_intra_word_obfuscation():
    # Intra-word insertion with 2 zero-width spaces: p\u200Bw\u200Bd
    raw = "Please reset your p\u200Bw\u200Bd now."
    cleaned, is_suspicious, count = scan_and_strip_zero_width(raw)
    assert cleaned == "Please reset your pwd now."
    assert is_suspicious is True
    assert count == 2

    res = normalize_content_text(raw)
    assert res.cleaned_text == "Please reset your pwd now."
    assert res.has_zero_width_obfuscation is True
    assert res.zero_width_count == 2


def test_zero_width_multiple_occurrences():
    # Multiple invisible codepoints
    raw = "Urgent\u200C notice\u200D regarding account."
    cleaned, is_suspicious, count = scan_and_strip_zero_width(raw)
    assert cleaned == "Urgent notice regarding account."
    assert is_suspicious is True
    assert count == 2


def test_unicode_nfkd_decomposition():
    # Ligature 'ﬁ' -> 'fi', full-width characters 'Ｐａｓｓ' -> 'Pass'
    raw = "Please conﬁrm your Ｐａｓｓword."
    res = normalize_content_text(raw)
    assert "confirm your Password." in res.cleaned_text


def test_normally_closed_script_and_style_tags_suppress_only_content():
    # Public path: parser cleanly suppresses script/style blocks and retains surrounding text
    raw = (
        "<p>Pre-script text.</p>"
        "<script type='text/javascript'>console.log('internal code');</script>"
        "<style>body { background: #000; }</style>"
        "<p>Post-script text.</p>"
    )
    res = normalize_content_text(raw)
    assert "Pre-script text." in res.cleaned_text
    assert "Post-script text." in res.cleaned_text
    assert "console.log" not in res.cleaned_text
    assert "background: #000" not in res.cleaned_text


def test_unclosed_script_tag_safely_suppresses_ambiguous_remainder():
    # Public path: parser reaches EOF with unclosed script tag; ambiguous remainder is suppressed
    raw = "<p>Legitimate header.</p><script>var code = 1;\nPlease verify your password immediately."
    res = normalize_content_text(raw)
    assert "Legitimate header." in res.cleaned_text
    assert "code = 1" not in res.cleaned_text
    assert "Please verify your password immediately." not in res.cleaned_text


def test_fallback_sanitizer_closed_script_and_style_tags():
    # Deterministic test: fallback helper removes closed script/style blocks cleanly
    raw = (
        "<div>Pre-fallback text.</div>"
        "<script>bad_script();</script>"
        "<style>.hide { display: none; }</style>"
        "<div>Post-fallback text.</div>"
    )
    cleaned = _sanitize_html_fallback(raw)
    assert "Pre-fallback text." in cleaned
    assert "Post-fallback text." in cleaned
    assert "bad_script" not in cleaned
    assert "display: none" not in cleaned


def test_fallback_sanitizer_unclosed_script_suppresses_trailing_remainder():
    # Deterministic test: fallback helper suppresses opening tag and all subsequent text through EOF
    raw = (
        "<div>Header notice.</div>"
        "<script type='text/javascript'>var exploit = 'active';"
        "<div>Apparent trailing visible text.</div>"
    )
    cleaned = _sanitize_html_fallback(raw)
    assert "Header notice." in cleaned
    assert "exploit" not in cleaned
    assert "Apparent trailing visible text." not in cleaned


def test_fallback_sanitizer_incomplete_opening_tag_at_eof():
    # Deterministic test: tag truncated at EOF without closing '>' delimiter
    raw = "<div>Visible text.</div><script type='text/javascript' unclosed"
    cleaned = _sanitize_html_fallback(raw)
    assert "Visible text." in cleaned
    assert "script" not in cleaned
    assert "unclosed" not in cleaned


def test_fallback_sanitizer_does_not_suppress_ordinary_words():
    # Ensures words like 'scripture' or 'styleguide' are not erroneously stripped
    raw = "<p>Reading scripture in the styleguide.</p>"
    cleaned = _sanitize_html_fallback(raw)
    assert "Reading scripture in the styleguide." in cleaned