from shieldyn_oss.url_utils import extract_urls, is_shortener_url


def test_extract_urls_strips_punctuation():
    text = "Visit https://example.com/path)."
    urls = extract_urls(text)
    assert "https://example.com/path" in urls


def test_extract_urls_adds_scheme_for_www():
    text = "Go to www.example.com/abc"
    urls = extract_urls(text)
    assert "http://www.example.com/abc" in urls


def test_shortener_detection():
    assert is_shortener_url("https://bit.ly/abc")
