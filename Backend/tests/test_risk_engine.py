from analyzer.risk_engine import analyze_url


def _shortener_result(url):
    return analyze_url(url, url)


def test_configured_shortener_hostname_keeps_existing_score_and_reason():
    for url in (
        "https://t.co/abc",
        "https://www.t.co/abc",
        "https://nested.t.co/abc",
        "https://T.CO./abc",
    ):
        result = _shortener_result(url)
        assert result["score"] == 40
        assert result["reasons"] == ["URL shortener detected"]


def test_shortener_text_outside_hostname_does_not_trigger():
    for url in (
        "https://example.com/path/t.co/abc",
        "https://example.com/?next=t.co",
        "https://example.com/#t.co",
        "https://nott.co/abc",
        "https://examplet.co/abc",
        "https://t.co.example.com/abc",
    ):
        result = _shortener_result(url)
        assert result["score"] == 0
        assert "URL shortener detected" not in result["reasons"]


def test_canonical_url_serialization_does_not_score_redirect():
    equivalent_pairs = (
        ("https://example.com", "https://example.com/"),
        ("https://EXAMPLE.com/", "https://example.com/"),
        ("https://example.com:443", "https://example.com/"),
        ("https://example.com.", "https://example.com/"),
    )
    for original, final in equivalent_pairs:
        result = analyze_url(original, final)
        assert result["score"] == 0
        assert "URL redirected to another address" not in result["reasons"]


def test_www_hostname_canonicalization_does_not_score_redirect():
    equivalent_pairs = (
        ("https://google.com", "https://www.google.com/"),
        ("https://www.example.com", "https://example.com/"),
        ("https://WWW.Example.COM./", "https://example.com/"),
    )
    for original, final in equivalent_pairs:
        result = analyze_url(original, final)
        assert result["score"] == 0
        assert "URL redirected to another address" not in result["reasons"]


def test_meaningful_redirects_still_score():
    redirect_pairs = (
        ("https://example.com/", "https://other-example.com/"),
        ("https://example.com/", "https://evil-example.com/"),
        ("https://login.example.com/", "https://example.com/"),
        ("https://example.com/", "https://accounts.example.com/"),
        ("https://example.com/login", "https://example.com/account"),
        ("http://example.com/", "https://example.com/"),
        ("https://example.com/?a=1", "https://example.com/?a=2"),
    )
    for original, final in redirect_pairs:
        baseline = analyze_url(original, original)
        result = analyze_url(original, final)
        assert result["score"] == baseline["score"] + 10
        assert "URL redirected to another address" in result["reasons"]


def test_fragments_are_ignored_but_queries_remain_significant():
    equivalent = analyze_url("https://example.com/#one", "https://example.com/#two")
    assert equivalent["score"] == 0

    meaningful = analyze_url("https://example.com/?campaign=one", "https://example.com/?campaign=two")
    assert meaningful["score"] == 10
