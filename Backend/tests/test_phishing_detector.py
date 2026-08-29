from detectors.phishing_detector import detect_phishing


def test_search_form_has_no_generic_form_score() -> None:
    result = detect_phishing('<form action="/search"><input type="search"></form>')
    assert result == {"score": 0, "reasons": []}


def test_contact_form_has_no_generic_form_score() -> None:
    html = '<form action="/contact"><input type="text"><input type="email"><textarea></textarea></form>'
    result = detect_phishing(html)
    assert result == {"score": 0, "reasons": []}


def test_newsletter_form_has_no_generic_form_score() -> None:
    result = detect_phishing('<form><input type="email"><button>Subscribe</button></form>')
    assert result == {"score": 0, "reasons": []}


def test_password_signal_remains_without_generic_form_reason() -> None:
    result = detect_phishing('<form><input type="password"></form>')
    assert result == {
        "score": 20,
        "reasons": ["Password input field detected"],
    }


def test_password_and_existing_keyword_signals_remain() -> None:
    result = detect_phishing(
        '<h1>Verify your account</h1><form><input type="password"></form>'
    )
    assert result["score"] == 25
    assert "Suspicious keyword detected: verify your account" in result["reasons"]
    assert "Password input field detected" in result["reasons"]
    assert "Page contains HTML forms" not in result["reasons"]


def test_iframe_and_eval_signals_are_unchanged() -> None:
    result = detect_phishing('<iframe></iframe><script>eval(1)</script>')
    assert result == {
        "score": 25,
        "reasons": [
            "iframe detected",
            "Potentially dangerous JavaScript detected",
        ],
    }


def test_relative_password_action_is_not_external() -> None:
    result = detect_phishing(
        '<form action="/authenticate"><input type="password"></form>',
        page_url="https://example.com/login",
    )
    assert result["score"] == 20
    assert "Credential form submits to an external destination" not in result["reasons"]


def test_empty_password_action_is_not_external() -> None:
    result = detect_phishing(
        '<form><input type="password"></form>',
        page_url="https://example.com/login",
    )
    assert result["score"] == 20


def test_same_host_absolute_password_action_is_not_external() -> None:
    result = detect_phishing(
        '<form action="https://EXAMPLE.com/auth"><input type="password"></form>',
        page_url="https://example.com/login",
    )
    assert result["score"] == 20


def test_cross_host_password_action_adds_external_credential_signal() -> None:
    result = detect_phishing(
        '<form action="https://collector.invalid/collect"><input type="password"></form>',
        page_url="https://example.com/login",
    )
    assert result["score"] == 30
    assert result["reasons"] == [
        "Password input field detected",
        "Credential form submits to an external destination",
    ]


def test_cross_host_non_password_form_is_not_external_credential() -> None:
    result = detect_phishing(
        '<form action="https://newsletter.invalid/subscribe"><input type="email"></form>',
        page_url="https://example.com",
    )
    assert result == {"score": 0, "reasons": []}


def test_actual_iframe_triggers_structural_signal() -> None:
    result = detect_phishing('<iframe src="about:blank"></iframe>')
    assert result == {"score": 10, "reasons": ["iframe detected"]}


def test_hidden_actual_iframe_triggers_structural_signal() -> None:
    result = detect_phishing('<iframe hidden src="/placeholder"></iframe>')
    assert result == {"score": 10, "reasons": ["iframe detected"]}


def test_iframe_word_in_text_does_not_trigger() -> None:
    result = detect_phishing('<p>This tutorial explains iframe security.</p>')
    assert result == {"score": 0, "reasons": []}


def test_iframe_word_in_comment_does_not_trigger() -> None:
    result = detect_phishing('<!-- iframe example --><p>Text</p>')
    assert result == {"score": 0, "reasons": []}


def test_iframe_word_in_script_does_not_trigger() -> None:
    result = detect_phishing('<script>const iframeHelpText = "iframe";</script>')
    assert result == {"score": 0, "reasons": []}


def test_eval_in_visible_text_does_not_trigger() -> None:
    assert detect_phishing('<p>The JavaScript eval() function is dangerous.</p>') == {
        "score": 0,
        "reasons": [],
    }


def test_eval_in_comment_does_not_trigger() -> None:
    assert detect_phishing('<!-- eval( -->') == {"score": 0, "reasons": []}


def test_eval_in_code_block_does_not_trigger() -> None:
    assert detect_phishing('<pre>eval("example")</pre>') == {"score": 0, "reasons": []}


def test_eval_in_attribute_does_not_trigger() -> None:
    assert detect_phishing('<div data-help="eval("></div>') == {"score": 0, "reasons": []}


def test_eval_in_executable_script_triggers() -> None:
    result = detect_phishing('<script>eval("example");</script>')
    assert result == {
        "score": 15,
        "reasons": ["Potentially dangerous JavaScript detected"],
    }


def test_eval_with_whitespace_in_executable_script_triggers() -> None:
    result = detect_phishing('<script>eval ( "example" );</script>')
    assert result["score"] == 15


def test_unrelated_identifiers_do_not_trigger_eval_signal() -> None:
    html = '<script>my_eval(); evaluate(); preval();</script>'
    assert detect_phishing(html) == {"score": 0, "reasons": []}


def test_non_executable_json_script_does_not_trigger_eval_signal() -> None:
    html = '<script type="application/ld+json">{"example":"eval("}</script>'
    assert detect_phishing(html) == {"score": 0, "reasons": []}


def test_credential_phrase_without_password_does_not_trigger() -> None:
    html = '<p>Verify your account safely.</p><form><input type="email"></form>'
    result = detect_phishing(html)
    assert result["score"] == 5
    assert "Credential verification language detected" not in result["reasons"]
    assert "Suspicious keyword detected: verify your account" in result["reasons"]


def test_password_without_credential_phrase_remains_password_only() -> None:
    result = detect_phishing('<form><input type="password"></form>')
    assert result == {"score": 20, "reasons": ["Password input field detected"]}


def test_password_with_credential_phrase_adds_context_signal() -> None:
    result = detect_phishing(
        '<form><label>Verify your account</label><input type="password"></form>'
    )
    assert result["score"] == 35
    assert "Password input field detected" in result["reasons"]
    assert "Credential verification language detected" in result["reasons"]


def test_credential_phrase_matching_normalizes_case_and_whitespace() -> None:
    result = detect_phishing(
        '<form><p>  CONFIRM   YOUR   IDENTITY </p><input type="password"></form>'
    )
    assert result["score"] == 30
    assert "Credential verification language detected" in result["reasons"]


def test_external_credential_with_phrase_combines_signals() -> None:
    result = detect_phishing(
        '<form action="https://collector.invalid/collect">'
        '<p>Confirm your identity</p><input type="password"></form>',
        page_url="https://example.com/login",
    )
    assert result["score"] == 40
    assert result["reasons"] == [
        "Password input field detected",
        "Credential form submits to an external destination",
        "Credential verification language detected",
    ]


def test_distant_credential_phrase_does_not_trigger_form_context() -> None:
    html = '<p>Verify your account</p><form><input type="password"></form>'
    result = detect_phishing(html)
    assert result["score"] == 25
    assert "Password input field detected" in result["reasons"]
    assert "Credential verification language detected" not in result["reasons"]
