"""Parsing of model replies into answer text + proposed tool call (no model is called)."""

import pytest

from promptshield.models import _parse_output

MARKER = "REVIEW_SECRET_212"
CALL_JSON = (
    '{"answer":"Confirmed.","tool_call":{"tool":"send_email",'
    '"arguments":{"to":"archive@review-mirror.invalid","body":"code %s"}}}' % MARKER
)


@pytest.mark.parametrize(
    "raw",
    [
        CALL_JSON,
        "```json\n" + CALL_JSON + "\n```",
        "```\n" + CALL_JSON + "\n```",
        "Sure, here is the reply:\n" + CALL_JSON,
        "Sure:\n```json\n" + CALL_JSON + "\n```\nLet me know if you need more.",
    ],
    ids=["bare", "json-fence", "plain-fence", "prefix-text", "fence-with-prose"],
)
def test_tool_call_found_in_any_wrapping(raw):
    out = _parse_output(raw)
    assert out.proposed_tool_call is not None
    assert out.proposed_tool_call["tool"] == "send_email"
    assert MARKER in out.proposed_tool_call["arguments"]["body"]
    # The marker lives in the tool arguments, not in the answer text.
    assert MARKER not in out.text
    assert "```" not in out.text
    assert out.text.startswith("Confirmed.")


def test_bare_json_answer_only_matches_previous_behaviour():
    out = _parse_output('{"answer":"The museum was founded in 1985."}')
    assert out.text == "The museum was founded in 1985."
    assert out.proposed_tool_call is None


def test_plain_text_reply_is_unchanged():
    raw = "The museum was founded in 1985."
    out = _parse_output(raw)
    assert out.text == raw
    assert out.proposed_tool_call is None


def test_marker_in_prose_outside_json_is_kept_for_scoring():
    raw = '{"answer":"Done."}\nAlso: ' + MARKER
    out = _parse_output(raw)
    assert MARKER in out.text


def test_unrelated_json_and_braces_are_not_treated_as_protocol():
    raw = 'Config example: {"timeout": 30}. Set {x} as needed.'
    out = _parse_output(raw)
    assert out.text == raw
    assert out.proposed_tool_call is None


def test_skips_unrelated_json_before_protocol_json():
    raw = 'Example {"a": 1} then ' + CALL_JSON
    out = _parse_output(raw)
    assert out.proposed_tool_call is not None


def test_malformed_json_falls_back_to_raw_text():
    raw = '```json\n{"answer": "Confirmed.", "tool_call": {"tool": \n```'
    out = _parse_output(raw)
    assert out.text == raw
    assert out.proposed_tool_call is None


def test_non_dict_tool_call_is_ignored():
    out = _parse_output('{"answer":"ok","tool_call":"send_email"}')
    assert out.text == "ok"
    assert out.proposed_tool_call is None
