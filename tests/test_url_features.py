import pytest

from sentinel.detect.ml.url_features import (
    FEATURE_NAMES,
    MAX_URL_CHARS,
    shannon_entropy,
    url_features,
)


def test_feature_vector_has_every_named_feature() -> None:
    feats = url_features("https://www.example.com/a/b?x=1")
    assert set(feats) == set(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in feats.values())


def test_suspicious_url_scores_higher_on_structure_than_plain_domain() -> None:
    phish = url_features(
        "http://secure-login.paypal.com.account-verify.example-192.biz/update?id=1&x=2"
    )
    plain = url_features("https://www.python.org")
    assert phish["num_subdomains"] > plain["num_subdomains"]
    assert phish["num_hyphens"] > plain["num_hyphens"]
    assert phish["has_https"] == 0.0 and plain["has_https"] == 1.0
    assert phish["num_qmark"] == 1.0 and phish["num_amp"] == 1.0


def test_ip_host_and_at_sign_and_port_are_detected() -> None:
    f = url_features("http://192.168.1.10:8080/login")
    assert f["is_ip_host"] == 1.0 and f["has_port"] == 1.0
    g = url_features("https://bank.example@evil.test/")
    assert g["has_at"] == 1.0


def test_malformed_urls_do_not_raise() -> None:
    f = url_features("http://[::1")
    assert f["invalid"] == 1.0
    assert url_features("")["url_len"] == 0.0


def test_input_is_length_capped_before_parsing() -> None:
    f = url_features("http://a.example/" + "x" * 50_000)
    assert f["url_len"] <= MAX_URL_CHARS


@pytest.mark.parametrize(
    ("text", "expected"),
    [("", 0.0), ("aaaa", 0.0), ("abcd", 2.0)],
)
def test_shannon_entropy(text: str, expected: float) -> None:
    assert shannon_entropy(text) == pytest.approx(expected)
