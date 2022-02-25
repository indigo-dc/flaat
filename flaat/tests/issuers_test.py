import pytest

from flaat.issuers import IssuerConfig, is_url
from flaat.test_env import FLAAT_AT, FLAAT_ISS, environment


class TestURLs:
    def test_url_1(self):
        assert is_url("http://heise.de")

    def test_valid_url_http(self):
        assert is_url("http://heise.de")

    def test_valid_url_https(self):
        assert is_url("http://heise.de")

    def test_valid_url_ftp(self):
        assert is_url("http://heise.de")

    def test_valid_url_https_path(self):
        assert is_url("https://heise.de/thi_s&is=difficult")

    def test_invalid_url(self):
        assert not is_url("htp://heise.de")


def test_token_introspection():
    client_id = environment.get("FLAAT_CLIENT_ID")
    client_secret = environment.get("FLAAT_CLIENT_SECRET")
    if client_id is None or client_secret is None:  # pragma: no cover
        pytest.skip("FLAAT_CLIENT_ID and FLAAT_CLIENT_SECRET are not set")

    issuer_config = IssuerConfig.get_from_string(FLAAT_ISS)
    assert issuer_config is not None
    issuer_config.client_id = client_id
    issuer_config.client_secret = client_secret
    introspection_info = issuer_config._get_introspected_token_info(FLAAT_AT)
    assert introspection_info is not None
