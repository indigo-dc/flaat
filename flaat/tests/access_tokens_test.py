import pytest

from flaat.access_tokens import get_access_token_info
from flaat.test_env import FLAAT_AT, NON_JWT_FLAAT_AT


class TestTokens:
    def test_get_accesstoken_info_non_jwt(self):
        access_token = NON_JWT_FLAAT_AT
        if access_token == "":
            pytest.skip("No non JWT access token")

        access_token_info = get_access_token_info(access_token)
        assert access_token_info is None

    def test_get_accesstoken_info_jwt(self):
        access_token = FLAAT_AT
        access_token_info = get_access_token_info(access_token)
        assert access_token_info is not None
        assert access_token_info.verification is not None
