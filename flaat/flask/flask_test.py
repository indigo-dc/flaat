# pylint: disable=redefined-outer-name
import pytest


@pytest.mark.parametrize("path", ["/info"])
class TestInjectUserInfos:
    """Tests for example endpoint 'info'."""

    @pytest.fixture
    def response(self, client, path, headers):
        return client.get(path, headers=headers)

    @pytest.mark.parametrize("credentials", ["mytoken"])
    def test_AUTHORIZED(self, response):
        assert response.status_code == 200
        assert b"No userinfo" in response.data

    @pytest.mark.parametrize("credentials", [None])
    def test_UNAUTHORIZED(self, response):
        assert response.status_code == 200
        assert b"No userinfo" in response.data


@pytest.mark.parametrize("path", ["/info_strict"])
class TestInjectUserInfoStrict:
    """Tests for example endpoint 'info_strict'."""

    @pytest.fixture
    def response(self, client, path, headers):
        return client.get(path, headers=headers)

    @pytest.mark.parametrize("credentials", ["mytoken"])
    def test_AUTHORIZED(self, response):
        assert response.status_code == 200
        assert b"No userinfo" in response.data

    @pytest.mark.parametrize("credentials", [None])
    def test_UNAUTHORIZED(self, response):
        assert response.status_code == 401
        assert b"No authorization header" in response.data
        assert b"Unauthenticated" in response.data
