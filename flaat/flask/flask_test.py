# pylint: disable=redefined-outer-name
import pytest


@pytest.mark.parametrize("path", ["/info"])
class TestInjectUserInfos:
    """Test request combinations for example using `inject_user_infos`
    with parameter strict set to `False`.
    """

    @pytest.mark.parametrize("credentials", ["A", "B"])
    def test_is_authorized(self, client, path, headers):
        response = client.get(path, headers=headers)
        assert response.status_code == 200

    @pytest.mark.parametrize("credentials", [None])
    def test_not_authorized(self, client, path, headers):
        response = client.get(path, headers=headers)
        assert response.status_code == 401


@pytest.mark.parametrize("path", ["/info_strict"])
class TestStrictUserInfos:
    """Test request combinations for example using `inject_user_infos`
    with parameter strict set to `True`.
    """

    @pytest.mark.parametrize("credentials", ["A"])
    def test_is_authorized(self, client, path, headers):
        response = client.get(path, headers=headers)
        assert response.status_code == 200

    @pytest.mark.parametrize("credentials", ["B", None])
    def test_not_authorized(self, client, path, headers):
        response = client.get(path, headers=headers)
        assert response.status_code == 401
