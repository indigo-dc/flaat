from pytest_cases import parametrize


class Authorized:
    """Request be valid pass."""

    @parametrize("path", ["/info", "/info_strict"])
    def case_ValidToken(self, path):
        raise NotImplementedError

    @parametrize("path", ["/info"])
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers


class Unauthorized:
    """Request should not pass."""

    @parametrize("path", ["/info_strict"])
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers

    @parametrize("path", ["/info", "/info_strict"])
    def case_NoBearer(self, path):
        headers = None
        return path, headers
