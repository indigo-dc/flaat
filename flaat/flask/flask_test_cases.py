from pytest_cases import parametrize

paths = {
    "/info",
    "/info_no_strict",
    "/authenticated",
    "/authenticated_callback",
}


class Authorized:
    """Request should pass."""

    @parametrize("path", paths)
    def case_ValidToken(self, path, oidc_token):
        headers = {"Authorization": f"Bearer {oidc_token}"}
        return path, headers

    @parametrize("path", {"/info_no_strict"})
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers


class Unauthorized:
    """Request should not pass."""

    @parametrize("path", paths - {"/info_no_strict"})
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers

    @parametrize("path", paths)
    def case_NoBearer(self, path):
        headers = None
        return path, headers
