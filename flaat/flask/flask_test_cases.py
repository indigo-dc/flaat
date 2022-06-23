from pytest_cases import parametrize
from flaat.test_env import FLAAT_AT


example_paths = {
    "/info",
    "/info_no_strict",
    "/authenticated",
    "/authenticated_callback",
    "/authorized_claim",
    "/authorized_vo",
}


class Authorized:
    """Request should pass."""

    @parametrize("path", example_paths)
    def case_ValidToken(self, path):
        headers = {"Authorization": f"Bearer {FLAAT_AT}"}
        return path, headers

    @parametrize("path", {"/info_no_strict"})
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers


class Unauthorized:
    """Request should not pass."""

    @parametrize("path", example_paths - {"/info_no_strict"})
    def case_FakeToken(self, path):
        headers = {"Authorization": f"Bearer fake_token"}
        return path, headers

    @parametrize("path", example_paths)
    def case_NoBearer(self, path):
        headers = None
        return path, headers
