import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, FLAAT_ISS
from flaat.user_infos import UserInfos


class TestUserInfos:
    def test_success(self):
        flaat = BaseFlaat()
        flaat.set_trusted_OP_list([FLAAT_ISS])
        info = UserInfos(flaat, FLAAT_AT)
        assert info is not None

    def test_untrusted(self):
        flaat = BaseFlaat()
        with pytest.raises(FlaatUnauthenticated):
            UserInfos(flaat, FLAAT_AT)

    def test_invalid_at(self):
        flaat = BaseFlaat()
        with pytest.raises(FlaatUnauthenticated):
            UserInfos(flaat, "invalid-at")
