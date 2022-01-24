import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, FLAAT_ISS
from flaat.user_infos import UserInfos

INVALID_ENTITLEMENT = "foo-bar"
VALID_ENTITLEMENT = "urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"
CLAIM = "eduperson_entitlement"


def test_invalid_aarc_entitlements():
    """two broken decorators which should fail at import time"""

    flaat = BaseFlaat()
    with pytest.raises(FlaatException):
        flaat.aarc_entitlement_required(
            entitlement=INVALID_ENTITLEMENT,
            claim=CLAIM,
        )

    with pytest.raises(FlaatException):
        flaat.aarc_entitlement_required(
            entitlement=[
                INVALID_ENTITLEMENT,
                VALID_ENTITLEMENT,
            ],
            claim=CLAIM,
        )


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
