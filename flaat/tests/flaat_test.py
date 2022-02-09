import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, FLAAT_ISS


def test_success():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    info = flaat.get_user_infos_from_access_token(FLAAT_AT)
    assert info is not None


def test_untrusted():
    flaat = BaseFlaat()
    with pytest.raises(FlaatUnauthenticated):
        flaat.get_user_infos_from_access_token(FLAAT_AT)


def test_invalid_at():
    flaat = BaseFlaat()
    with pytest.raises(FlaatUnauthenticated):
        flaat.get_user_infos_from_access_token(FLAAT_AT)


def test_set_iss():
    flaat = BaseFlaat()

    # correct issuer
    flaat.set_issuer(FLAAT_ISS)
    info = flaat.get_user_infos_from_access_token(FLAAT_AT)
    assert info is not None

    # setting invalid issuer
    flaat.set_issuer("https://another.issuer")
    with pytest.raises(FlaatException):
        flaat.get_user_infos_from_access_token(FLAAT_AT)
