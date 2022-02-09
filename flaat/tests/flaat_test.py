import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, FLAAT_ISS
from flaat.caches import user_infos_cache


def get_user_infos(flaat):
    user_infos_cache.clear()
    return flaat.get_user_infos_from_access_token(FLAAT_AT)


def test_success():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    info = flaat.get_user_infos_from_access_token(FLAAT_AT)
    assert info is not None


def test_untrusted():
    flaat = BaseFlaat()
    with pytest.raises(FlaatUnauthenticated):
        get_user_infos(flaat)


def test_invalid_at():
    flaat = BaseFlaat()
    assert flaat.get_user_infos_from_access_token("invalid_at") is None


def test_set_iss():
    flaat = BaseFlaat()

    # correct issuer
    flaat.set_issuer(FLAAT_ISS)
    info = get_user_infos(flaat)
    assert info is not None

    # setting invalid issuer
    flaat.set_issuer("https://another.issuer")
    with pytest.raises(FlaatException):
        get_user_infos(flaat)
