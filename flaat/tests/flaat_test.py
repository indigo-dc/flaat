import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, NON_JWT_FLAAT_AT, FLAAT_ISS, NON_JWT_FLAAT_ISS
from flaat.caches import user_infos_cache


def get_user_infos(flaat):
    user_infos_cache.clear()
    return flaat.get_user_infos_from_access_token(FLAAT_AT)


def test_success():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    info = flaat.get_user_infos_from_access_token(FLAAT_AT)
    assert info is not None


def test_issuer_hint_success():
    flaat = BaseFlaat()
    info = flaat.get_user_infos_from_access_token(FLAAT_AT, issuer_hint=FLAAT_ISS)
    assert info is not None


def test_issuer_hint_fail():
    flaat = BaseFlaat()
    with pytest.raises(FlaatException):
        flaat.get_user_infos_from_access_token(
            FLAAT_AT, issuer_hint="https://invalid.issuer.org"
        )


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


def test_non_jwt_at():
    if NON_JWT_FLAAT_AT == "":  # pragma: no cover
        pytest.skip(
            "No non JWT access token (Set NON_JWT_OIDC_AGENT_ACCOUNT to correct shortname)"
        )
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([NON_JWT_FLAAT_ISS])
    info = flaat.get_user_infos_from_access_token(NON_JWT_FLAAT_AT)
    assert info is not None

    # to test the access_token_issuer_cache we have to bypass the user_infos_cache
    user_infos_cache.clear()

    # this should cause a cache hit in the access_token_issuer_cache
    info = flaat.get_user_infos_from_access_token(NON_JWT_FLAAT_AT)
    assert info is not None
