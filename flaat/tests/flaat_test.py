import pytest
import os

from flaat import (
    ENV_VAR_AUTHN_OVERRIDE,
    ENV_VAR_AUTHZ_OVERRIDE,
    AuthWorkflow,
    BaseFlaat,
)
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.requirements import HasSubIss, get_claim_requirement
from flaat.test_env import FLAAT_AT, NON_JWT_FLAAT_AT, FLAAT_ISS, NON_JWT_FLAAT_ISS
from flaat.caches import user_infos_cache
from flaat.user_infos import UserInfos


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


def _mock_auth_user_none(*_, **__):
    return None


def _mock_auth_user_valid(*_, **__):
    return UserInfos(
        None,
        {"sub": "foo", "iss": "bar"},  # userinfo
        None,
    )


def test_env_override_authentication(monkeypatch):
    monkeypatch.setattr(BaseFlaat, "authenticate_user", _mock_auth_user_none)
    flaat = BaseFlaat()

    workflow = AuthWorkflow(flaat)

    @workflow.decorate_view_func
    def view_func():
        pass

    with pytest.raises(FlaatUnauthenticated):
        view_func()

    os.environ[ENV_VAR_AUTHN_OVERRIDE] = "YES"

    # no exception now
    view_func()

    del os.environ[ENV_VAR_AUTHN_OVERRIDE]


def test_env_override_authorization(monkeypatch):
    monkeypatch.setattr(BaseFlaat, "authenticate_user", _mock_auth_user_valid)
    flaat = BaseFlaat()

    workflow = AuthWorkflow(
        flaat,
        user_requirements=get_claim_requirement("claim-value", "claim-name"),
    )

    @workflow.decorate_view_func
    def view_func():
        pass

    with pytest.raises(FlaatForbidden):
        view_func()

    os.environ[ENV_VAR_AUTHZ_OVERRIDE] = "YES"

    # no exception now
    view_func()

    del os.environ[ENV_VAR_AUTHZ_OVERRIDE]


def test_env_override_authorization_without_user(monkeypatch):
    """overriding authorization, but having no authentication still should produce an error"""

    monkeypatch.setattr(BaseFlaat, "authenticate_user", _mock_auth_user_none)
    flaat = BaseFlaat()

    workflow = AuthWorkflow(
        flaat,
        user_requirements=get_claim_requirement("claim-value", "claim-name"),
    )

    @workflow.decorate_view_func
    def view_func():
        pass

    with pytest.raises(FlaatUnauthenticated):
        view_func()

    os.environ[ENV_VAR_AUTHZ_OVERRIDE] = "YES"

    with pytest.raises(FlaatUnauthenticated):
        view_func()

    del os.environ[ENV_VAR_AUTHZ_OVERRIDE]
