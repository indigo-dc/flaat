""" These tests are nothing AIO specific, but we can only test them with a framework.
We therefore picked AIO as an example.

FIXME The environment overrides in here are crude and will not work if run concurrently!
"""

import os
from typing import Optional

import pytest
from aiohttp import web

from flaat import ENV_VAR_AUTHN_OVERRIDE, ENV_VAR_AUTHZ_OVERRIDE, AuthWorkflow
from flaat.aio import Flaat
from flaat.aio.aio_test import flaat
from flaat.requirements import get_claim_requirement
from flaat.user_infos import UserInfos


@pytest.fixture
def app():
    """aio web Application for override testing"""

    workflow = AuthWorkflow(
        flaat,
        user_requirements=get_claim_requirement("claim-value", "claim-name"),
    )

    async def view_func(request, test_inject=None):
        _ = request
        _ = test_inject
        return web.Response(text="Success")

    _app = web.Application()
    _app.router.add_get("/", workflow.decorate_view_func(view_func))
    return _app


# from: https://docs.aiohttp.org/en/stable/testing.html#pytest-example
@pytest.fixture
def cli(event_loop, aiohttp_client, app):
    return event_loop.run_until_complete(aiohttp_client(app))


def _mock_auth_user(monkeypatch, user_infos: Optional[UserInfos]):
    def _mock_authenticate_user(*_, **__):
        return user_infos

    monkeypatch.setattr(Flaat, "authenticate_user", _mock_authenticate_user)


async def test_env_override_authentication(monkeypatch, cli):
    _mock_auth_user(monkeypatch, user_infos=None)

    resp = await cli.get("/")
    assert resp.status == 401  # no user

    os.environ[ENV_VAR_AUTHN_OVERRIDE] = "YES"

    resp = await cli.get("/")
    assert resp.status == 200  # no user, but authentication override

    del os.environ[ENV_VAR_AUTHN_OVERRIDE]


async def test_env_override_authorization(monkeypatch, cli):
    # this user does not meet the requirments from the workflow in this module
    forbidden_user = UserInfos(
        None,
        {"sub": "foo", "iss": "bar"},  # userinfo
        None,
    )
    _mock_auth_user(monkeypatch, user_infos=forbidden_user)

    resp = await cli.get("/")
    assert resp.status == 403  # user, but forbidden

    os.environ[ENV_VAR_AUTHN_OVERRIDE] = "YES"

    resp = await cli.get("/")
    assert resp.status == 200  # user, but authorization override

    del os.environ[ENV_VAR_AUTHN_OVERRIDE]


async def test_env_override_authorization_without_user(monkeypatch, cli):
    _mock_auth_user(monkeypatch, user_infos=None)

    resp = await cli.get("/")
    assert resp.status == 401  # no user, no override

    os.environ[ENV_VAR_AUTHZ_OVERRIDE] = "YES"

    resp = await cli.get("/")
    assert resp.status == 401  # no user, only authorization override

    del os.environ[ENV_VAR_AUTHZ_OVERRIDE]
