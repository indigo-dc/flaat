# pylint: disable=redefined-outer-name,wildcard-import
import pytest
from aiohttp import web

from flaat.aio import Flaat
from flaat.test_env import *

flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)


@flaat.login_required()
async def login_required(_):
    return web.Response(text="Success")


@flaat.group_required(
    group=FLAAT_GROUP,
    claim=FLAAT_CLAIM_GROUP,
    match="all",
)
async def group_required(_):
    return web.Response(text="Success")


@flaat.aarc_g002_entitlement_required(
    entitlement=FLAAT_ENTITLEMENT,
    claim=FLAAT_CLAIM_ENTITLEMENT,
    match="all",
)
async def aarc_g002_entitlement_required(_):
    return web.Response(text="Success")


@pytest.fixture
def app():
    """aio web Application for testing"""
    app = web.Application()
    app.router.add_get(PATH_LOGIN_REQUIRED, login_required)
    app.router.add_get(PATH_GROUP_REQUIRED, group_required)
    app.router.add_get(PATH_ENTITLEMENT_REQUIRED, aarc_g002_entitlement_required)
    return app


# from: https://docs.aiohttp.org/en/stable/testing.html#pytest-example
@pytest.fixture
def cli(loop, aiohttp_client, app):
    return loop.run_until_complete(aiohttp_client(app))


@pytest.mark.parametrize(
    "status,kwargs",
    [(401, {}), (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}})],
)
@pytest.mark.parametrize("path", TEST_PATHS)
async def test_decorator(cli, path, status, kwargs):
    resp = await cli.get(path, **kwargs)
    assert resp.status == status
