import pytest
from aiohttp import web

from flaat.aio import Flaat
from flaat.test_env import *

flaat = Flaat()
flaat.set_trusted_OP_list(
    [
        FLAAT_ISS,
    ]
)


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
    app.router.add_get("/entitlement_required", aarc_g002_entitlement_required)
    app.router.add_get("/login_required", login_required)
    app.router.add_get("/group_required", group_required)
    return app


@pytest.fixture
async def client(app, aiohttp_client):
    """aio test client for testing"""
    return await aiohttp_client(app)


@pytest.mark.parametrize(
    "status,kwargs",
    [(401, {}), (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}})],
)
@pytest.mark.parametrize(
    "path",
    # these paths correspond to the paths from the app fixture
    [
        "/login_required",
        "/group_required",
        "/entitlement_required",
    ],
)
async def test_decorator(client, path, status, kwargs):
    resp = await client.get(path, **kwargs)
    assert resp.status == status
