# pylint: disable=redefined-outer-name,wildcard-import
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest

from flaat.fastapi import Flaat
from flaat.test_env import *

flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)


@flaat.login_required()
def login_required(request: Request):
    _ = request
    return {"message": "Success"}


@flaat.group_required(
    group=FLAAT_GROUP,
    claim=FLAAT_CLAIM_GROUP,
    match="all",
)
def group_required(request: Request):
    return {"message": "Success"}


@flaat.aarc_g002_entitlement_required(
    entitlement=FLAAT_ENTITLEMENT,
    claim=FLAAT_CLAIM_ENTITLEMENT,
    match="all",
)
def aarc_g002_entitlement_required(request: Request):
    return {"message": "Success"}


@pytest.fixture
def app():
    """fastapi app testing fixture"""
    app = FastAPI()
    # security = HTTPBearer()
    # deps = [Depends(security)]
    deps = []
    app.get(PATH_LOGIN_REQUIRED, dependencies=deps)(login_required)
    app.get(PATH_GROUP_REQUIRED, dependencies=deps)(group_required)
    app.get(PATH_ENTITLEMENT_REQUIRED, dependencies=deps)(
        aarc_g002_entitlement_required
    )
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.parametrize(
    "status,kwargs",
    [(401, {}), (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}})],
)
@pytest.mark.parametrize("path", TEST_PATHS)
def test_decorator(client, path, status, kwargs):
    resp = client.get(path, **kwargs)
    assert resp.status_code == status
