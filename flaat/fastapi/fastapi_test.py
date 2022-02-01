# pylint: disable=redefined-outer-name,wildcard-import,unused-wildcard-import

import logging
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest

from flaat.fastapi import Flaat
from flaat.test_env import *

logger = logging.getLogger(__name__)

flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)

DECORATORS = Decorators(flaat).get_named_decorators()


async def view_func(request: Request, user_infos=None, user=None):
    _ = request
    _ = user
    return {"message": "Success"}


@pytest.fixture
def app():
    """fastapi app testing fixture"""
    app = FastAPI()
    for decorator in DECORATORS:
        app.get(f"/{decorator.name}")(decorator.decorator(view_func))
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.parametrize("status,kwargs", STATUS_KWARGS_LIST)
@pytest.mark.parametrize("decorator", DECORATORS)
def test_decorator(client, decorator, status, kwargs):
    resp = client.get(f"/{decorator.name}", **kwargs)
    logger.debug("Response: %s %s", resp.status_code, resp.text)
    assert resp.status_code == status
