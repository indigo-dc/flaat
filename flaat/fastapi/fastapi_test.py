# pylint: disable=redefined-outer-name

import logging

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from flaat.fastapi import Flaat
from flaat.test_env import FLAAT_TRUSTED_OPS_LIST, User, get_status_kwargs_list

logger = logging.getLogger(__name__)

flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)

DECORATORS = User(flaat).get_named_decorators()


async def view_func(request: Request, test_inject=None):
    _ = request
    _ = test_inject
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


@pytest.mark.parametrize("status,kwargs", get_status_kwargs_list())
@pytest.mark.parametrize("decorator", DECORATORS)
def test_decorator(client, decorator, status, kwargs):
    resp = client.get(f"/{decorator.name}", **kwargs)
    expected = decorator.get_expected_status_code(status)
    assert resp.status_code == expected
