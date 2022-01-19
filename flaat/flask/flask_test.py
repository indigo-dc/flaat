# pylint: disable=redefined-outer-name,wildcard-import,unused-wildcard-import
from flask.app import Flask
import pytest
from werkzeug import Response

from flaat.flask import Flaat
from flaat.test_env import *


# TODO shouldn't we recreate the flaat instance for every test?
# especially thinking about caches etc.
flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)


@flaat.login_required()
def login_required():
    return Response(response="Success")


@flaat.group_required(
    group=FLAAT_GROUP,
    claim=FLAAT_CLAIM_GROUP,
    match="all",
)
def group_required():
    return Response(response="Success")


@flaat.aarc_g002_entitlement_required(
    entitlement=FLAAT_ENTITLEMENT,
    claim=FLAAT_CLAIM_ENTITLEMENT,
    match="all",
)
def aarc_g002_entitlement_required():
    return Response(response="Success")


@pytest.fixture
def app():
    """flask web app for testing"""
    app = Flask(__name__)
    app.route(PATH_LOGIN_REQUIRED)(login_required)
    app.route(PATH_GROUP_REQUIRED)(group_required)
    app.route(PATH_ENTITLEMENT_REQUIRED)(aarc_g002_entitlement_required)
    return app


@pytest.fixture
def client(app: Flask):
    return app.test_client()


@pytest.mark.parametrize("status,kwargs", STATUS_KWARGS_LIST)
@pytest.mark.parametrize("path", TEST_PATHS)
def test_decorator(client, path, status, kwargs):
    resp = client.get(path, **kwargs)
    assert resp.status_code == status
