# pylint: disable=redefined-outer-name
from flask.app import Flask
import pytest
from werkzeug import Response

from flaat.flask import Flaat
from flaat.test_env import User, FLAAT_TRUSTED_OPS_LIST, STATUS_KWARGS_LIST


flaat = Flaat()
flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)

DECORATORS = User(flaat).get_named_decorators()


def view_func(test_inject=None):
    _ = test_inject
    return Response(response="Success")


@pytest.fixture
def app():
    """flask web app for testing"""
    app = Flask(__name__)
    for decorator in DECORATORS:

        decorated_view_func = decorator.decorator(view_func)
        # rename to decorator name, as flask does not allow duplicate view_func names
        decorated_view_func.__name__ = f"{decorator.name}-view_func"

        app.route(f"/{decorator.name}")(decorated_view_func)

    return app


@pytest.fixture
def client(app: Flask):
    return app.test_client()


@pytest.mark.parametrize("status,kwargs", STATUS_KWARGS_LIST)
@pytest.mark.parametrize("decorator", DECORATORS)
def test_decorator(client, decorator, status, kwargs):
    resp = client.get(f"/{decorator.name}", **kwargs)
    expected = decorator.get_expected_status_code(status)
    assert resp.status_code == expected
