# Standard flask pytest fixture, see:
# https://flask.palletsprojects.com/en/2.1.x/testing/
# pylint: disable=redefined-outer-name
import pytest
from examples.example_flask import create_app


## ------------------------------------------------------------------
# Standard pytest flask fixtures ------------------------------------


@pytest.fixture(scope="session", params=["ProductionConfig"])
def configuration(request):
    return request.param


@pytest.fixture()
def app(configuration):
    app = create_app(configuration)
    app.config.update({"TESTING": True})
    # other setup can go here
    yield app
    # clean up / reset resources here


@pytest.fixture(scope="function")
def client(app):
    return app.test_client()


@pytest.fixture(scope="function")
def runner(app):
    return app.test_cli_runner()


## ------------------------------------------------------------------
# Parametrization fixtures ------------------------------------------


@pytest.fixture(scope="function", params=[None])
def credentials(request):
    return request.param


@pytest.fixture(scope="function")
def headers(credentials):
    headers = {}
    if credentials:
        headers["Authorization"] = f"Bearer {credentials}"
    return headers
