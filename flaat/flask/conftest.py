# Standard flask pytest fixture, see:
# https://flask.palletsprojects.com/en/2.1.x/testing/
# pylint: disable=redefined-outer-name
from examples.example_flask import create_app
from pytest_cases import fixture


@fixture(scope="session", params=["ProductionConfig"])
def configuration(request):
    return request.param


@fixture()
def app(configuration):
    app = create_app(configuration)
    app.config.update({"TESTING": True})
    # other setup can go here
    yield app
    # clean up / reset resources here


@fixture(scope="function")
def client(app):
    return app.test_client()


@fixture(scope="function")
def runner(app):
    return app.test_cli_runner()
