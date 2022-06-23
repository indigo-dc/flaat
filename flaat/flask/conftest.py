# Standard flask pytest fixture, see:
# https://flask.palletsprojects.com/en/2.1.x/testing/
# pylint: disable=redefined-outer-name
import functools

from flaat import issuers
from flaat.test_env import FLAAT_TRUSTED_OPS_LIST
from pytest_cases import fixture


@fixture(scope="session", params=["ProductionConfig"])
def configuration(request):
    return request.param


@fixture()
def app(configuration):
    from examples.example_flask import create_app

    app = create_app(configuration)
    app.config["TRUSTED_OP_LIST"] = FLAAT_TRUSTED_OPS_LIST
    app.config["TESTING"] = True
    # other setup can go here
    yield app
    # clean up / reset resources here


@fixture(scope="function")
def client(app):
    return app.test_client()


def replace_email(func):
    """Replaces the original email by a mock"""
    @ functools.wraps(func)
    def wrapper(*args, **kwargs):
        if user_info := func(*args, **kwargs):
            user_info['email'] = "dev@foo.org"
        return user_info

    return wrapper


def add_entitlements(func):
    """Replaces the original entitlements by a mock"""
    @ functools.wraps(func)
    def wrapper(*args, **kwargs):
        if user_info := func(*args, **kwargs):
            user_info['mock_entitlements'] = [
                "urn:mace:egi.eu:group:test:foo",
                "urn:mace:egi.eu:group:test:bar",
            ]
        return user_info

    return wrapper


issuers.IssuerConfig._get_user_info = replace_email(
    issuers.IssuerConfig._get_user_info)
issuers.IssuerConfig._get_user_info = add_entitlements(
    issuers.IssuerConfig._get_user_info)
