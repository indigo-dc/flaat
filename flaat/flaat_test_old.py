import logging

import pytest

from flaat import aio, fastapi, flask

logger = logging.getLogger(__name__)


# the names are included here, because pytest only calls the classes Flaat0, Flaat1 ..., which is not very helpful
FRAMEWORKS = [
    ("aio", aio.Flaat),
    ("flask", flask.Flaat),
    ("fastapi", fastapi.Flaat),
]


def on_failure_raise(e):
    raise e


@pytest.mark.parametrize(
    "on_failure",
    [None, on_failure_raise],
)
@pytest.mark.parametrize("name,framework", FRAMEWORKS)
class TestFlaatDecorators:
    def test_login_required(self, name, framework, on_failure):
        logger.debug("starting test")

        f = framework()

        decorator = getattr(f, "login_required")(on_failure=on_failure)

        @decorator
        def view_func():
            return "foo"

        assert "foo" == view_func()

    @pytest.mark.parametrize(
        "group",
        ["single_group", ["group_one", "group_two"]],
    )
    def test_group_required(self, name, framework, on_failure, group):
        logger.debug("starting test")

        f = framework()
        decorator = f.group_required(group, claim="group", on_failure=on_failure)

        @decorator
        def view_func():
            return "foo"

        assert "foo" == view_func()

    @pytest.mark.parametrize(
        "entitlement",
        [
            "urn:mace:egi.eu:group:admins",
            ["urn:mace:egi.eu:group:admins", "urn:mace:egi.eu:group:super-admins"],
        ],
    )
    def test_aarc_ent_required(self, name, framework, on_failure, entitlement):
        logger.debug("starting test")

        f = framework()
        claim = "eduperson_entitlement"
        decorator = f.aarc_g002_entitlement_required(
            entitlement, claim, on_failure=on_failure
        )

        @decorator
        def view_func():
            return "foo"

        assert "foo" == view_func()
