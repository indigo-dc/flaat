import logging
import os
from typing import Callable, List, Optional

import liboidcagent
from attr import dataclass
from dotenv import dotenv_values

from flaat import AuthWorkflow, BaseFlaat
from flaat.exceptions import FlaatException
from flaat.requirements import (
    CheckResult,
    HasClaim,
    get_claim_requirement,
    get_vo_requirement,
)
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

environment = {
    **dotenv_values(".env"),
    **os.environ,
}


def env_var(name, mandatory=True):
    val = environment.get(name, "")
    if mandatory and val == "":  # pragma: no cover
        return ""
        # raise ValueError(f"Set '{name}' in environment or .env file")

    return val


def load_at(short_name: str, mandatory=False, min_valid_period=0, audience=None) -> str:
    try:
        return liboidcagent.get_access_token(
            short_name, min_valid_period=min_valid_period, audience=audience
        )
    except liboidcagent.OidcAgentError as e:  # pragma: no cover
        if mandatory:
            raise FlaatException(
                f"Error acquiring access token for oidc agent account '{short_name}': {e}"
            ) from e
        return ""


OIDC_AGENT_ACCOUNT = env_var("OIDC_AGENT_ACCOUNT")
FLAAT_AT = load_at(OIDC_AGENT_ACCOUNT)

FLAAT_CLAIM_ENTITLEMENT = env_var("FLAAT_CLAIM_ENTITLEMENT")
FLAAT_CLAIM_GROUP = env_var("FLAAT_CLAIM_GROUP")
FLAAT_ISS = env_var("FLAAT_ISS")
FLAAT_TRUSTED_OPS_LIST = [
    FLAAT_ISS,
    "https://accounts.google.com/",  # including google here, because it does not support JWTs
]
FLAAT_CLIENT_ID = environment.get("FLAAT_CLIENT_ID", "")
FLAAT_CLIENT_SECRET = environment.get("FLAAT_CLIENT_SECRET", "")

# optional access token, that is not a JWT
NON_JWT_OIDC_AGENT_ACCOUNT = env_var("NON_JWT_OIDC_AGENT_ACCOUNT", mandatory=False)
NON_JWT_FLAAT_AT = load_at(NON_JWT_OIDC_AGENT_ACCOUNT, mandatory=False)
NON_JWT_FLAAT_ISS = env_var("NON_JWT_FLAAT_ISS", mandatory=False)

# optional oidc agent account from OP that supports setting 'aud' claim
AUD_OIDC_AGENT_ACCOUNT = env_var("AUD_OIDC_AGENT_ACCOUNT", mandatory=False)
AUD_FLAAT_ISS = env_var("AUD_FLAAT_ISS", mandatory=False)


# List to parametrize framework tests
def get_status_kwargs_list():
    return [
        # No access token -> unauthorized
        (401, {"headers": {}}),
        # Invalid access token -> unauthorized
        (401, {"headers": {"Authorization": "Bearer invalid_at"}}),
        # Good access token with the right entitlements
        # If the decorator has a status_code then that one overrides the 200 set here
        # see get_expected_status_code
        (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}}),
    ]


@dataclass
class NamedDecorator:
    name: str
    decorator: Callable
    status_code: Optional[int] = None  # expected status of this decorator

    def get_expected_status_code(self, status_code: int):
        expected = status_code
        if status_code == 200 and self.status_code is not None:
            expected = self.status_code
        return expected


def check_request(user_infos: UserInfos, *args, **kwargs) -> CheckResult:
    _ = user_infos
    _ = args
    _ = kwargs
    return CheckResult(True, "No checks applied")


class User:
    claim_groups: str
    claim_entitlements: str

    groups: List[str]
    entitlements: List[str]

    decorators: List[NamedDecorator]

    def __init__(self, flaat):
        self.flaat: BaseFlaat = flaat
        self.flaat.set_client_id(FLAAT_CLIENT_ID)
        self.flaat.set_client_secret(FLAAT_CLIENT_SECRET)
        self.at = FLAAT_AT
        logger.debug("Fetching user infos for test_env")
        self.user_infos = self.flaat.get_user_infos_from_access_token(self.at)
        if (
            self.user_infos is None or self.user_infos.user_info is None
        ):  # pragma: no cover
            raise FlaatException(
                "Cannot run tests: could not fetch a userinfo with the access token"
            )

        self.claim_groups = FLAAT_CLAIM_GROUP
        self.claim_entitlements = FLAAT_CLAIM_ENTITLEMENT

        self.groups = self.user_infos.user_info.get(self.claim_groups, None)
        if (
            not isinstance(self.groups, list) or len(self.groups) < 2
        ):  # pragma: no cover
            raise FlaatException(
                "FLAAT_CLAIM_GROUP must point to list of at least two groups"
            )

        self.entitlements = self.user_infos.user_info.get(self.claim_entitlements, None)
        if (
            not isinstance(self.entitlements, list) or len(self.entitlements) < 2
        ):  # pragma: no cover
            raise FlaatException(
                "FLAAT_CLAIM_ENTITLEMENT must point to list of at least two entitlements"
            )

    def get_named_decorators(self):
        """construct  decorators for testing"""

        def on_failure(exc, _):
            logger.info("TEST on_failure called")
            raise exc

        decorators = [
            NamedDecorator(
                "inject_user_infos", self.flaat.inject_user_infos(key="test_inject")
            ),
            NamedDecorator(
                "access_level_IDENTIFIED", self.flaat.access_level("IDENTIFIED")
            ),
            NamedDecorator(
                "access_level_IDENTIFIED-on_failure",
                self.flaat.access_level("IDENTIFIED", on_failure=on_failure),
            ),  # with on_failure
            NamedDecorator(
                "requires-GroupAndEntitlement",
                self.flaat.requires(
                    [
                        get_claim_requirement(self.groups, self.claim_groups),
                        get_vo_requirement(self.entitlements, self.claim_entitlements),
                    ],
                ),
            ),  # multiple reqs
            NamedDecorator(
                "requires-forbidden",
                self.flaat.requires(
                    HasClaim("group_that_does_not_exist", self.claim_groups),
                ),
                status_code=403,
            ),  # this must cause forbidden
            NamedDecorator(
                "workflow_all",
                AuthWorkflow(
                    self.flaat,
                    request_requirements=check_request,
                ).decorate_view_func,
            ),
        ]
        return decorators
