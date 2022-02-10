import logging
import os
from typing import Callable, List, Optional

from attr import dataclass
from dotenv import dotenv_values
import liboidcagent

from flaat import BaseFlaat
from flaat.exceptions import FlaatException
from flaat.requirements import HasClaim, get_claim_requirement, get_vo_requirement

logger = logging.getLogger(__name__)

environment = {
    **dotenv_values(".env"),
    **os.environ,
}


def _mandatory_env_var(name):
    val = environment.get(name, "")
    if val == "":  # pragma: no cover
        raise ValueError(f"Set '{name}' in environment or .env file")

    return val


OIDC_AGENT_ACCOUNT = _mandatory_env_var("OIDC_AGENT_ACCOUNT")

FLAAT_AT = ""
try:
    FLAAT_AT = liboidcagent.get_access_token(OIDC_AGENT_ACCOUNT)
except liboidcagent.OidcAgentError as e:  # pragma: no cover
    raise FlaatException(
        f"Error acquiring access token for oidc agent account '{OIDC_AGENT_ACCOUNT}': {e}"
    ) from e

FLAAT_CLAIM_ENTITLEMENT = _mandatory_env_var("FLAAT_CLAIM_ENTITLEMENT")
FLAAT_CLAIM_GROUP = _mandatory_env_var("FLAAT_CLAIM_GROUP")
FLAAT_ISS = _mandatory_env_var("FLAAT_ISS")
FLAAT_TRUSTED_OPS_LIST = [FLAAT_ISS]

STATUS_KWARGS_LIST = [
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


class User:
    claim_groups: str
    claim_entitlements: str

    groups: List[str]
    entitlements: List[str]

    decorators: List[NamedDecorator]

    def __init__(self, flaat):
        self.flaat: BaseFlaat = flaat
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
                "CLAIM_GROUP must point to list of at least two groups"
            )

        self.entitlements = self.user_infos.user_info.get(self.claim_entitlements, None)
        if (
            not isinstance(self.entitlements, list) or len(self.entitlements) < 2
        ):  # pragma: no cover
            raise FlaatException(
                "CLAIM_ENTITLEMENT must point to list of at least two entitlements"
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
        ]
        return decorators
