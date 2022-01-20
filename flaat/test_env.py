import os
from typing import Callable, List, Tuple

from attr import dataclass

from flaat.exceptions import FlaatException
from flaat.user_infos import UserInfos


def _mandatory_env_var(name):
    env_var = f"FLAAT_{name}"
    val = os.environ.get(env_var, "")
    if val == "":
        raise ValueError(f"Environment variable is empty: {env_var}")

    return val


FLAAT_AT = _mandatory_env_var("AT")
FLAAT_CLAIM_ENTITLEMENT = _mandatory_env_var("CLAIM_ENTITLEMENT")
FLAAT_CLAIM_GROUP = _mandatory_env_var("CLAIM_GROUP")
FLAAT_ISS = _mandatory_env_var("ISS")
FLAAT_TRUSTED_OPS_LIST = [FLAAT_ISS]

STATUS_KWARGS_LIST = [
    # no token -> unauthorized
    (401, {}),
    # invalid access token -> unauthorized
    (
        401,
        {"headers": {"Authorization": "Bearer invalid_at"}},
    ),
    # good access token with the right entitlements
    (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}}),
]


def on_failure(e):
    pass


@dataclass
class NamedDecorator:
    name: str
    decorator: Callable

    def __str__(self):
        return self.name


class Decorators:
    claim_groups: str
    claim_entitlements: str

    groups: List[str]
    entitlements: List[str]

    decorators: List[NamedDecorator]

    def __init__(self, flaat):
        self.flaat = flaat
        self.at = FLAAT_AT
        user_info = UserInfos(self.flaat, self.at)
        if user_info.user_info is None:
            raise FlaatException(
                "Cannot run tests: could not fetch a userinfo with the access token"
            )

        self.claim_groups = FLAAT_CLAIM_GROUP
        self.claim_entitlements = FLAAT_CLAIM_ENTITLEMENT

        self.groups = user_info.user_info.get(self.claim_groups, None)
        if not isinstance(self.groups, list) or len(self.groups) < 2:
            raise FlaatException(
                "CLAIM_GROUP must point to list of at least two groups"
            )

        self.entitlements = user_info.user_info.get(self.claim_entitlements, None)
        if not isinstance(self.entitlements, list) or len(self.entitlements) < 2:
            raise FlaatException(
                "CLAIM_ENTITLEMENT must point to list of at least two entitlements"
            )

    def get_named_decorators(self):
        """constructs (nearly) all options of using our decorators for testing them
        against the frameworks"""
        decorators = [
            NamedDecorator("inject_user_infos", self.flaat.inject_user_infos),
            NamedDecorator("login_required-none", self.flaat.login_required()),
            NamedDecorator(
                "login_required-on_failure",
                self.flaat.login_required(on_failure=on_failure),
            ),
        ]

        for match in [1, "all"]:
            decorators.append(
                NamedDecorator(
                    f"group_required-match={match}",
                    self.flaat.group_required(
                        group=self.groups,
                        claim=self.claim_groups,
                        match=match,
                    ),
                )
            )
            decorators.append(
                NamedDecorator(
                    f"aarc_entitlement_required-match={match}",
                    self.flaat.aarc_entitlement_required(
                        entitlement=self.entitlements,
                        claim=self.claim_entitlements,
                        match=match,
                    ),
                )
            )

        return decorators
