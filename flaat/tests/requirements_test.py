# pylint: disable=redefined-outer-name

from typing import List
import pytest
from flaat import BaseFlaat
from flaat.exceptions import FlaatException
from flaat.test_env import (
    FLAAT_AT,
    FLAAT_CLAIM_GROUP,
    FLAAT_CLAIM_ENTITLEMENT,
    FLAAT_TRUSTED_OPS_LIST,
)
from flaat.user_infos import UserInfos
from flaat.requirements import Requirement, ValidLogin, HasAARCEntitlement, HasGroup


INVALID_ENTITLEMENT = "foo-bar"
VALID_ENTITLEMENT = "urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"
CLAIM = "eduperson_entitlement"


def test_invalid_aarc_entitlements():
    """two broken decorators which should fail at import time"""

    with pytest.raises(FlaatException):
        HasAARCEntitlement(
            required=INVALID_ENTITLEMENT,
            claim=CLAIM,
        )

    with pytest.raises(FlaatException):
        HasAARCEntitlement(
            required=[
                INVALID_ENTITLEMENT,
                VALID_ENTITLEMENT,
            ],
            claim=CLAIM,
        )


class Requirements:
    claim_groups: str
    claim_entitlements: str

    groups: List[str]
    entitlements: List[str]

    def __init__(self):
        self.flaat = BaseFlaat()
        self.flaat.set_trusted_OP_list(FLAAT_TRUSTED_OPS_LIST)
        self.at = FLAAT_AT
        self.user_infos = UserInfos(self.flaat, self.at)
        if self.user_infos.user_info is None:
            raise FlaatException(
                "Cannot run tests: could not fetch a userinfo with the access token"
            )

        self.claim_groups = FLAAT_CLAIM_GROUP
        self.claim_entitlements = FLAAT_CLAIM_ENTITLEMENT

        self.groups = self.user_infos.user_info.get(self.claim_groups, None)
        if not isinstance(self.groups, list) or len(self.groups) < 2:
            raise FlaatException(
                "CLAIM_GROUP must point to list of at least two groups"
            )

        self.entitlements = self.user_infos.user_info.get(self.claim_entitlements, None)
        if not isinstance(self.entitlements, list) or len(self.entitlements) < 2:
            raise FlaatException(
                "CLAIM_ENTITLEMENT must point to list of at least two entitlements"
            )

        self.requirements: List[Requirement] = [ValidLogin()]

        for match in [1, "all"]:
            self.requirements.append(
                HasGroup(self.groups, claim=self.claim_groups, match=match)
            )
            self.requirements.append(
                HasAARCEntitlement(
                    self.entitlements, claim=self.claim_entitlements, match=match
                )
            )


@pytest.fixture
def user_infos():
    return Requirements().user_infos


@pytest.fixture
def requirements():
    return Requirements().requirements


def test_possible_requirements_success(requirements, user_infos):
    """constructs (nearly) all options of using our decorators for testing them
    against the frameworks"""

    for req in requirements:
        assert req.satisfied_by(user_infos)
