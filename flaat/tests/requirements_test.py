# pylint: disable=redefined-outer-name

from typing import List

import pytest

from flaat import BaseFlaat
from flaat.exceptions import FlaatException
from flaat.requirements import HasAARCEntitlement, HasGroup, Requirement, ValidLogin
from flaat.test_env import FLAAT_ISS, User

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


class RequirementsUser(User):
    def __init__(self):
        flaat = BaseFlaat()
        flaat.set_issuer(FLAAT_ISS)
        super().__init__(flaat)

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
def user():
    return RequirementsUser()


def test_possible_requirements_success(user):
    """constructs (nearly) all options of using our decorators for testing them
    against the frameworks"""

    for req in user.requirements:
        assert req.is_satisfied_by(user.user_infos)
