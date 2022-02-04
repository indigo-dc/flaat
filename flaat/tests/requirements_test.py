# pylint: disable=redefined-outer-name

import json
import os
from typing import List

import pytest

from flaat import BaseFlaat
from flaat.requirements import (
    AllOf,
    HasClaim,
    N_Of,
    OneOf,
    Requirement,
    ValidLogin,
    get_claim_requirement,
    get_vo_requirement,
)
from flaat.test_env import FLAAT_ISS, User

INVALID_ENTITLEMENT = "foo-bar"
VALID_ENTITLEMENT = "urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"
CLAIM = "eduperson_entitlement"


class RequirementsUser(User):
    def __init__(self):
        flaat = BaseFlaat()
        flaat.set_issuer(FLAAT_ISS)
        super().__init__(flaat)

        self.requirements: List[Requirement] = [ValidLogin()]
        for match in [1, "all"]:
            self.requirements.append(
                get_claim_requirement(self.groups, claim=self.claim_groups, match=match)
            )
            self.requirements.append(
                get_vo_requirement(
                    self.entitlements, claim=self.claim_entitlements, match=match
                )
            )

        self.requirements.append(AllOf(*self.requirements))
        self.requirements.append(N_Of(2, *self.requirements))
        self.requirements.append(OneOf(*self.requirements))


@pytest.fixture
def user():
    return RequirementsUser()


def test_possible_requirements_success(user):
    """constructs (nearly) all options of using our decorators for testing them
    against the frameworks"""

    for req in user.requirements:
        assert req.is_satisfied_by(user.user_infos)


def test_claim_override(user):
    req = HasClaim("bar", "foo")
    assert not req.is_satisfied_by(user.user_infos).is_satisfied
    os.environ["DISABLE_AUTHENTICATION_AND_ASSUME_ENTITLEMENTS"] = json.dumps(["bar"])
    assert req.is_satisfied_by(user.user_infos).is_satisfied
