# pylint: disable=redefined-outer-name

import json
import os
from typing import List

import pytest

from flaat import BaseFlaat
from flaat.requirements import (
    AllOf,
    HasClaim,
    HasSubIss,
    IsTrue,
    N_Of,
    OneOf,
    Requirement,
    Satisfied,
    Unsatisfiable,
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

        self.success_requirements: List[Requirement] = [
            HasSubIss(),
            Satisfied(),
            IsTrue(lambda _: True),
        ]
        for match in [1, "all"]:
            self.success_requirements.append(
                get_claim_requirement(self.groups, claim=self.claim_groups, match=match)
            )
            self.success_requirements.append(
                get_vo_requirement(
                    self.entitlements, claim=self.claim_entitlements, match=match
                )
            )

        self.success_requirements.append(AllOf(*self.success_requirements))
        self.success_requirements.append(N_Of(2, *self.success_requirements))
        self.success_requirements.append(OneOf(*self.success_requirements))

        self.failure_requirements = [Unsatisfiable()]


@pytest.fixture
def user():
    return RequirementsUser()


def test_possible_requirements_success(user):
    """constructs (nearly) all options of using our decorators for testing them
    against the frameworks"""

    for req in user.success_requirements:
        assert req.is_satisfied_by(user.user_infos).is_satisfied


def test_possible_requirements_failure(user):
    for req in user.failure_requirements:
        assert not req.is_satisfied_by(user.user_infos).is_satisfied


def test_claim_override(user):
    req = HasClaim("bar", "foo")
    assert not req.is_satisfied_by(user.user_infos).is_satisfied
    os.environ["DISABLE_AUTHENTICATION_AND_ASSUME_ENTITLEMENTS"] = json.dumps(["bar"])
    assert req.is_satisfied_by(user.user_infos).is_satisfied


def test_empty_meta_requirements(user):
    user_infos = user.user_infos
    assert not AllOf().is_satisfied_by(user_infos).is_satisfied
    assert not OneOf().is_satisfied_by(user_infos).is_satisfied
    assert not N_Of(1).is_satisfied_by(user_infos).is_satisfied
