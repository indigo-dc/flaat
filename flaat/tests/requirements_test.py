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
    get_audience_requirement,
)
from flaat.test_env import (
    FLAAT_ISS,
    User,
    AUD_OIDC_AGENT_ACCOUNT,
    AUD_FLAAT_ISS,
    load_at,
)
from flaat.exceptions import FlaatException

INVALID_ENTITLEMENT = "foo-bar"
VALID_ENTITLEMENT = "urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"
CLAIM = "eduperson_entitlement"

INVALID_AUDIENCE = "foo"
VALID_AUDIENCE = "test-audience"


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


def _get_user_infos(flaat, access_token):
    user_infos = flaat.get_user_infos_from_access_token(access_token)
    if user_infos is None:
        raise FlaatException(
            "Cannot run tests: could not fetch a userinfo with the access token"
        )
    return user_infos


@pytest.fixture
def user():
    return RequirementsUser()


@pytest.fixture
def flaat_aud():
    if AUD_OIDC_AGENT_ACCOUNT == "" or AUD_FLAAT_ISS == "":
        pytest.skip("No env vars set for OP that supports audience")
    flaat = BaseFlaat()
    flaat.set_issuer(AUD_FLAAT_ISS)
    flaat.set_trusted_OP_list([AUD_FLAAT_ISS])
    return flaat


def test_possible_requirements_success(user):
    """constructs (nearly) all options of using our decorators for testing them
    against the frameworks"""

    for req in user.success_requirements:
        assert req.is_satisfied_by(user.user_infos).is_satisfied


def test_possible_requirements_failure(user):
    for req in user.failure_requirements:
        assert not req.is_satisfied_by(user.user_infos).is_satisfied


def test_empty_meta_requirements(user):
    user_infos = user.user_infos
    assert not AllOf().is_satisfied_by(user_infos).is_satisfied
    assert not OneOf().is_satisfied_by(user_infos).is_satisfied
    assert not N_Of(1).is_satisfied_by(user_infos).is_satisfied


def test_unset_or_unsupported_aud_success(user):
    user_infos = user.user_infos
    assert get_audience_requirement("").is_satisfied_by(user_infos).is_satisfied
    assert get_audience_requirement([]).is_satisfied_by(user_infos).is_satisfied
    assert get_audience_requirement(5).is_satisfied_by(user_infos).is_satisfied
    assert get_audience_requirement({}).is_satisfied_by(user_infos).is_satisfied


def test_supported_aud_success(flaat_aud):
    access_token = load_at(AUD_OIDC_AGENT_ACCOUNT, audience=VALID_AUDIENCE)
    user_infos = _get_user_infos(flaat_aud, access_token)
    assert (
        get_audience_requirement(VALID_AUDIENCE)
        .is_satisfied_by(user_infos)
        .is_satisfied
    )
    assert (
        get_audience_requirement([VALID_AUDIENCE])
        .is_satisfied_by(user_infos)
        .is_satisfied
    )
    assert (
        get_audience_requirement([VALID_AUDIENCE, INVALID_AUDIENCE])
        .is_satisfied_by(user_infos)
        .is_satisfied
    )


def test_supported_aud_invalid(flaat_aud):
    access_token = load_at(AUD_OIDC_AGENT_ACCOUNT, audience=VALID_AUDIENCE)
    user_infos = _get_user_infos(flaat_aud, access_token)
    assert (
        not get_audience_requirement(INVALID_AUDIENCE)
        .is_satisfied_by(user_infos)
        .is_satisfied
    )


def test_supported_aud_missing(flaat_aud):
    access_token = load_at(AUD_OIDC_AGENT_ACCOUNT)
    user_infos = _get_user_infos(flaat_aud, access_token)
    assert (
        not get_audience_requirement(INVALID_AUDIENCE)
        .is_satisfied_by(user_infos)
        .is_satisfied
    )


def test_supported_aud_multiple(flaat_aud):
    access_token = load_at(AUD_OIDC_AGENT_ACCOUNT, audience=f"{VALID_AUDIENCE} bar")
    user_infos = _get_user_infos(flaat_aud, access_token)
    assert (
        get_audience_requirement(VALID_AUDIENCE)
        .is_satisfied_by(user_infos)
        .is_satisfied
    )
    assert (
        get_audience_requirement([VALID_AUDIENCE, INVALID_AUDIENCE])
        .is_satisfied_by(user_infos)
        .is_satisfied
    )
    assert (
        not get_audience_requirement(INVALID_AUDIENCE)
        .is_satisfied_by(user_infos)
        .is_satisfied
    )
