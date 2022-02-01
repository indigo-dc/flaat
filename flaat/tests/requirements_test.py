import pytest
from flaat.requirements import HasAARCEntitlement
from flaat.exceptions import FlaatException


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
