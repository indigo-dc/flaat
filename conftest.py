import logging
from typing import Optional

from pytest import MonkeyPatch

from flaat import BaseFlaat, test_env
from flaat.access_tokens import AccessTokenInfo
from flaat.exceptions import FlaatUnauthenticated
from flaat.test_env import FLAAT_AT, OIDC_AGENT_ACCOUNT
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)
logging.getLogger("requests_cache").setLevel(logging.WARN)
logging.getLogger("urllib3").setLevel(logging.WARN)
logging.getLogger("asyncio").setLevel(logging.WARN)


# mock data
_jwt_issuer = "https://mock.issuer.jwt"
_non_jwt_issuer = "https://mock.issuer.non.jwt"
_jwt_user_infos = UserInfos(
    AccessTokenInfo(
        {},
        {},
        "",
    ),
    {
        "iss": _jwt_issuer,
        "sub": "mock_sub",
        "mock_groups": ["foo", "bar"],
        "mock_entitlements": [
            "urn:mace:egi.eu:group:test:foo",
            "urn:mace:egi.eu:group:test:bar",
        ],
    },
    None,
)

_non_jwt_user_infos = UserInfos(
    None,
    {
        "iss": _non_jwt_issuer,
        "sub": "non_jwt_mock_sub",
        "mock_groups": ["foo", "bar"],
        "mock_entitlements": [
            "urn:mace:egi.eu:group:test:foo",
            "urn:mace:egi.eu:group:test:bar",
        ],
    },
    None,
)


def _mock_get_user_infos_from_access_token(
    self: BaseFlaat, at, issuer_hint=""
) -> Optional[UserInfos]:
    logger.debug("Mock called for access token: %s %s", at, issuer_hint)
    if issuer_hint == "https://invalid.issuer.org":
        raise FlaatUnauthenticated("mock_unauthenticated")
    if at == "invalid_at":
        return None

    info = None
    if at == "mock_jwt_at":
        info = _jwt_user_infos

    if at == "mock_non_jwt_at":
        info = _non_jwt_user_infos

    if info is not None:
        if not self._issuer_is_trusted(info.issuer):
            raise FlaatUnauthenticated(
                f"Issuer {info.issuer} not trusted (trusted: {self.trusted_op_list} {self.iss})"
            )
        return info
    return None


def mock_user_for_ci():
    logger.debug("Monkey patching BaseFlaat as we have no access token")
    mp = MonkeyPatch()
    mp.setattr(
        BaseFlaat,
        "get_user_infos_from_access_token",
        _mock_get_user_infos_from_access_token,
    )
    for (key, value) in [
        ("FLAAT_ISS", _jwt_issuer),
        ("NON_JWT_FLAAT_ISS", _non_jwt_issuer),
        ("FLAAT_TRUSTED_OPS_LIST", [_jwt_issuer, _non_jwt_issuer]),
        ("FLAAT_CLAIM_GROUP", "mock_groups"),
        ("FLAAT_CLAIM_ENTITLEMENT", "mock_entitlements"),
        ("FLAAT_AT", "mock_jwt_at"),
        ("NON_JWT_FLAAT_AT", "mock_non_jwt_at"),
    ]:
        mp.setattr(test_env, key, value)


if OIDC_AGENT_ACCOUNT == "" or FLAAT_AT == "":
    mock_user_for_ci()
