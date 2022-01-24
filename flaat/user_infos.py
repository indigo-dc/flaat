import json
import logging
from typing import List, Optional

from flaat import issuertools, tokentools
from flaat.tokentools import AccessTokenInfo
from flaat.exceptions import FlaatForbidden

logger = logging.getLogger(__name__)


class UserInfos:
    """Infos represents infos about an access token and the user it belongs to"""

    valid_for_secs: int = -1
    access_token_info: Optional[AccessTokenInfo]
    user_info: Optional[dict]
    introspection_info: Optional[dict]

    def __init__(self, flaat, access_token: str):
        self.access_token_info = tokentools.get_access_token_info(access_token)
        if self.access_token_info is not None:
            self.valid_for_secs = self.access_token_info.timeleft

        issuer_config = flaat._find_issuer_config_everywhere(
            access_token, self.access_token_info
        )
        self.user_info = issuertools.get_user_info(access_token, issuer_config)
        self.introspection_info = issuertools.get_introspected_token_info(
            access_token,
            issuer_config,
            flaat.client_id,
            flaat.client_secret,
        )

    def __repr__(self):
        return json.dumps(self.__dict__)

    @property
    def issuer(self) -> str:
        if self.access_token_info is not None:
            return self.access_token_info.body.get("iss", "")
        return ""

    @property
    def subject(self) -> str:
        if self.user_info is not None:
            return self.user_info.get("sub", "")
        return ""

    def get_entitlements_from_claim(
        self, claim: str, search_precedence: Optional[List[str]] = None
    ) -> List[str]:
        """extract groups / entitlements from given claim (in userinfo or access_token)"""
        if search_precedence is None:
            search_precedence = ["userinfo", "access_token"]

        avail_group_entries = None

        for location in search_precedence:
            avail_group_entries = None
            if location == "userinfo":
                if self.user_info is not None:
                    avail_group_entries = self.user_info.get(claim)
            if location == "access_token":
                if self.access_token_info is not None:
                    avail_group_entries = self.access_token_info.body.get(claim)

            if avail_group_entries is not None:
                break

        if avail_group_entries is None:
            raise FlaatForbidden(f"Claim does not exist: {claim})")
        if not isinstance(avail_group_entries, list):
            raise FlaatForbidden(f"Claim is not a list: {avail_group_entries})")

        return avail_group_entries
