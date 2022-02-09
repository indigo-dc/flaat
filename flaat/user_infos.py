from json import JSONEncoder
import logging
from typing import Optional

from flaat.access_tokens import AccessTokenInfo

logger = logging.getLogger(__name__)


class UserInfos:
    """Infos represents infos about an access token and the user it belongs to"""

    user_info: dict
    access_token_info: Optional[AccessTokenInfo]
    introspection_info: Optional[dict]
    valid_for_secs: int = -1

    def __init__(
        self,
        access_token_info: Optional[AccessTokenInfo],
        user_info: dict,
        introspection_info: Optional[dict],
    ):
        self.access_token_info = access_token_info
        if self.access_token_info is not None:
            self.valid_for_secs = self.access_token_info.timeleft

        self.user_info = user_info
        self.introspection_info = introspection_info

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

    def __str__(self):
        return f"{self.subject}@{self.issuer}"

    def toJSON(self):
        class ATEncoder(JSONEncoder):
            def default(self, o):
                return o.__dict__

        return ATEncoder(indent=4, sort_keys=True, separators=(",", ":")).encode(self)
