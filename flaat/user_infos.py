import logging
from json import JSONEncoder
from time import time
from typing import Any, Optional


logger = logging.getLogger(__name__)


class UserInfos:
    """Infos about an access token and the user it belongs to.
    This class acts like a dictionary with regards to claims.
    So `infos["foo"]` will give you the claim if it does exist in one of the underlying dicts.
    """

    user_info: dict
    """ user_info is the user info dictionary from the user info endpoint of the issuer."""
    access_token_info: Optional[Any] = None  # Optional AccessTokenInfo
    """ Is set to `AccessTokenInfo` if the respective access token was a JWT."""
    introspection_info: Optional[dict] = None
    """ Is the data returned from the token intropsection endpoint of the issuer."""

    def __init__(
        self,
        access_token_info: Optional[Any],  # Optional AccessTokenInfo
        user_info: dict,
        introspection_info: Optional[dict],
    ):
        self.access_token_info = access_token_info
        self.user_info = user_info
        self.introspection_info = introspection_info

        # trigger possible post processing here
        self.post_process_dictionaries()

    def _strip_duplicate_infos(self):  # pragma: no cover
        """strip duplicate infos from the introspection_info and access_token_info.body"""
        if self.introspection_info is not None:
            for key in self.user_info.keys():
                if key in self.introspection_info:
                    del self.introspection_info[key]
        if self.access_token_info is not None:
            for key in self.user_info.keys():
                if key in self.access_token_info.body:
                    del self.access_token_info.body[key]

    def post_process_dictionaries(self):
        """post_process_dictionaries can be used to do post processing on the raw dictionaries after initialization.
        Extend this class and overwrite this method to do custom post processing.
        Make sure to call `super().post_process_dictionaries()`, so the post processing done here is picked up.
        """
        # copy a possible 'iss' fields into the user info if it does not exist
        # This is useful if someone extracts only the user_info dictionary from us
        if "iss" not in self.user_info and self.has_key("iss"):
            self.user_info["iss"] = self["iss"]

        # striping duplicates is somewhat opinionated and is therefore not included here
        # self._strip_duplicate_infos()

    @property
    def valid_for_secs(self) -> Optional[int]:
        """Is set if we now about the expiry of these user infos."""

        def _timeleft(info_dict, claim="exp") -> Optional[int]:
            """Get expiry from info dictionary (either from access token or introspection"""
            if claim in info_dict:
                now = time()
                timeleft = info_dict[claim] - now
                return timeleft

            return None  # pragma: no cover

        timeleft = None
        if self.introspection_info is not None:
            timeleft = _timeleft(self.introspection_info)

        if timeleft is None and self.access_token_info is not None:
            timeleft = _timeleft(self.access_token_info.body)

        return timeleft

    @property
    def issuer(self) -> str:
        """The issuer of the access token"""
        return self.get("iss", "")

    @property
    def subject(self) -> str:
        """The users subject at the issuer"""
        return self.get("sub", "")

    # make the UserInfos act like a dictionary with regard to claims
    def __getitem__(self, key):
        if key in self.user_info:
            return self.user_info[key]
        if self.introspection_info is not None and key in self.introspection_info:
            return self.introspection_info[key]
        if self.access_token_info is not None and key in self.access_token_info.body:
            return self.access_token_info.body[key]
        raise KeyError(
            "Claim does not exist in user_info, access_token_info.body and introspection_info"
        )  # pragma: no cover

    def has_key(self, key):
        return (
            key in self.user_info
            or (
                self.access_token_info is not None
                and key in self.access_token_info.body
            )
            or (self.introspection_info is not None and key in self.introspection_info)
        )

    def get(self, key, default=None):
        if self.has_key(key):
            return self[key]
        return default

    def __str__(self):
        return f"{self.subject}@{self.issuer}"

    def toJSON(self) -> str:
        """Render these infos to JSON"""

        class ATEncoder(JSONEncoder):
            def default(self, o):
                return o.__dict__

        return ATEncoder(indent=4, sort_keys=True, separators=(",", ":")).encode(self)
