# This code is distributed under the MIT License

from __future__ import annotations
import json
import logging
import re
from typing import Optional

import requests
from requests.models import HTTPBasicAuth

from flaat import access_tokens
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

# Defaults for requests
VERIFY_TLS = True
TIMEOUT = 1.2  # (seconds)


def is_url(string):
    """Return True if parameter is a URL, otherwise False"""
    regex = re.compile(
        r"^(?:http|ftp)s?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    if re.match(regex, string):
        return True
    return False


class IssuerConfig:
    issuer_config: dict
    client_id: str
    client_secret: str

    def __init__(self, issuer_config: dict, client_id="", client_secret=""):
        self.issuer_config = issuer_config
        self.client_id = client_id
        self.client_secret = client_secret

    @property
    def issuer(self) -> str:
        return self.issuer_config.get("issuer", "")

    @classmethod
    def get_from_url(cls, url) -> Optional[IssuerConfig]:
        """Get issuer_wellknown/configuration from url; return json if true, None otherwise.
        Note that this endpoint is called more often than necessary. We rely on requests_cache to keep
        this efficient"""
        # If requests_cache is not wanted. Here would be one place to implement caching

        headers = {"Content-type": "application/x-www-form-urlencoded"}
        config_url = url

        # remove slashes:
        config_url = re.sub("^https?://", "", config_url)
        config_url = config_url.replace("//", "/")
        config_url = "https://" + config_url
        logger.info("Fetching issuer config from: %s", config_url)
        try:
            resp = requests.get(
                config_url, verify=VERIFY_TLS, headers=headers, timeout=TIMEOUT
            )
            issuer_config: dict = resp.json()
            return cls(issuer_config=issuer_config)

        except requests.exceptions.RequestException as e:
            logger.debug("Error fetching issuer config from %s: %s", config_url, e)
            return None

    @classmethod
    def get_from_string(cls, string: str) -> Optional[IssuerConfig]:
        """If the string provided is a URL: try several well known endpoints until the ISS config is
        found"""
        if string is None or not is_url(string):
            return None

        well_known_path = "/.well-known/openid-configuration"

        if string.endswith(well_known_path):
            return cls.get_from_url(string)

        if string.endswith(("/oauth2", "/oauth2/")):
            return cls.get_from_url(string + well_known_path)

        for url in [
            string + well_known_path,
            string + "/oauth2" + well_known_path,
        ]:
            iss_config = cls.get_from_url(url)
            if iss_config is not None:
                return iss_config

        return None

    def _get_introspected_token_info(self, access_token: str):
        """Query te token introspection endpoint, if there is a client_id and client_secret set"""

        if self.client_id == "" and self.client_secret == "":
            logger.debug(
                "Skipping introspection endpoint because client_id and client_secret are not configured"
            )
            return None

        if self.client_secret != "":
            auth = HTTPBasicAuth(self.client_id, self.client_secret)
        else:
            auth = HTTPBasicAuth(self.client_id, "")

        introspection_endpoint = self.issuer_config.get("introspection_endpoint", "")
        if introspection_endpoint == "":
            return None

        logger.debug("Getting introspection from %s", introspection_endpoint)
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        post_data = {"token": access_token}
        try:
            resp = requests.post(
                introspection_endpoint,
                verify=VERIFY_TLS,
                headers=headers,
                data=post_data,
                timeout=TIMEOUT,
                auth=auth,
            )
            resp_json = dict(resp.json())
            logger.debug(
                "Got Introspection from %s: %s",
                introspection_endpoint,
                json.dumps(resp_json, sort_keys=True, indent=4, separators=(",", ": ")),
            )
            return resp_json
        except requests.exceptions.RequestException as e:
            logger.warning(
                "Error fetching introspection info from %s: %s",
                introspection_endpoint,
                e,
            )
            return None

    def _get_user_info(self, access_token: str) -> Optional[dict]:
        """Query the userinfo endpoint, using the AT as authentication"""
        headers = {}
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        headers["Authorization"] = f"Bearer {access_token}"
        userinfo_endpoint = self.issuer_config.get("userinfo_endpoint", "")

        if userinfo_endpoint == "":
            return None

        logger.debug("Trying to get userinfo from %s", userinfo_endpoint)
        try:
            resp = requests.get(
                userinfo_endpoint,
                verify=VERIFY_TLS,
                headers=headers,
                timeout=TIMEOUT,
            )

            resp_json = dict(resp.json())
            logger.debug(
                "Got Userinfo from %s: %s",
                userinfo_endpoint,
                json.dumps(resp_json, sort_keys=True, indent=4, separators=(",", ": ")),
            )
            if "error_description" in resp_json:
                logger.warning(
                    "Error fetching userinfo from %s: %s",
                    userinfo_endpoint,
                    resp_json["error_description"],
                )
                return None
            return resp_json

        except requests.exceptions.RequestException as e:
            logger.warning("Error fetching userinfo from %s: %s", userinfo_endpoint, e)
            return None

    def get_user_infos(
        self, access_token, access_token_info=None
    ) -> Optional[UserInfos]:
        user_info = self._get_user_info(access_token)
        if user_info is None:
            return None

        if access_token_info is None:
            access_token_info = access_tokens.get_access_token_info(access_token)

        introspection_info = self._get_introspected_token_info(access_token)

        return UserInfos(access_token_info, user_info, introspection_info)
