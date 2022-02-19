# This code is distributed under the MIT License

from __future__ import annotations
import json
import logging
import re
from typing import Optional

import requests
from requests.models import HTTPBasicAuth

from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

# Defaults for requests
_VERIFY_TLS = True
_TIMEOUT = 1.2  # (seconds)


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


def _make_json_request(
    url, timeout: float, verify_tls: bool, **kwargs
) -> Optional[dict]:
    try:
        if "data" in kwargs:
            resp = requests.post(url, verify=verify_tls, timeout=timeout, **kwargs)
        else:
            resp = requests.get(url, verify=verify_tls, timeout=timeout, **kwargs)

        if resp.status_code != 200:
            logger.debug("Error response: %s %s", resp.status_code, resp.text)
            return None

        resp_json = dict(resp.json())
        return resp_json

    except requests.exceptions.RequestException as e:
        logger.debug("Error making json request to %s: %s", url, e)
        return None


class IssuerConfig:
    issuer_config: dict
    client_id: str
    client_secret: str
    timeout: float
    verify_tls: bool

    def __init__(
        self,
        issuer_config: dict,
        client_id="",
        client_secret="",
        timeout=_TIMEOUT,
        verify_tls=_VERIFY_TLS,
    ):
        self.issuer_config = issuer_config
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.verify_tls = verify_tls

    @property
    def issuer(self) -> str:
        return self.issuer_config.get("issuer", "")

    @classmethod
    def _get_from_url(cls, url, timeout, verify_tls) -> Optional[IssuerConfig]:
        config_url = url

        # remove slashes:
        config_url = re.sub("^https?://", "", config_url)
        config_url = config_url.replace("//", "/")
        config_url = "https://" + config_url

        logger.debug("Fetching issuer config from: %s", config_url)
        issuer_config_dict = _make_json_request(config_url, timeout, verify_tls)
        if issuer_config_dict is None:
            return None

        return cls(
            issuer_config=issuer_config_dict, timeout=timeout, verify_tls=verify_tls
        )

    @classmethod
    def get_from_string(
        cls, iss: str, timeout=_TIMEOUT, verify_tls=_VERIFY_TLS
    ) -> Optional[IssuerConfig]:
        """If the string provided is a URL: try several well known endpoints until the ISS config is
        found"""
        if iss is None or not is_url(iss):
            return None

        well_known_path = "/.well-known/openid-configuration"

        if iss.endswith(well_known_path):
            return cls._get_from_url(iss, timeout, verify_tls)

        if iss.endswith(("/oauth2", "/oauth2/")):
            return cls._get_from_url(iss + well_known_path, timeout, verify_tls)

        for url in [
            iss + well_known_path,
            iss + "/oauth2" + well_known_path,
        ]:
            iss_config = cls._get_from_url(url, timeout, verify_tls)
            if iss_config is not None:
                logger.info("Retrieved config for issuer: %s", iss)
                return iss_config

        return None

    def _get_introspected_token_info(self, access_token: str):
        """Query te token introspection endpoint, if there is a client_id and client_secret set"""

        if self.client_id == "" and self.client_secret == "":
            logger.debug(
                "Skipping token introspection because both client_id and client_secret are not configured"
            )
            return None

        introspection_endpoint = self.issuer_config.get("introspection_endpoint", "")
        if introspection_endpoint == "":
            logger.debug(
                "Skipping token introspection because there is no introspection endpoint"
            )
            return None

        post_data = {"token": access_token}
        introspection_info_dict = _make_json_request(
            introspection_endpoint,
            self.timeout,
            self.verify_tls,
            data=post_data,
            auth=HTTPBasicAuth(self.client_id, self.client_secret),
        )
        logger.debug(
            "Got introspection info from %s: %s",
            introspection_endpoint,
            json.dumps(
                introspection_info_dict,
                sort_keys=True,
                indent=4,
                separators=(",", ": "),
            ),
        )
        return introspection_info_dict

    def _get_user_info(self, access_token: str) -> Optional[dict]:
        """Query the userinfo endpoint, using the AT as authentication"""

        userinfo_endpoint = self.issuer_config.get("userinfo_endpoint", "")
        if userinfo_endpoint == "":
            return None

        headers = {"Authorization": f"Bearer {access_token}"}
        logger.debug("Trying to get userinfo from %s", userinfo_endpoint)
        user_info_dict = _make_json_request(
            userinfo_endpoint, self.timeout, self.verify_tls, headers=headers
        )
        logger.debug(
            "Got userinfo from %s: %s",
            userinfo_endpoint,
            json.dumps(
                user_info_dict, sort_keys=True, indent=4, separators=(",", ": ")
            ),
        )
        return user_info_dict

    def get_user_infos(
        self,
        access_token,
        access_token_info=None,
    ) -> Optional[UserInfos]:
        user_info = self._get_user_info(access_token)
        if user_info is None:
            return None

        introspection_info = self._get_introspected_token_info(access_token)

        return UserInfos(access_token_info, user_info, introspection_info)
