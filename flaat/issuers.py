"""Tools for token handling in FLAAT"""
# This code is distributed under the MIT License

from __future__ import annotations
from base64 import b64encode
import json
import logging
from queue import Empty, Queue
import re
from threading import Thread
from typing import List, Optional

import requests

from flaat import access_tokens
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)


# Set defaults:
verify_tls = True
timeout = 1.2  # (seconds)
num_request_workers = 10
param_q = Queue(num_request_workers * 2)
result_q = Queue(num_request_workers * 2)


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
        config_url = config_url.replace("//+", "/")
        config_url = "https://" + config_url
        logger.info("Fetching issuer config from: %s", config_url)
        try:
            resp = requests.get(
                config_url, verify=verify_tls, headers=headers, timeout=timeout
            )
            if resp.status_code != 200:
                logger.warning("Getconfig: resp: %s", resp.status_code)
        except requests.exceptions.ConnectionError:
            logger.warning("Cannot obtain iss_config from endpoint: %s", config_url)
            return None
        except requests.exceptions.ReadTimeout:
            logger.warning(
                "Timeout fetching issuer config from endpoint: %s", config_url
            )
            return None

        try:
            issuer_config: dict = resp.json()
            return cls(issuer_config=issuer_config)
        except requests.exceptions.JSONDecodeError:
            logger.debug("URL did not return JSON: %s", url)
            return None

    @classmethod
    def get_from_at(cls, access_token) -> Optional[IssuerConfig]:
        """If there is an issuer in the AT, we fetch the ISS config and return it"""
        at_info = access_tokens.get_access_token_info(access_token)
        if at_info is None:
            return None

        at_iss = at_info.issuer
        logger.debug("Issuer: %s", at_iss)
        if at_iss is None or not is_url(at_iss):
            return None

        config_url = at_iss + "/.well-known/openid-configuration"
        return cls.get_from_url(config_url)

    @classmethod
    def get_from_string(cls, string: str) -> Optional[IssuerConfig]:
        """If the string provided is a URL: try several well known endpoints until the ISS config is
        found"""
        if string is None or not is_url(string):
            return None

        for url in [
            string + "/.well-known/openid-configuration",
            string,
            string + "/oauth2",
            string + "/oauth2" + "/.well-known/openid-configuration",
        ]:
            iss_config = cls.get_from_url(url)
            if iss_config is not None:
                return iss_config

        return None

    def _get_introspected_token_info(self, access_token: str):
        """Query te token introspection endpoint, if there is a client_id and client_secret set"""
        headers = {}
        headers = {"Content-type": "application/x-www-form-urlencoded"}

        post_data = {"token": access_token}

        if self.client_id == "" or self.client_secret == "":
            logger.debug(
                "Skipping introspection endpoint because client_id and client_secret are not configured"
            )
            return None

        basic_auth_string = self.client_id
        if self.client_secret != "":
            basic_auth_string += ":{self.client_secret}"
        basic_auth_bytes = bytearray(basic_auth_string, "utf-8")

        headers[
            "Authorization"
        ] = f'Basic {b64encode(basic_auth_bytes).decode("utf-8")}'

        introspection_endpoint = self.issuer_config.get("introspection_endpoint", "")
        if introspection_endpoint == "":
            return None

        logger.debug("Getting introspection from %s", introspection_endpoint)
        resp = requests.post(
            introspection_endpoint,
            verify=verify_tls,
            headers=headers,
            data=post_data,
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.debug("Introspection response: %s - %s", resp.status_code, resp.text)
            return None

        return dict(resp.json())

    def _get_user_info(self, access_token: str) -> Optional[dict]:
        """Query the userinfo endpoint, using the AT as authentication"""
        headers = {}
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        headers["Authorization"] = f"Bearer {access_token}"
        userinfo_endpoint = self.issuer_config.get("userinfo_endpoint", "")
        logger.debug("Trying to get userinfo from %s", userinfo_endpoint)
        if userinfo_endpoint == "":
            return None

        try:
            resp = requests.get(
                userinfo_endpoint,
                verify=verify_tls,
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning(
                    "Failed to fetch userinfo from %s: %s / %s / %s\nHeaders was: %s\nTimeout: %s",
                    userinfo_endpoint,
                    resp.status_code,
                    resp.text,
                    resp.reason,
                    headers,
                    timeout,
                )
                return None

            resp_json = resp.json()
            logger.debug(
                "Got Userinfo from %s: %s",
                userinfo_endpoint,
                json.dumps(resp_json, sort_keys=True, indent=4, separators=(",", ": ")),
            )
            return resp_json

        except requests.exceptions.ReadTimeout:
            logger.warning(
                "Timeout fetching userinfo from %s (timeout was %s)",
                userinfo_endpoint,
                timeout,
            )
            return None

    def get_user_infos(self, access_token, access_token_info=None) -> UserInfos:
        if access_token_info is None:
            access_token_info = access_tokens.get_access_token_info(access_token)
        user_info = self._get_user_info(access_token)
        introspection_info = self._get_introspected_token_info(access_token)

        return UserInfos(access_token_info, user_info, introspection_info)


def thread_worker_issuerconfig():
    """Thread worker"""
    logger.debug("thread_worker_issuerconfig starting")

    def safe_get(q):
        try:
            return q.get(timeout=5)
        except Empty:
            return None

    while True:
        item = safe_get(param_q)
        if item is None:
            break
        result = IssuerConfig.get_from_url(item)
        result_q.put(result)
        param_q.task_done()
        result_q.task_done()

    logger.debug("thread_worker_issuerconfig stopping")


def find_issuer_config_in_list(
    op_list: List[str], op_hint=None, exclude_list: Optional[List[str]] = None
) -> Optional[IssuerConfig]:
    """find the hinted issuer in configured op_list"""
    if exclude_list is None:
        exclude_list = []

    for _ in range(num_request_workers):
        t = Thread(target=thread_worker_issuerconfig)
        t.daemon = True
        t.start()

    if not op_list:
        return None

    for issuer in op_list:
        if issuer in exclude_list:
            logger.debug("skipping %s due to exclude list", issuer)
            continue
        issuer_wellknown = issuer + "/.well-known/openid-configuration"
        if op_hint is None:
            param_q.put(issuer_wellknown)
        else:
            if re.search(op_hint, issuer):
                param_q.put(issuer_wellknown)
    param_q.join()
    result_q.join()
    try:
        while not result_q.empty():
            entry = result_q.get(block=False, timeout=timeout)
            if entry is not None:
                return IssuerConfig(entry)
    except Empty:
        return None
