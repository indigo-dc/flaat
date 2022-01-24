"""Tools for token handling in FLAAT"""
# This code is distributed under the MIT License

import fileinput
import json
import logging
import re
from base64 import b64encode
from queue import Empty, Queue
from threading import Thread
from typing import Optional

import requests
import requests_cache

from flaat import tokentools

logger = logging.getLogger(__name__)


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


# default cache values:
class Cache_options:
    """capture options for requests_cache"""

    def __init__(self):
        self.include_get_headers = True
        self.expire_after = 300
        self.allowable_codes = (200, 400, 401, 402, 403, 404)
        self.backend = "memory"

    def set_lifetime(self, lifetime):
        """set cache lifetime"""
        self.expire_after = lifetime
        self.update_cache()

    def set_allowable_codes(self, allowable_codes):
        """set http status code that will be cached"""
        self.allowable_codes = allowable_codes
        self.update_cache()

    def set_backend(self, backend):
        """set the backend"""
        self.backend = backend
        self.update_cache()

    def update_cache(self):
        """update the changes"""
        requests_cache.install_cache(
            include_get_headers=self.include_get_headers,
            expire_after=self.expire_after,
            allowable_codes=self.allowable_codes,
            backend=self.backend,
        )


cache_options = Cache_options()
cache_options.update_cache()


# Set defaults:
verify_tls = True
timeout = 1.2  # (seconds)
num_request_workers = 10
param_q = Queue(num_request_workers * 2)
result_q = Queue(num_request_workers * 2)


def find_issuer_config_in_at(access_token) -> Optional[dict]:
    """If there is an issuer in the AT, we fetch the ISS config and return it"""
    at_info = tokentools.get_access_token_info(access_token)
    if at_info is None:
        return None

    at_iss = at_info.issuer
    logger.debug("Issuer: %s", at_iss)
    if at_iss is None or not is_url(at_iss):
        return None

    config_url = at_iss + "/.well-known/openid-configuration"
    return get_iss_config_from_url(config_url)


def find_issuer_config_in_string(string: str) -> Optional[dict]:
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
        iss_config = get_iss_config_from_url(url)
        if iss_config is not None:
            return iss_config

    return None


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
        result = get_iss_config_from_url(item)
        result_q.put(result)
        param_q.task_done()
        result_q.task_done()

    logger.debug("thread_worker_issuerconfig stopping")


def find_issuer_config_in_list(
    op_list, op_hint=None, exclude_list: Optional[list] = None
) -> Optional[dict]:
    """find the hinted issuer in configured op_list"""
    if exclude_list is None:
        exclude_list = []

    for _ in range(num_request_workers):
        t = Thread(target=thread_worker_issuerconfig)
        # t = Thread(target=worker)
        t.daemon = True
        t.start()

    if op_list:
        for issuer in op_list:
            if issuer in exclude_list:
                logger.debug("skipping %s due to exclude list", issuer)
                continue
            issuer_wellknown = issuer + "/.well-known/openid-configuration"
            if op_hint is None:
                # print ('getting issuer config from {}'.format(issuer))
                # iss_config.append(get_iss_config_from_url(issuer_wellknown))
                # logger.debug("Trying issuer from %s" % issuer_wellknown)
                param_q.put(issuer_wellknown)
            else:
                if re.search(op_hint, issuer):
                    # logger.debug("Using hint and trying issuer from %s" % issuer_wellknown)
                    # iss_config.append(get_iss_config_from_url(issuer_wellknown))
                    param_q.put(issuer_wellknown)
        param_q.join()
        result_q.join()
        try:
            while not result_q.empty():
                entry = result_q.get(block=False, timeout=timeout)
                if entry is not None:
                    return entry
                    # iss_config.append(entry)
            # for entry in iter(result_q.get_nowait, None):
            # iss_config.append(entry)
        except Empty:
            logger.info("exception: Empty value")

    return None


def find_issuer_config_in_file(op_file, op_hint=None, exclude_list=None):
    """find the hinted issuer in a configured, oidc-agent compatible issuers.conf file
    we only use the first (space separated) entry of that file."""
    if exclude_list is None:
        exclude_list = []
    iss_config = None
    op_list = []
    if op_file:
        for issuer in fileinput.input(op_file):
            issuer_from_conf = str(issuer).rstrip("\n").split(" ", maxsplit=1)[0]
            if issuer_from_conf == "":
                continue
            if issuer_from_conf in exclude_list:
                logger.debug("skipping %s due to exclude list", issuer)
                continue
            op_list.append(issuer_from_conf)
        return find_issuer_config_in_list(op_list, op_hint, exclude_list)
    return iss_config


def get_iss_config_from_url(url) -> Optional[dict]:
    """Get issuer_wellknown/configuration from url; return json if true, None otherwise.
    Note that this endpoint is called more often than necessary. We rely on requests_cache to keep
    this efficient"""
    # If requests_cache is not wanted. Here would be one place to implement caching
    logger.debug("Trying to fetch issuer config from: %s", url)

    headers = {"Content-type": "application/x-www-form-urlencoded"}
    config_url = url

    # remove slashes:
    config_url = re.sub("^https?://", "", config_url)
    config_url = config_url.replace("//+", "/")
    config_url = "https://" + config_url
    logger.debug("Issuer URL: %s\nComputed config URL: %s", url, config_url)
    logger.info("Getting config from: %s", config_url)
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
        logger.warning("Timeout fetching issuer config from endpoint: %s", config_url)
        return None

    try:
        return resp.json()
    except requests.exceptions.JSONDecodeError:
        logger.debug("URL did not return JSON: %s", url)
        return None


def get_user_info(access_token, issuer_config) -> Optional[dict]:
    """Query the userinfo endpoint, using the AT as authentication"""
    headers = {}
    headers = {"Content-type": "application/x-www-form-urlencoded"}
    headers["Authorization"] = f"Bearer {access_token}"
    logger.debug("Trying to get userinfo from %s", issuer_config["userinfo_endpoint"])
    try:
        resp = requests.get(
            issuer_config["userinfo_endpoint"],
            verify=verify_tls,
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.warning(
                "Failed to fetch userinfo from %s: %s / %s / %s\nHeaders was: %s\nTimeout: %s",
                issuer_config["userinfo_endpoint"],
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
            issuer_config["userinfo_endpoint"],
            json.dumps(resp_json, sort_keys=True, indent=4, separators=(",", ": ")),
        )
        return resp_json

    except requests.exceptions.ReadTimeout:
        logger.warning(
            "Timeout fetching userinfo from %s (timeout was %s)",
            issuer_config["issuer"],
            timeout,
        )
        return None


def get_introspected_token_info(
    access_token, issuer_config, client_id=None, client_secret=None
):
    """Query te token introspection endpoint, if there is a client_id and client_secret set"""
    headers = {}
    headers = {"Content-type": "application/x-www-form-urlencoded"}

    post_data = {"token": access_token}

    if client_id is None or client_secret is None:
        logger.debug(
            "Skipping introspection endpoint because client_id and client_secret are not configured"
        )
        return None

    if client_secret in ["", None]:
        basic_auth_string = str(client_id)
    else:
        basic_auth_string = f"{client_id:client_secret}"
    basic_auth_bytes = bytearray(basic_auth_string, "utf-8")

    headers["Authorization"] = f'Basic {b64encode(basic_auth_bytes).decode("utf-8")}'

    introspection_endpoint = issuer_config.get("introspection_endpoint", "")
    if introspection_endpoint != "":
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
