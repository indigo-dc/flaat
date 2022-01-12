"""Tools for token handling in FLAAT"""
# This code is distributed under the MIT License
# pylint
# vim: tw=100 foldmethod=indent
# pylint: disable=invalid-name, superfluous-parens
# pylint: disable=logging-not-lazy, logging-format-interpolation, logging-fstring-interpolation
# pylint: disable=wrong-import-position, line-too-long

import sys

is_py2 = sys.version[0] == "2"
if is_py2:
    # pylint: disable=import-error
    from Queue import Queue, Empty
else:
    from queue import Queue, Empty
from threading import Thread
import re
import fileinput
from base64 import b64encode
import json
import logging
import requests
import requests_cache

from flaat import tokentools


logger = logging.getLogger(__name__)

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
verbose = 2
verify_tls = True
timeout = 1.2  # (seconds)
num_request_workers = 10
param_q = Queue(num_request_workers * 2)
result_q = Queue(num_request_workers * 2)


def find_issuer_config_in_at(access_token):
    """If there is an issuer in the AT, we fetch the ISS config and return it"""
    iss_config = None
    at_iss = tokentools.get_issuer_from_accesstoken_info(access_token)
    if verbose > 1:
        logger.info(f"Issuer: {at_iss}")
    if at_iss is not None:
        if tokentools.is_url(at_iss):
            config_url = at_iss + "/.well-known/openid-configuration"
            iss_config = get_iss_config_from_endpoint(config_url)
    return iss_config


def find_issuer_config_in_string(string):
    """If the string provided is a URL: try several well known endpoints until the ISS config is
    found"""
    iss_config = None
    if string is not None:
        if tokentools.is_url(string):
            iss_config = get_iss_config_from_endpoint(string)
            if iss_config:
                return iss_config
            iss_config = get_iss_config_from_endpoint(string + "/oauth2")
            if iss_config:
                return iss_config
            iss_config = get_iss_config_from_endpoint(
                string + "/.well-known/openid-configuration"
            )
            if iss_config:
                return iss_config
            iss_config = get_iss_config_from_endpoint(
                string + "/oauth2" + "/.well-known/openid-configuration"
            )
    return iss_config


def thread_worker_issuerconfig():
    """Thread worker"""

    def safe_get(q):
        try:
            return q.get(timeout=5)
        except Empty:
            return None

    while True:
        item = safe_get(param_q)
        if item is None:
            break
        result = get_iss_config_from_endpoint(item)
        result_q.put(result)
        param_q.task_done()
        result_q.task_done()


def find_issuer_config_in_list(op_list, op_hint=None, exclude_list=[]):
    """find the hinted issuer in configured op_list"""

    iss_config = None
    for i in range(num_request_workers):
        t = Thread(target=thread_worker_issuerconfig)
        # t = Thread(target=worker)
        t.daemon = True
        t.start()

    if op_list:
        iss_config = []
        for issuer in op_list:
            # if verbose>1:
            #     logger.info('Considering issuer %s' % issuer)
            if issuer in exclude_list:
                if verbose > 1:
                    logger.debug("skipping %s due to exclude list" % issuer)
                continue
            issuer_wellknown = issuer + "/.well-known/openid-configuration"
            if op_hint is None:
                # print ('getting issuer config from {}'.format(issuer))
                # iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
                # logger.debug("Trying issuer from %s" % issuer_wellknown)
                param_q.put(issuer_wellknown)
            else:
                if re.search(op_hint, issuer):
                    # logger.debug("Using hint and trying issuer from %s" % issuer_wellknown)
                    # iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
                    param_q.put(issuer_wellknown)
        param_q.join()
        result_q.join()
        try:
            while not result_q.empty():
                entry = result_q.get(block=False, timeout=timeout)
                if entry is not None:
                    iss_config.append(entry)
            # for entry in iter(result_q.get_nowait, None):
            # iss_config.append(entry)
        except Empty:
            logger.info("exception: Empty value")

    return iss_config


def find_issuer_config_in_file(op_file, op_hint=None, exclude_list=[]):
    """find the hinted issuer in a configured, oidc-agent compatible issuers.conf file
    we only use the first (space separated) entry of that file."""
    iss_config = None
    op_list = []
    if op_file:
        iss_config = []
        for issuer in fileinput.input(op_file):
            issuer_from_conf = issuer.rstrip("\n").split(" ")[0]
            if issuer_from_conf == "":
                continue
            if issuer_from_conf in exclude_list:
                if verbose > 1:
                    logger.info("skipping %s due to exclude list" % issuer)
                continue
            op_list.append(issuer_from_conf)
        return find_issuer_config_in_list(op_list, op_hint, exclude_list)
    return iss_config


def get_iss_config_from_endpoint(issuer_url):
    """Get issuer_wellknown/configuration from url; return json if true, None otherwise.
    Note that this endpoint is called more often than necessary. We rely on requests_cache to keep
    this efficient"""
    # If requests_cache is not wanted. Here would be one place to implement caching

    headers = {"Content-type": "application/x-www-form-urlencoded"}
    config_url = issuer_url
    # remove slashes:
    config_url = re.sub("^https?://", "", config_url)
    config_url = config_url.replace("//", "/")
    config_url = config_url.replace("//", "/")
    config_url = "https://" + config_url

    if verbose > 2:
        logger.info("Getting config from: %s" % config_url)
    try:
        resp = requests.get(
            config_url, verify=verify_tls, headers=headers, timeout=timeout
        )
        if verbose > 2:
            if resp.status_code != 200:
                logger.warning("Getconfig: resp: %s" % resp.status_code)
    except requests.exceptions.ConnectionError as e:
        if verbose > 2:
            logger.warning(
                "Warning: cannot obtain iss_config from endpoint: {}".format(config_url)
            )
            # print ('Additional info: {}'.format (e))
        return None
    except requests.exceptions.ReadTimeout as e:
        if verbose > 1:
            logger.warning(
                "Warning: cannot obtain iss_config from endpoint: {}".format(config_url)
            )
            # print ('Additional info: {}'.format (e))
        return None
    try:
        return resp.json()
    except Exception as e:
        logger.warning(f"Caught exception: {e}\n{str(resp.text)}")
        return None


def get_user_info(access_token, issuer_config):
    """Query the userinfo endpoint, using the AT as authentication"""
    headers = {}
    headers = {"Content-type": "application/x-www-form-urlencoded"}
    headers["Authorization"] = "Bearer {0}".format(access_token)
    if verbose > 2:
        logger.debug("using this access token: %s" % access_token)
    if verbose > 0:
        logger.info(
            "Trying to get userinfo from %s" % issuer_config["userinfo_endpoint"]
        )
    try:
        resp = requests.get(
            issuer_config["userinfo_endpoint"],
            verify=verify_tls,
            headers=headers,
            timeout=timeout,
        )
    except requests.exceptions.ReadTimeout:
        logger.error("ReadTimeout caught for issuer_config['issuer']")
        # logger.debug(F"headers were: {headers}, timeout: {timeout}")
        return None
    if resp.status_code != 200:
        if verbose > 1:
            logger.warning(
                "Not getting userinfo from %s: %s / %s / %s"
                % (
                    issuer_config["userinfo_endpoint"],
                    resp.status_code,
                    resp.text,
                    resp.reason,
                )
            )
            if verbose > 2:
                logger.warning(f"request was: get {issuer_config['userinfo_endpoint']}")
                logger.warning(f"headers were: {headers}, timeout: {timeout}")
        # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
        return None

    if verbose > 0:
        logger.info(
            "          got userinfo from %s" % issuer_config["userinfo_endpoint"]
        )
    resp_json = resp.json()
    if verbose > 2:
        logger.info(
            "Actual Userinfo: from %s" % issuer_config["userinfo_endpoint"]
            + ": "
            + json.dumps(resp_json, sort_keys=True, indent=4, separators=(",", ": "))
        )
        if resp.status_code != 200:
            logger.info("userinfo: resp: %s" % resp.status_code)
    return (resp_json, issuer_config)


def get_introspected_token_info(
    access_token, issuer_config, client_id=None, client_secret=None
):
    """Query te token introspection endpoint, if there is a client_id and client_secret set"""
    headers = {}
    headers = {"Content-type": "application/x-www-form-urlencoded"}

    post_data = {"token": access_token}

    if client_id is None or client_secret is None:
        if verbose > 1:
            logger.debug(
                "Skipping introspection endpioint because client_id and client_secret are not configured"
            )
        return None

    if client_secret in ["", None]:
        basic_auth_string = "%s" % (client_id)
    else:
        basic_auth_string = "%s:%s" % (client_id, client_secret)
    basic_auth_bytes = bytearray(basic_auth_string, "utf-8")

    headers["Authorization"] = "Basic %s" % b64encode(basic_auth_bytes).decode("utf-8")

    if verbose > 1:
        logger.info(
            "Getting introspection from %s" % issuer_config["userinfo_endpoint"]
        )
    try:
        resp = requests.post(
            issuer_config["introspection_endpoint"],
            verify=verify_tls,
            headers=headers,
            data=post_data,
            timeout=timeout,
        )
    except KeyError:  # no introspection_endpoint found
        return None

    if verbose > 2:
        logger.info("introspect: resp: %s" % resp.status_code)
    if resp.status_code != 200:
        try:
            # lets try to find an error in a returned json:
            # resp_json = resp.json()
            # return({'error': '{}: {}'.format(resp.status_code, resp_json['error'])})
            return None
        except KeyError:
            # return ({'error': 'unknown error: {}'.format(resp.status_code)})
            return None
        except:
            logger.error("Introspect: Error: %s" % resp.status_code)
            logger.error("Introspect: Error: %s" % resp.text)
            logger.error("Introspect: Error: %s" % str(resp.text))
            logger.error("Introspect: Error: %s" % str(resp.reason))
            # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
            return None

    return resp.json()
