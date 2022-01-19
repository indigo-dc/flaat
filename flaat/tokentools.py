"""Tools for FLAAT"""
# This code is distributed under the MIT License

import base64
import json
import logging
import re
import time
from typing import List, Optional, Union


logger = logging.getLogger(__name__)


def merge_tokens(tokenlist: List[Union[dict, None]]) -> dict:
    """put all provided tokens into one token."""
    supertoken = {}
    for entry in tokenlist:
        if entry is not None:
            for key in entry.keys():
                supertoken[key] = entry[key]

    return supertoken


def base64url_encode(data):
    """Decode base64 encode data"""
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    encode = base64.urlsafe_b64encode(data)
    return encode.decode("utf-8").rstrip("=")


def base64url_decode(data):
    """Encode base64 encode data"""
    size = len(data) % 4
    if size == 2:
        data += "=="
    elif size == 3:
        data += "="
    elif size != 0:
        raise ValueError("Invalid base64 string")
    return base64.urlsafe_b64decode(data).decode()


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


def get_accesstoken_info(access_token):
    """Return information contained in the access token. Maybe None"""
    # FIXME: Add a parameter verify=True, then go and verify the token

    splits = access_token.split(".")
    if len(splits) != 3:
        logger.info("Access token is not a JWT")
        return None

    (header_enc, body_enc, signature_enc) = splits

    try:
        header = json.loads(base64url_decode(header_enc))
        body = json.loads(base64url_decode(body_enc))
        logger.debug(
            "header: %s",
            json.dumps(header, sort_keys=True, indent=4, separators=(",", ": ")),
        )
        logger.debug(
            "body: %s",
            json.dumps(body, sort_keys=True, indent=4, separators=(",", ": ")),
        )
        return {"header": header, "body": body, "signature": signature_enc}
    except ValueError as e:
        logger.debug("Unable to decode JWT: %s", e)
        return None


def get_issuer_from_access_token_info(
    access_token_info: Optional[dict],
) -> Optional[str]:
    """Return the issuer of the AT, if it can be found, otherwise None"""

    if access_token_info is None:
        return None

    try:
        return access_token_info["body"]["iss"]
    except ValueError as e:
        logger.error("Error accessing access_token_info: %s", e)
        return None


def get_timeleft(token) -> int:
    """Get the lifetime left in the token"""
    timeleft = -1
    if token is not None:
        now = time.time()
        try:
            timeleft = token["exp"] - now
        except KeyError:  # no 'exp' claim
            pass
        try:
            timeleft = token["body"]["exp"] - now
        except KeyError:  # no 'exp' claim
            pass
        try:
            timeleft = token["access_token"]["body"]["exp"] - now
        except KeyError:  # no 'exp' claim
            pass
    return timeleft
