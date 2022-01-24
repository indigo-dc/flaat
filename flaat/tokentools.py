"""Tools for FLAAT"""
# This code is distributed under the MIT License

import base64
from dataclasses import dataclass
import json
import logging
import time
from typing import Optional


logger = logging.getLogger(__name__)


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


@dataclass
class AccessTokenInfo:
    header: dict
    body: dict
    signature: str

    @property
    def issuer(self) -> str:
        return self.body.get("iss", "")

    @property
    def timeleft(self) -> int:
        """Get the lifetime left in the token"""
        timeleft = -1
        now = time.time()
        try:
            timeleft = self.body["exp"] - now
        except KeyError:  # no 'exp' claim
            pass
        return timeleft


def get_access_token_info(access_token) -> Optional[AccessTokenInfo]:
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
        return AccessTokenInfo(header, body, signature_enc)
    except ValueError as e:
        logger.debug("Unable to decode JWT: %s", e)
        return None
