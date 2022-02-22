# This code is distributed under the MIT License

import base64
import json
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


def _base64_url_encode(data):
    """Decode base64 encode data"""
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    encode = base64.urlsafe_b64encode(data)
    return encode.decode("utf-8").rstrip("=")


def _base64_url_decode(data):
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
    """Infos from a JWT access token"""

    header: dict
    """ The JWT header """

    body: dict
    """ The JWT body """

    signature: str
    """ The JWT signature """

    @property
    def issuer(self) -> str:
        return self.body.get("iss", "")


def get_access_token_info(access_token) -> Optional[AccessTokenInfo]:

    # FIXME: Add a parameter verify=True, then go and verify the token

    splits = access_token.split(".")
    if len(splits) != 3:
        logger.info("Access token is not a JWT")
        return None

    (header_enc, body_enc, signature_enc) = splits

    try:
        header = json.loads(_base64_url_decode(header_enc))
        logger.debug("JWT Header: %s", header)
        body = json.loads(_base64_url_decode(body_enc))
        logger.debug("JWT Body:   %s", body)
        return AccessTokenInfo(header, body, signature_enc)
    except ValueError as e:
        logger.debug("Unable to decode JWT: %s", e)
        return None
