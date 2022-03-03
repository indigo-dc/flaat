# This code is distributed under the MIT License

import base64
from dataclasses import dataclass
import logging
from typing import Optional

import jwt
from jwt import PyJWKClient

from flaat.exceptions import FlaatUnauthenticated
from flaat.issuers import IssuerConfig

logger = logging.getLogger(__name__)

# Expand this list in a sensible way
PERMITTED_SIGNATURE_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
]


def _base64_url_encode(data):
    """Decode base64 encode data"""
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    encode = base64.urlsafe_b64encode(data)
    return encode.decode("utf-8").rstrip("=")


@dataclass
class AccessTokenInfo:
    """Infos from a JWT access token"""

    header: dict
    """ The JWTs JOSE header """

    body: dict
    """ The JWTs data payload """

    signature: str
    """ The JWTs JWS signature """

    verification: Optional[dict]
    """ Infos about the verification of the JWT.
    If set to `None`, then the JWT data is unverified."""

    def __init__(self, complete_decode, verification=Optional[dict]):
        self.header = complete_decode.get("header", {})
        self.body = complete_decode.get("payload", {})
        self.signature = _base64_url_encode(complete_decode.get("signature", b""))
        self.verification = verification

    @property
    def issuer(self) -> str:
        return self.body.get("iss", "")


def get_access_token_info(access_token, verify=True) -> Optional[AccessTokenInfo]:
    unverified = None
    try:
        unverified = jwt.api_jwt.decode_complete(
            access_token,
            options={
                "verify_signature": False,
            },
        )
        unverified_body = unverified.get("payload", {})
    except jwt.DecodeError:
        return None

    if not verify:
        return AccessTokenInfo(unverified_body, verification=None)

    issuer = IssuerConfig.get_from_string(unverified_body.get("iss", ""))
    if issuer is None:
        raise FlaatUnauthenticated("Could not verify JWT: No 'iss' claim in body")

    jwks_uri = issuer.issuer_config.get("jwks_uri", "")
    if jwks_uri == "":
        raise FlaatUnauthenticated(
            "Could not verify JWT: Issuer config has no jwks_uri"
        )

    jwk_client = PyJWKClient(jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(access_token)
    try:
        complete_decode = jwt.api_jwt.decode_complete(
            access_token, signing_key.key, algorithms=PERMITTED_SIGNATURE_ALGORITHMS
        )
    except jwt.InvalidSignatureError as e:
        raise FlaatUnauthenticated("Could not verify JWT: Invalid signature") from e

    return AccessTokenInfo(
        complete_decode,
        verification={"algorithm": complete_decode.get("header", {}).get("alg", "")},
    )
