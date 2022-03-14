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


def _get_signing_key_from_jwt(jwks_uri, access_token) -> str:
    jwk_client = PyJWKClient(jwks_uri)

    try:
        return jwk_client.get_signing_key_from_jwt(access_token).key
    except jwt.exceptions.PyJWKClientError:
        # keys don't have 'kid' field, retrieve key by type, given the 'alg' in token header
        unverified = jwt.api_jwt.decode_complete(
            access_token, options={"verify_signature": False}
        )
        alg = unverified["header"][
            "alg"
        ]  # MUST be present, possible values defined at https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

        # algorithm is none, then signing key is None; signature must be empty octet string
        if alg == "none":
            return ""
        # infer key type from algorithm
        key_type = ""
        if alg.startswith("RS") or alg.startswith("PS"):
            key_type = "RSA"
        if alg.startswith("HS"):
            key_type = "oct"
        if alg.startswith("ES"):
            key_type = "EC"
        if alg.startswith("Ed"):
            key_type = "OKP"
        # get key from JWKS endpoint by key type
        jwk_set = jwk_client.get_jwk_set()
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.key_type == key_type
        ]
        if len(signing_keys) == 0:
            raise FlaatUnauthenticated(
                "Could not verify JWT: The JWKS endpoint did not contain any signing key "
                f"of type {key_type}."
            )
        if len(signing_keys) > 1:
            raise FlaatUnauthenticated(
                f"Could not verify JWT: The JWKS endpoint has too many keys of type {key_type} "
                "and no 'kid' specified."
            )
        return signing_keys[0].key


def get_access_token_info(access_token, verify=True) -> Optional[AccessTokenInfo]:
    unverified = {}
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
        return AccessTokenInfo(unverified, verification=None)

    issuer = IssuerConfig.get_from_string(unverified_body.get("iss", ""))
    if issuer is None:
        raise FlaatUnauthenticated("Could not verify JWT: No 'iss' claim in body")

    jwks_uri = issuer.issuer_config.get("jwks_uri", "")
    if jwks_uri == "":
        raise FlaatUnauthenticated(
            "Could not verify JWT: Issuer config has no jwks_uri"
        )

    signing_key = _get_signing_key_from_jwt(jwks_uri, access_token)

    try:
        complete_decode = jwt.api_jwt.decode_complete(
            access_token,
            signing_key,
            algorithms=PERMITTED_SIGNATURE_ALGORITHMS,
            options={"verify_aud": False},
        )
    except jwt.exceptions.PyJWTError as e:
        raise FlaatUnauthenticated(f"Could not verify JWT: {e}") from e

    return AccessTokenInfo(
        complete_decode,
        verification={"algorithm": complete_decode.get("header", {}).get("alg", "")},
    )
