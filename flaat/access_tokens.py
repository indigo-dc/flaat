# This code is distributed under the MIT License

import base64
from dataclasses import dataclass
import logging
from typing import Optional, List

import jwt

from flaat.exceptions import FlaatUnauthenticated
from flaat.issuers import IssuerConfig

logger = logging.getLogger(__name__)

# Expand this list in a sensible way
PERMITTED_SIGNATURE_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "EdDSA",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "ES521",
    "HS256",
    "HS384",
    "HS512",
    "PS256",
    "PS384",
    "PS512"
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

    def __init__(self, complete_decode, verification):
        self.header = complete_decode.get("header", {})
        self.body = complete_decode.get("payload", {})
        self.signature = _base64_url_encode(complete_decode.get("signature", b""))
        self.verification = verification

    @property
    def issuer(self) -> str:
        return self.body.get("iss", "")


class FlaatPyJWKClient(jwt.PyJWKClient):
    """Fixes the jwt.PyJWKClient class:

    * get_signing_keys
        * does not call self.get_jwk_set(), since it fails when "enc" keys are present
        * returns only keys used for signing (e.g. filters out keys with "use" == "enc")
    * get_signing_key_from_jwt
        * tries to retrieve keys by id only if "kid" is specified in token header
        * otherwise, it tries to infer the key type ("kty") from the algorithm used to sign the token ("alg")
        * "alg" is always present in JWT header
    * an additional method get_signing_key_by_alg
    """

    def get_signing_keys(self) -> List[jwt.api_jwk.PyJWK]:
        data = self.fetch_data()
        # filter for signing keys, i.e. "use" in ["sig", None]
        keys = [
            key for key in data.get("keys", []) if key.get("use", None) in ["sig", None]
        ]
        signing_keys = jwt.PyJWKSet(keys)
        if not signing_keys:
            raise jwt.exceptions.PyJWKClientError(
                "The JWKS endpoint did not contain any signing keys"
            )

        return signing_keys.keys

    def get_signing_key_by_alg(self, alg: str) -> jwt.api_jwk.PyJWK:
        # algorithm is none, then signing key is None; signature must be empty octet string
        if alg == "none":
            return jwt.api_jwk.PyJWK({}, algorithm="none")
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

        signing_keys = self.get_signing_keys()
        signing_key = None

        for key in signing_keys:
            if key.key_type == key_type:
                signing_key = key
                break

        if not signing_key:
            raise jwt.exceptions.PyJWKClientError(
                f'Unable to find a signing key that matches alg: "{alg}"'
            )

        return signing_key

    def get_signing_key_from_jwt(self, token: str) -> jwt.api_jwk.PyJWK:
        unverified = jwt.api_jwt.decode_complete(
            token, options={"verify_signature": False}
        )
        header = unverified["header"]

        kid = header.get("kid", None)
        if kid:
            return self.get_signing_key(kid)

        # alg MUST be present, possible values defined at https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
        alg = header.get("alg", None)
        if alg:
            return self.get_signing_key_by_alg(alg)

        raise FlaatUnauthenticated(
            "Could not verify JWT: The token header did not contain an 'alg'."
        )


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

    jwk_client = FlaatPyJWKClient(jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(access_token)

    try:
        complete_decode = jwt.api_jwt.decode_complete(
            access_token,
            signing_key.key,
            algorithms=PERMITTED_SIGNATURE_ALGORITHMS,
            options={"verify_aud": False},
        )
    except jwt.exceptions.PyJWTError as e:
        raise FlaatUnauthenticated(f"Could not verify JWT: {e}") from e

    return AccessTokenInfo(
        complete_decode,
        verification={"algorithm": complete_decode.get("header", {}).get("alg", "")},
    )
