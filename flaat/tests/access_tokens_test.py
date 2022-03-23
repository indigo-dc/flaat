import contextlib
import json
from unittest import mock

import pytest

import jwt
from flaat.access_tokens import get_access_token_info, FlaatPyJWKClient
from flaat.test_env import FLAAT_AT, NON_JWT_FLAAT_AT


class TestTokens:
    def test_get_accesstoken_info_non_jwt(self):
        access_token = NON_JWT_FLAAT_AT
        if access_token == "":
            pytest.skip("No non JWT access token")

        access_token_info = get_access_token_info(access_token)
        assert access_token_info is None

    def test_get_accesstoken_info_jwt(self):
        access_token = FLAAT_AT
        if access_token in ["", "mock_jwt_at"]:
            pytest.skip("No JWT access token")
        access_token_info = get_access_token_info(access_token)
        assert access_token_info is not None
        assert access_token_info.verification is not None


RESPONSE_DATA = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "bilbo.baggins@hobbiton.example",
            "use": "sig",
            "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
            "e": "AQAB",
        },
        {
            "kid": "O_YttVFkHHz5miLSoyU9s88nH7NZ3IjnXJdtdWZWET8",
            "kty": "RSA",
            "alg": "RSA-OAEP",
            "use": "enc",
            "n": "woLHcpbl4iV-E8UeXNE1Ne2iKwbEs653WE808JB5saqYIpwI9ItVvdP7dWb0Nx2EyO6YfwcfQ50O2wz5rQDkCiGNY9vF4wq3UV1VTYc-Ed8zlLC9hfJQXO0dNXyrdem4im0jb-4y9S2VGRGLTy_1P-MnN60Tqr9TVpR0XEx0sAS12xO9cp0JesfwIgmRdAi8D1A7ug1w35SIsnT5rzEqciu1o7GytcL7EuTy4MRNJp1nXN0fZuNYoIqq7qVbHNoi9WhC1yuPA6AoJnt11wjifJAWraRnMfTCfaeJ-tW43xjpZlOqAxaB-3r-UTj2JBGbIDvF-yeW5E2yjRD9YsWYDQ",
            "e": "AQAB",
            "x5c": [
                "MIIClTCCAX0CBgF++OQ2PzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANlZ2kwHhcNMjIwMjE0MTUzODMyWhcNMzIwMjE0MTU0MDEyWjAOMQwwCgYDVQQDDANlZ2kwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCgsdyluXiJX4TxR5c0TU17aIrBsSzrndYTzTwkHmxqpginAj0i1W90/t1ZvQ3HYTI7ph/Bx9DnQ7bDPmtAOQKIY1j28XjCrdRXVVNhz4R3zOUsL2F8lBc7R01fKt16biKbSNv7jL1LZUZEYtPL/U/4yc3rROqv1NWlHRcTHSwBLXbE71ynQl6x/AiCZF0CLwPUDu6DXDflIiydPmvMSpyK7WjsbK1wvsS5PLgxE0mnWdc3R9m41igiqrupVsc2iL1aELXK48DoCgme3XXCOJ8kBatpGcx9MJ9p4n61bjfGOlmU6oDFoH7ev5ROPYkEZsgO8X7J5bkTbKNEP1ixZgNAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGzA1gBJwyQCjDAFjXCTtEhjJa7xXkNqtBchQlTIDpxDqrKsXLKsLLZzTdx1Bw6p6dLqrRoB6mBbcQz+zHYS6r6E1Vp3JcUFs3aZ9dtW1dowzGKv0JU+42c3Gwl3en5dr3yVhahLRLI0PJf8eFhz4fItGISTDM4ppPK/b2p1Aj03zezD7aKQ9jygnhsGQmHtaW6m8mMQ9a7YwqURd3+VlexbbvvwX6pbXIQj3DK15f2rSLjvdva9smy898ewNonfBpLPvPc5oKLWRf1OyWzpbdwaMXHnItpASpWLFEjb56MjzhAD9dZy4Vruzd45rwohhLXr+qnTqmD81gee9gl13oU="
            ],
            "x5t": "OaLNe4i3IrUkY7G_RhP_czaw1R0",
            "x5t#S256": "5qRFpp9YT000QmD8xuXFWExHTa3hG_jAXBqCYlw6Vj0",
        },
    ]
}


@contextlib.contextmanager
def mocked_response(data):
    with mock.patch("urllib.request.urlopen") as urlopen_mock:
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(data)]
        urlopen_mock.return_value = response
        yield urlopen_mock


class TestFlaatPyJWKClient:
    """Use RSA key from PyJWKClient tests,
    Only test new/overwritten methods and add new test cases.
    """

    def test_get_signing_keys(self):
        url = "mock_url"

        with mocked_response(RESPONSE_DATA):
            jwks_client = FlaatPyJWKClient(url)
            signing_keys = jwks_client.get_signing_keys()

        assert len(signing_keys) == 1
        assert isinstance(signing_keys[0], jwt.api_jwk.PyJWK)

    def test_get_signing_key_by_alg(self):
        url = "mock_url"

        with mocked_response(RESPONSE_DATA):
            jwks_client = FlaatPyJWKClient(url)
            signing_key = jwks_client.get_signing_key_by_alg("RS256")

        assert isinstance(signing_key, jwt.api_jwk.PyJWK)
        assert signing_key.key_type == "RSA"

    def test_get_signing_key_from_jwt_by_kid(self):
        token = "eyJhbGciOiJSUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.FY-57Y3K04hjK53P6t7XXnM_PLIYZbV0b596UOzmIBWkAznzga6Rqo-_uommL2hcsZMrzUtNpN0b9_11z7DDjaoPUYoJITyFDgJGLynMC538iLBWA-7x-3y-oKZkAK78yM5h5C3lIiRAlPKP_2UNyK-W40xyxoBW975fLqBVMChDUmQkyhH2GS4i16nZdbCYVMjGytxTHGH6810QneKVeoV0EStjxHjBKxTF26_1PRqeuMiYom6CRp7BdGQidDO_JxH7BqD6GPwnV3AzaFBnFsE5L9mrSTOymuvCELXLJwQYYGpT5i1ti4MP2jtSQYxvy3Zel56ybnSaaI1QTyRNAQ"
        url = "mock_url"

        with mocked_response(RESPONSE_DATA):
            jwks_client = FlaatPyJWKClient(url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="https://expenses-api",
            options={"verify_exp": False},
        )

        assert data == {
            "iss": "https://dev-87evx9ru.auth0.com/",
            "sub": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients",
            "aud": "https://expenses-api",
            "iat": 1572006954,
            "exp": 1572006964,
            "azp": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC",
            "gty": "client-credentials",
        }

    def test_get_signing_key_from_jwt_by_alg(self):
        token = "eyJhbGciOiJSUzI1NiIsImN0eSI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.gn8boXt4bGSpjuWYijwGE6A0NG1NtRnT07jBw6e2WxBb8KnwxO5BJr-GL0f-UJSRiWDwoSrrwOs5PP0I0XiQPnnmnD4J8OB3z3ETdI3pxa4EsceLaLto0F9SM7JxSHP8NzZJfRwD8GTwgrOs3PrG7nsukvXQYwsRejgYysjsaRCRMa46CfoJGRowYxSuNxtlTMLRlB2q7YNKpxwiCVw1UCrJ_CZybcO3HUFufyuRuWztaI2L8AIueO_oCchhi3X1bNErgzeIza1UsdXrf6Eqf788Easd1YO1RQYSuEejnwdrgh0BERCLMN8kO16vIxYvb2vcM95odRD-ge_lyp8_TA"
        url = "mock_url"

        RESPONSE_DATA_NO_KID = RESPONSE_DATA.copy()
        del RESPONSE_DATA_NO_KID["keys"][0]["kid"]

        with mocked_response(RESPONSE_DATA_NO_KID):
            jwks_client = FlaatPyJWKClient(url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="https://expenses-api",
            options={"verify_exp": False},
        )

        assert data == {
            "iss": "https://dev-87evx9ru.auth0.com/",
            "sub": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC@clients",
            "aud": "https://expenses-api",
            "iat": 1572006954,
            "exp": 1572006964,
            "azp": "aW4Cca79xReLWUz0aE2H6kD0O3cXBVtC",
            "gty": "client-credentials",
        }
