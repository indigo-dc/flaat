import json

import pytest

from flaat import tokentools


class TestBase64:
    @pytest.mark.parametrize(
        "name,teststring",
        [
            ("simple", "this is a static teststring without strange chars"),
            ("newline", "this is a static teststring with\nnewline\rand\tstuff"),
            ("evil", "this is a static\nteststring\rwith mäni€ strange characters"),
            (
                "evil_unicode",
                "this is a static\nteststring\rwith mäni€ strange characters",
            ),
        ],
    )
    def test_encode_decode(self, name, teststring):
        _ = name
        b64 = tokentools.base64url_encode(teststring)
        assert teststring == tokentools.base64url_decode(b64)


class TestTokens:
    def test_get_accesstoken_info_unity(self):
        at = "g9b2LEMq2cHjup73HMtYjYo11tNDJ-6UoTd_rblDTdU"
        assert tokentools.get_access_token_info(at) is None

    def test_get_accesstoken_info_iam(self):
        at = """eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhMWVhM2FhMi04ZGFmLTQxYmItYjRmYi1lYjg4ZjQzOWU0NDYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNTY3Njc2MTY1LCJpYXQiOjE1Njc2NzI1NjUsImp0aSI6ImIxOTJkY2RjLWQ3OTAtNDA4OC1iNzFlLTBkYTgwMDQ0ZmZhNSJ9.T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo"""
        header = json.loads('{"kid": "rsa1", "alg": "RS256"}')
        body = json.loads(
            '{"sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446", "iss": "https://iam-test.indigo-datacloud.eu/", "exp": 1567676165, "iat": 1567672565, "jti": "b192dcdc-d790-4088-b71e-0da80044ffa5"}'
        )
        signature = """T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo"""
        info = tokentools.get_access_token_info(at)
        assert info is not None
        assert header == info.header
        assert body == info.body
        assert signature == info.signature
