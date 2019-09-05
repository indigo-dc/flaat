# -*- coding: utf-8 -*-
# pylint: disable=bad-whitespace, invalid-name, missing-docstring
import unittest
import json
import sys
from flaat import tokentools
is_py2 = sys.version[0] == '2'


class is_url(unittest.TestCase):
    def test_url_1(self):
        self.assertTrue(tokentools.is_url('http://heise.de'))
    def test_valid_url_http(self):
        self.assertTrue(tokentools.is_url('http://heise.de'))
    def test_valid_url_https(self):
        self.assertTrue(tokentools.is_url('https://heise.de'))
    def test_valid_url_ftp(self):
        self.assertTrue(tokentools.is_url('ftp://heise.de'))
    def test_valid_url_https_path(self):
        self.assertTrue(tokentools.is_url('https://heise.de/thi_s&is=difficult'))
    def test_invalid_url(self):
        self.assertFalse(tokentools.is_url('htp://heise.de'))

class base64(unittest.TestCase):
    def test_encode_decode_simple(self):
        data="this is a static teststring without strange chars"
        b64 = tokentools.base64url_encode(data)
        b64_dec = tokentools.base64url_decode(b64)

        # self.assertEqual (data, b64_dec.decode())
        self.assertEqual (data, tokentools.base64url_decode(b64).decode())

    def test_encode_decode_newline(self):
        data="this is a static teststring with\nnewline\rand\tstuff"
        b64 = tokentools.base64url_encode(data)
        self.assertEqual (data, tokentools.base64url_decode(b64).decode())

    def test_encode_decode_evil(self):
        '''No unicode for python2'''
        if not is_py2:
            data=u"this is a static\nteststring\rwith mäni€ strange characters"
            b64 = tokentools.base64url_encode(data)
            self.assertEqual (data, tokentools.base64url_decode(b64).decode())

    def test_encode_decode_evil_unicode(self):
        '''No unicode for python2'''
        if not is_py2:
            data=u"this is a static\nteststring\rwith mäni€ strange characters"
            b64 = tokentools.base64url_encode(data)
            self.assertEqual (data, tokentools.base64url_decode(b64).decode())

class tokens(unittest.TestCase):
    def test_merge_tokens(self):
        at_info=json.loads('''{
            "body": {
                "exp": 1567676165,
                "iat": 1567672565,
                "iss": "https://iam-test.indigo-datacloud.eu/",
                "jti": "b192dcdc-d790-4088-b71e-0da80044ffa5",
                "sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446"
            },
            "header": {
                "alg": "RS256",
                "kid": "rsa1"
            },
            "signature": "T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo"
            } ''')
        ui_info=json.loads('''{
            "external_authn": {
                "iss": "https://accounts.google.com",
                "sub": "104223951181002749851",
                "type": "oidc"
            },
            "family_name": "Hardt",
            "gender": "M",
            "given_name": "Marcus",
            "groups": [
                "Users",
                "Developers",
                "test.vo-users"
            ],
            "name": "Marcus Hardt",
            "organisation_name": "indigo-dc",
            "preferred_username": "marcus",
            "sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446",
            "updated_at": 1563283972
            }''')
        merged_token = json.loads('''{
            "body": {
                "exp": 1567676165,
                "iat": 1567672565,
                "iss": "https://iam-test.indigo-datacloud.eu/",
                "jti": "b192dcdc-d790-4088-b71e-0da80044ffa5",
                "sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446"
            },
            "header": {
                "alg": "RS256",
                "kid": "rsa1"
            },
            "signature": "T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo",
            "external_authn": {
                "iss": "https://accounts.google.com",
                "sub": "104223951181002749851",
                "type": "oidc"
            },
            "family_name": "Hardt",
            "gender": "M",
            "given_name": "Marcus",
            "groups": [
                "Users",
                "Developers",
                "test.vo-users"
            ],
            "name": "Marcus Hardt",
            "organisation_name": "indigo-dc",
            "preferred_username": "marcus",
            "sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446",
            "updated_at": 1563283972
            }''')
        tt_merged_token = tokentools.merge_tokens([at_info, ui_info])
        self.assertDictEqual(tt_merged_token, merged_token)

    def test_get_accesstoken_info_unity(self):
        at = "g9b2LEMq2cHjup73HMtYjYo11tNDJ-6UoTd_rblDTdU"
        self.assertEqual(tokentools.get_accesstoken_info(at), None)
    def test_get_accesstoken_info_iam(self):
        at = '''eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhMWVhM2FhMi04ZGFmLTQxYmItYjRmYi1lYjg4ZjQzOWU0NDYiLCJpc3MiOiJodHRwczpcL1wvaWFtLXRlc3QuaW5kaWdvLWRhdGFjbG91ZC5ldVwvIiwiZXhwIjoxNTY3Njc2MTY1LCJpYXQiOjE1Njc2NzI1NjUsImp0aSI6ImIxOTJkY2RjLWQ3OTAtNDA4OC1iNzFlLTBkYTgwMDQ0ZmZhNSJ9.T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo'''
        header = json.loads('{"kid": "rsa1", "alg": "RS256"}')
        body = json.loads('{"sub": "a1ea3aa2-8daf-41bb-b4fb-eb88f439e446", "iss": "https://iam-test.indigo-datacloud.eu/", "exp": 1567676165, "iat": 1567672565, "jti": "b192dcdc-d790-4088-b71e-0da80044ffa5"}')
        signature = '''T4EyIub8rkFh1mlz1lUBFmwn8GqMX-QXtWIkUyw-NylnvxNkmL0I4cjNwF-BFgnshGkVHC2f0kiSs799iEwMPuzzSeMxzCydyqo1f77Z7_R-Lh1UCWWATPoUY-oZmnzuQd9rTW8WDrbQFisW1Ig0FAsxyiJ3EMMhEie6kys2jRo'''
        retval = tokentools.get_accesstoken_info(at)
        self.assertDictEqual(header, retval['header'])
        self.assertDictEqual(body,   retval['body'])
        self.assertEqual(signature,  retval['signature'])


if __name__ == '__main__':
    unittest.main()

# class test_tokentools(unittest.TestCase):
#     def valid_url_http(self):
#         self.assertEqual(tokentools.is_url('http://heise.de'), True)
#     def valid_url_https(self):
#         self.assertEqual(tokentools.is_url('https://heise.de'), True)
#     def valid_url_ftp(self):
#         self.assertEqual(tokentools.is_url('ftp://heise.de'), True)
#     def valid_url_https_path(self):
#         self.assertTrue(tokentools.is_url('https://heise.de/thi_s&is=difficult'))
#     def invalid_url(self):
#         self.assertEqual(tokentools.is_url('http://heise.de'), False)

