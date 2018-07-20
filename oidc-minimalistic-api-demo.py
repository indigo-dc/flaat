#!/usr/bin/env python3
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# }}}
'''This is the minimalistic illustration the use of flask and oidc.
It only covers protection of your API 

For Python3 there is one
patch to be applied to flask_oidc __init__.py function (as of 2018-07018):
--- __init__.py 2018-07-18 15:29:28.329889173 +0200
+++ __init__.py--fixed-for-python3        2018-07-18 15:10:31.717529319 +0200
@@ -884,7 +903,7 @@
         if (auth_method == 'client_secret_basic'):
             basic_auth_string = '%s:%s' % (self.client_secrets['client_id'], self.client_secrets['client_secret'])
             basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
-            headers['Authorization'] = 'Basic %s' % b64encode(basic_auth_bytes)
+            headers['Authorization'] = 'Basic %s' % b64encode(basic_auth_bytes).decode('utf-8')
         elif (auth_method == 'bearer'):
             headers['Authorization'] = 'Bearer %s' % token
         elif (auth_method == 'client_secret_post'):
'''

import json
from flask import Flask, request, g
from flask_oidc import OpenIDConnect

import logging
logging.basicConfig(level=logging.DEBUG,
        format="[%(asctime)s] {%(filename)s:%(funcName)s:%(lineno)d} %(levelname)s - %(message)s")
logging.info('\n NEW START')

##########
# Basic config
app=Flask(__name__)# {{{

# for the API we don't need clientid and secret in client_secrets_deep.json
app.config.update({
    'OIDC_CLIENT_SECRETS': './client_secrets_deep.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_VALID_ISSUERS': ('https://iam.deep-hybrid-datacloud.eu/', 'https://accounts.google.com/'),
    'OIDC_SCOPES': (['openid', 'email', 'profile']),
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_basic',
    'SECRET_KEY': 'secret'})
oidc = OpenIDConnect(app)
# }}}

##########
# helpers
def get_access_token_from_request(request):# {{{
    '''Helper function to obtain the OIDC AT from the request'''
    if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
        token = request.headers['Authorization'].split(None,1)[1].strip()
    if 'access_token' in request.form:
        token = request.form['access_token']
    elif 'access_token' in request.args:
        token = request.args['access_token']
    return token
# }}}

##########
# REST API example (aka Resource server flow)
@app.route('/api')# {{{
# @oidc.accept_token(require_token=False, scopes_required=['openid', 'profile'])
def hello_api():
    '''Example for an API call (call it like curl http://localhost:8080/api -H "Authorization: Bearer $OIDC")'''
    response =  ''
    # we can get hold of the access token and then get the data from _retrieve_userinfo
    # Nice thing is that we don't even have to register a client, to obtain the userinfo just by
    # using the access_token
    access_token  = get_access_token_from_request(request)
    if access_token is None:
        response += 'Could not find access token in request'
        return (response)

    # response += 'AccessToken: %s\n' % access_token
    userinfo = oidc._retrieve_userinfo(access_token)
    if userinfo.get('error') is not None:
        response += '\nThere was an error using the access token, probably it expired:\n'
        response += userinfo.get('error')
        return (response)

    response += '\nuserinfo: '+ str(json.dumps(userinfo, sort_keys=True, indent='    ', separators=(',', ': ')))
    return (response)
# }}}

##########
# Main / Boilerplate
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
