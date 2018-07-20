#!/usr/bin/env python3
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# }}}
'''This is a simple application that illustrates the use of flask and oidc. For Python3 there is one
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
@oidc.accept_token(require_token=False, scopes_required=['openid', 'profile'])
def hello_api():
    '''Example for an API call (call it like curl http://localhost:8080/api -H "Authorization: Bearer $OIDC")'''
    response =  ''

    # here we have to use flask.g to get hold of our info:
    try:
        for field in g.oidc_token_info.keys():
            response +='\n%s: %s' % (field, g.oidc_token_info.get(field))
        response += '\n'
    except AttributeError:
        response += 'Cannot obtain g.oidc_token_info. This is probably due to an internal error in obtaining a token'

    # but again, we can get hold of the access token and then get the data from _retrieve_userinfo
    access_token  = get_access_token_from_request(request)
    if access_token is not None:
        response += 'AccessToken: %s<br/>\n' % access_token
        userinfo =  oidc._retrieve_userinfo(access_token)
        response += 'userinfo: '+ str(json.dumps(userinfo, sort_keys=True, indent='    ', separators=(',', ': ')))
    response += '\ndone\n'
    return (response)
# }}}

##########
# Web application example (aka authorisation code flow)
@app.route('/')# {{{
def hello_world():
    '''Example for web-app and login'''
    if oidc.user_loggedin:
        return ('Hello, %s, <a href="/private">See private</a> '
                '<a href="/logout">Log out</a>') % \
            oidc.user_getfield('email')
    return 'Welcome anonymous,  &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <a href="/private">Log in</a>'
# }}}
@app.route('/private')# {{{
@oidc.require_login
def hello_me():
    '''Example for web-app and private endpoint'''
    response =  ''

    info = oidc.user_getinfo(['email', 'groups'])
    response += 'Hello, %s (%s)! <a href="/">Return</a><br/>\n' % \
            (info.get('email'), info.get('groups'))

    # a bit of a hackier way to get hold of all information
    access_token = oidc.get_access_token()
    if access_token is not None:
        response += 'AccessToken: %s<br/>\n' % access_token
        userinfo =  oidc._retrieve_userinfo(access_token)
        response += 'userinfo: '+ str(json.dumps(userinfo, sort_keys=True, indent=' &nbsp;&nbsp;&nbsp;&nbsp; ', separators=(',<br/>\n', ': ')))
    return (response)
# }}}
@app.route('/logout')# {{{
def logout():
    '''And the logout for the web app'''
    oidc.logout()
    return 'Hi, you have been logged out! <a href="/">Return</a>'
# }}}

##########
# Main / Boilerplate
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
