'''Tools for FLAAT'''
# This code is distributed under the MIT License
# pylint
# vim: tw=100 foldmethod=indent
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# pylint: disable=logging-not-lazy, logging-format-interpolation


import base64
import re
import time
import json
import logging

logger = logging.getLogger(__name__)

verbose = 0
verify_tls = True

def merge_tokens(tokenlist):
    '''put all provided tokens into one token.'''
    supertoken = {}
    for entry in tokenlist:
        try:
            for key in entry.keys():
                supertoken[key] = entry[key]
        except AttributeError:
            pass
    if supertoken == {}:
        return None
    return supertoken

def get_access_token_from_request(request):
    '''Helper function to obtain the OIDC AT from the flask request variable'''
    token = None
    if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
        temp = request.headers['Authorization'].split('authorization header: ')[0]
        token = temp.split(' ')[1]
    elif 'access_token' in request.form:
        token = request.form['access_token']
    elif 'access_token' in request.args:
        token = request.args['access_token']
    return token

def base64url_encode(data):
    '''Decode base64 encode data'''
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    encode = base64.urlsafe_b64encode(data)
    return encode.decode('utf-8').rstrip('=')

def base64url_decode(data):
    '''Encode base64 encode data'''
    size = len(data) % 4
    if size == 2:
        data += '=='
    elif size == 3:
        data += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return base64.urlsafe_b64decode(data).decode()

def is_url(string):
    '''Return True if parameter is a URL, otherwise False'''
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if re.match(regex, string):
        return True
    return False

def get_accesstoken_info(access_token):
    '''Return information contained in the access token. Maybe None'''
    try:
        (header_enc, body_enc, signature_enc) = access_token.split('.')
        if verbose > 2:
            print('header_enc: '+str(header_enc))
            print('body_enc: '+str(body_enc))

        header = json.loads(base64url_decode(header_enc))
        body = json.loads(base64url_decode(body_enc))

        if verbose > 2:
            print('header')
            print(json.dumps(header, sort_keys=True, indent=4, separators=(',', ': ')))
            print('body')
            print(json.dumps(body, sort_keys=True, indent=4, separators=(',', ': ')))
        return ({'header': header, 'body': body, 'signature': signature_enc})
    except ValueError:
        # Cannot raise here, because inability to split will return None. That will trigger another
        # issuer to be used
        # raise
        return None

def get_issuer_from_accesstoken_info(access_token):
    '''Return the issuer of the AT, if it can be found, otherwise None'''
    try:
        return get_accesstoken_info(access_token)['body']['iss']
    except ValueError:
        return None
    except TypeError:
        return None

def get_timeleft(token):
    '''Get the lifetime left in the token'''
    timeleft = None
    if token is not None:
        now = time.time()
        try:
            timeleft = token['exp'] - now
        except KeyError: # no 'exp' claim
            pass
        try:
            timeleft = token['body']['exp'] - now
        except KeyError: # no 'exp' claim
            pass
        try:
            timeleft = token['access_token']['body']['exp'] - now
        except KeyError: # no 'exp' claim
            pass
    return timeleft
