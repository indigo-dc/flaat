#!/usr/bin/env python3
# MIT License{{{
#
# Copyright (c) 2017 - 2019 Karlsruhe Institute of Technology - Steinbuch Centre for Computing
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.}}}
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace, mixed-indentation
# pylint: disable=redefined-outer-name, logging-not-lazy, logging-format-interpolation
# pylint: disable=missing-docstring, trailing-whitespace, trailing-newlines, too-few-public-methods
# }}}

import os
import sys
import base64
import time
import re
import fileinput
import json
import requests
import configargparse

def parseOptions():# {{{
    '''Parse the commandline options'''

    path_of_executable = os.path.realpath(sys.argv[0])
    folder_of_executable = os.path.split(path_of_executable)[0]
    full_name_of_executable = os.path.split(path_of_executable)[1]
    name_of_executable = full_name_of_executable.rstrip('.py')

    config_files = [os.environ['HOME']+'/.config/%sconf' % name_of_executable,
                    folder_of_executable +'/%s.conf'     % name_of_executable,
                    '/root/configs/%s.conf'              % name_of_executable]
    parser = configargparse.ArgumentParser(
            default_config_files = config_files,
            description=name_of_executable, ignore_unknown_config_file_keys=True)

    parser.add('-c', '--my-config',  is_config_file=True, help='config file path')
    parser.add_argument('--verbose', '-v', action="count", default=0, help='Verbosity')
    parser.add_argument('--client_id',               default="")
    parser.add_argument('--client_secret',           default="")
    parser.add_argument('--verify_tls'             , default=True  , action="store_false" , help='disable verify')
    parser.add_argument('--accesstoken',   '--at'  , default=False , action="store_true")
    parser.add_argument('--userinfo',      '--ui'  , default=False , action="store_true")
    parser.add_argument('--introspection', '--in'  , default=False , action="store_true")
    parser.add_argument('--all',           '-a'    , default=False , action="store_true")
    parser.add_argument('--issuersconf'            , default='/etc/oidc-agent/issuer.config',
                                                     help='issuer.config, e.g. from oidc-agent')
    parser.add_argument('--issuer', '--iss', '-i',   help='Specify issuer (OIDC Provider)')
    parser.add_argument(dest='access_token'   )

    args = parser.parse_args()
    # parser.print_values()
    return args
# }}}
def is_url(string):# {{{
    import re
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, string)
# }}}
def get_iss_config_from_endpoint(issuer_url):# {{{
    '''Get issuer_wellknown/configuration from url; return json if true, None otherwise'''
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    config_url = issuer_url
    # remove slashes:
    config_url = re.sub('^https?://', '', config_url)
    config_url = config_url.replace('//', '/')
    config_url = config_url.replace('//', '/')
    config_url = 'https://'+config_url

    if args.verbose:
        print('trying to get config from: %s' % config_url)
    resp = requests.get (config_url, verify=args.verify_tls, headers=headers)
    if args.verbose > 2:
        print("resp: %s" % resp.status_code)
    try:
        return resp.json()
    except:
        print(str(resp.text))
        return None
# }}}
def get_issuer_from_accesstoken_info(access_token):# {{{
    try:
        return get_accesstoken_info(access_token)['body']['iss']
    except ValueError:
        return None
    except TypeError:
        return None
    # }}}
def find_issuer_configs(access_token):# {{{
    # 1: find info in the AT
    at_iss = get_issuer_from_accesstoken_info(access_token)
    if args.verbose > 1:
        print ('got iss from access_token: %s' % str(at_iss))
    if at_iss is not None:
        if is_url(at_iss):
            config_url = at_iss+'/.well-known/openid-configuration'
            iss_config = get_iss_config_from_endpoint(config_url)
            if iss_config is not None:
                return [iss_config]

    # 2: use a parameter in the commandline
    # 3: if the parameter is a URL: try url
    # 4: if the parameter is a URL: try url +  '/.well-known/openid-configuration'
    # 5: if the parameter is a URL: try url +  variations
    if args.issuer is None:
        print('Issuer not found in access token. Please consider using the -i option')
        exit (3)
    if is_url(args.issuer):
        iss_config = get_iss_config_from_endpoint(args.issuer)
        if iss_config:
            return [iss_config]
        iss_config = get_iss_config_from_endpoint(args.issuer+'/oauth2')
        if iss_config:
            return [iss_config]
        iss_config = get_iss_config_from_endpoint(args.issuer+'/.well-known/openid-configuration')
        if iss_config:
            return [iss_config]
        iss_config = get_iss_config_from_endpoint(args.issuer+'/oauth2'+'/.well-known/openid-configuration')
        if iss_config:
            return [iss_config]

    # 5: if the parameter is no URL: try all matches in issuers.conf
    if args.issuersconf:
        iss_config=[]
        for line in fileinput.input(args.issuersconf):
            issuer_from_conf=line.split(' ')[0]
            if re.search(args.issuer, line):
                issuer_wellknown=issuer_from_conf.rstrip('/') + '/.well-known/openid-configuration'
                iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
        return iss_config

    return None
# }}}
def base64url_encode(data):# {{{
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    encode = base64.urlsafe_b64encode(data)
    return encode.decode('utf-8').rstrip('=')
# }}}
def base64url_decode(data):# {{{
    size = len(data) % 4
    if size == 2:
        data += '=='
    elif size == 3:
        data += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return base64.urlsafe_b64decode(data.encode('utf-8'))
# }}}

def get_accesstoken_info(access_token):# {{{
    ''' if there is information in the access token, we return it, else None'''
    try:
        (header_enc, body_enc, signature_enc) = access_token.split('.')

    # header = json.loads(base64url_decode(header_enc).decode('utf-8'))
        header = json.loads(base64url_decode(header_enc))
        # print ('header: "%s"' % header)

        # body = json.loads(base64url_decode(body_enc).decode('utf-8'))
        body = json.loads(base64url_decode(body_enc))
        return ({'header': header, 'body': body, 'signature': signature_enc})
    except:
        return None
# }}}
def get_user_info(access_token, issuer_config):# {{{
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    headers['Authorization'] = 'Bearer {0}'.format(access_token)
    resp = requests.get (issuer_config['userinfo_endpoint'], verify=args.verify_tls, headers=headers)
        # "userinfo_uri": "https://iam.deep-hybrid-datacloud.eu/userinfo"
    if args.verbose > 1:
        print("resp: %s" % resp.status_code)
    if resp.status_code != 200:
        if args.verbose:
            print('no userinfo at %s' % issuer_config['userinfo_endpoint'])
        try:
            # lets try to find an error in a returned json:
            # resp_json = resp.json()
            # return({'error': resp_json['error']})
            return None
        except KeyError:
            # return ({'error': 'unknown error: {}'.format(resp.status_code)})
            return None
        except:
            if args.verbose > 2:
                print("Error: %s" % resp.status_code)
                print("Error: %s" % resp.text)
                print("Error: %s" % str(resp.text))
                print("Error: %s" % str(resp.reason))
            # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
            return None
    resp_json=resp.json()
    if args.verbose:
        print('got userinfo from %s' % issuer_config['userinfo_endpoint'])
    if args.verbose>1:
        print(json.dumps(resp_json, sort_keys=True, indent=4, separators=(',', ': ')))
    return resp_json
# }}}
def get_introspected_token_info(access_token, issuer_config):# {{{
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}

    post_data = {'token': access_token}

    if args.client_id is None or args.client_secret is None:
        if args.verbose:
            print ('You need to provide --client_id and --client_secret' % args.client_id)
        return None

    if args.client_secret is not '':
        basic_auth_string = '%s:%s' % (args.client_id, args.client_secret)
    else:
        basic_auth_string = '%s' % (args.client_id)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')

    headers['Authorization'] = 'Basic %s' % base64.b64encode(basic_auth_bytes).decode('utf-8')


    try:
        resp = requests.post (issuer_config['introspection_endpoint'], \
                              verify=args.verify_tls, headers=headers, data=post_data)
    except KeyError: # no introspection_endpoint found
        return None

    if args.verbose>1:
        print("resp: %s" % resp.status_code)
    if resp.status_code != 200:
        try:
            # lets try to find an error in a returned json:
            # resp_json = resp.json()
            # return({'error': '{}: {}'.format(resp.status_code, resp_json['error'])})
            return None
        except KeyError:
            # return ({'error': 'unknown error: {}'.format(resp.status_code)})
            return None
        except:
            print("Error: %s" % resp.status_code)
            print("Error: %s" % resp.text)
            print("Error: %s" % str(resp.text))
            print("Error: %s" % str(resp.reason))
            # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
            return None

    return(resp.json())
# }}}
def merge_tokens(tokenlist):# {{{
    supertoken={}
    for entry in tokenlist:
        try:
            for key in entry.keys():
                supertoken[key]=entry[key]
        except AttributeError:
            pass
    return supertoken
# }}}

args = parseOptions()

# find issuer configs{{{
issuer_configs = find_issuer_configs(args.access_token)
if args.verbose:
    print ('found %d issuer_config endpoints for your search "%s"' % (len(issuer_configs), args.issuer))
for issuer_config in issuer_configs:
    if issuer_config is None:
        print ('Error: cannot find issuer config. ')
    if args.verbose > 1:
        print ("issuer config:")
        print (json.dumps(issuer_config, sort_keys=True, indent=4, separators=(',', ': ')))
    if args.verbose > 1:
        print ('userinfo: %s' % issuer_config['userinfo_endpoint'])
# }}}

# get info from Access Token:{{{
accesstoken_info = get_accesstoken_info(args.access_token)
at_head={}
at_body={}
timeleft=None
if accesstoken_info is not None:
    at_head = accesstoken_info['header']
    at_body = accesstoken_info['body']
    now = time.time()
    timeleft = accesstoken_info['body']['exp'] - now
    if args.accesstoken or args.all:
        if args.verbose:
            print("\nInfo from ACCESS TOKEN:")
        print (json.dumps(accesstoken_info['header'], sort_keys=True, indent=4, separators=(',', ': ')))
        print (json.dumps(accesstoken_info['body'], sort_keys=True, indent=4, separators=(',', ': ')))
# }}}
# get userinfo{{{
for issuer_config in issuer_configs:
    user_info = get_user_info(args.access_token, issuer_config)
    if user_info is not None:
        if args.userinfo or args.all:
            if args.verbose:
                print("\nInfo from USERINFO:")
            print(json.dumps(user_info, sort_keys=True, indent=4, separators=(',', ': ')))
# }}}
# get introspection_token{{{

for issuer_config in issuer_configs:
    introspection_info = get_introspected_token_info(args.access_token, issuer_config)
    if introspection_info is not None:
        if args.introspection or args.all:
            print("\nInfo from TOKEN INTROSPECTION:")
            print(json.dumps(introspection_info, sort_keys=True, indent=4, separators=(',', ': ')))
# }}}

supertoken = merge_tokens ([at_head, at_body, user_info, introspection_info])

if args.verbose:
    print("\nSupertoken:")
print(json.dumps(supertoken, sort_keys=True, indent=4, separators=(',', ': ')))


if timeleft:
    print ('Token valid for: %.1f s' % timeleft)

