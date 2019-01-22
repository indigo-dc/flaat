#!/usr/bin/env python3
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

    parser.add_argument('--verbose', '-v', action="count", default=0, help='Verbosity')
    parser.add_argument('--userinfo_uri'           , default="https://iam.deep-hybrid-datacloud.eu/userinfo")
    parser.add_argument('--token_introspection_uri', default="https://iam.deep-hybrid-datacloud.eu/introspect")
    parser.add_argument('--client_id',               default="f41b1f96-a5e3-40eb-96e6-a377b1494174")
    parser.add_argument('--client_secret',           default="")
    parser.add_argument('--verify_tls'             , default=True  , action="store_false" , help='disable verify')
    parser.add_argument('--accesstoken',   '--at'  , default=False , action="store_true")
    parser.add_argument('--userinfo',      '--ui'  , default=False , action="store_true")
    parser.add_argument('--introspection', '--in'  , default=False , action="store_true")
    parser.add_argument('--all',           '-a'    , default=False , action="store_true")
    parser.add_argument(dest='access_token'   )
    args = parser.parse_args()

    return args
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
    (header_enc, body_enc, signature_enc) = access_token.split('.')

    # header = json.loads(base64url_decode(header_enc).decode('utf-8'))
    header = json.loads(base64url_decode(header_enc))
    # print ('header: "%s"' % header)

    # body = json.loads(base64url_decode(body_enc).decode('utf-8'))
    body = json.loads(base64url_decode(body_enc))
    return ({'header': header, 'body': body, 'signature': signature_enc})
# }}}
def get_user_info(access_token):# {{{
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    headers['Authorization'] = 'Bearer {0}'.format(access_token)
    resp = requests.get (args.userinfo_uri, verify=args.verify_tls, headers=headers)
        # "userinfo_uri": "https://iam.deep-hybrid-datacloud.eu/userinfo"
    if args.verbose:
        print("resp: %s" % resp.status_code)
    if resp.status_code != 200:
        try:
            # lets try to find an error in a returned json:
            resp_json = resp.json()
            return({'error': resp_json['error']})
        except KeyError:
            return ({'error': 'unknown error: {}'.format(resp.status_code)})
        except:
            print("Error: %s" % resp.status_code)
            print("Error: %s" % resp.text)
            print("Error: %s" % str(resp.text))
            print("Error: %s" % str(resp.reason))
            return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
    resp_json=resp.json()
    if args.verbose:
        print(json.dumps(resp_json, sort_keys=True, indent=4, separators=(',', ': ')))
    return resp_json
# }}}
def get_introspected_token_info(access_token):# {{{
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}

    post_data = {'token': access_token}

    if args.client_secret is not '':
        basic_auth_string = '%s:%s' % (args.client_id, args.client_secret)
    else:
        basic_auth_string = '%s' % (args.client_id)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')

    headers['Authorization'] = 'Basic %s' % base64.b64encode(basic_auth_bytes).decode('utf-8')


    resp = requests.post (args.token_introspection_uri, \
                          verify=args.verify_tls, headers=headers, data=post_data)
    if args.verbose:
        print("resp: %s" % resp.status_code)
    if resp.status_code != 200:
        try:
            # lets try to find an error in a returned json:
            resp_json = resp.json()
            return({'error': '{}: {}'.format(resp.status_code, resp_json['error'])})
        except KeyError:
            return ({'error': 'unknown error: {}'.format(resp.status_code)})
        except:
            print("Error: %s" % resp.status_code)
            print("Error: %s" % resp.text)
            print("Error: %s" % str(resp.text))
            print("Error: %s" % str(resp.reason))
            return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})

    return(resp.json())
# }}}
def merge_tokens(tokenlist):# {{{
    supertoken={}
    for entry in tokenlist:
        for key in entry.keys():
            supertoken[key]=entry[key]
    return supertoken
# }}}

args = parseOptions()


# get info from Access Token:
accesstoken_info = get_accesstoken_info(args.access_token)
now = time.time()
timeleft = accesstoken_info['body']['exp'] - now
if args.accesstoken or args.all:
    print("\nInfo from ACCESS TOKEN:")
    print (json.dumps(accesstoken_info['header'], sort_keys=True, indent=4, separators=(',', ': ')))
    print (json.dumps(accesstoken_info['body'], sort_keys=True, indent=4, separators=(',', ': ')))

# get userinfo
user_info = get_user_info(args.access_token)
if args.userinfo or args.all:
    print("\nInfo from USERINFO:")
    print(json.dumps(user_info, sort_keys=True, indent=4, separators=(',', ': ')))

# get id_token
introspection_info = get_introspected_token_info(args.access_token)
if args.introspection or args.all:
    print("\nInfo from TOKEN INTROSPECTION:")
    print(json.dumps(introspection_info, sort_keys=True, indent=4, separators=(',', ': ')))


supertoken = merge_tokens ([accesstoken_info['header'], accesstoken_info['body'], user_info,
    introspection_info])

print("\nSupertoken:")
print(json.dumps(supertoken, sort_keys=True, indent=4, separators=(',', ': ')))


print ('time left: %.1f s' % timeleft)

