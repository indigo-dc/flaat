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
import re
import fileinput
import json
import requests
import configargparse
from flaat import Flaat, tokentools 

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

    parser.add_argument('--accesstoken',   '-at'  , default=False , action="store_true", dest='show_access_token')
    parser.add_argument('--userinfo',      '-ui'  , default=False , action="store_true", dest='show_user_info')
    parser.add_argument('--introspection', '-in'  , default=False , action="store_true", dest='show_introspection_info')
    parser.add_argument('--all',           '-a'   , default=True ,                      dest='show_all')
    parser.add_argument('--quiet',         '-q'   , default=False, action="store_true")


    parser.add_argument('--issuersconf'            , default='/etc/oidc-agent/issuer.config',
                                                     help='issuer.config, e.g. from oidc-agent')
    parser.add_argument('--issuer', '--iss', '-i',   help='Specify issuer (OIDC Provider)')
    parser.add_argument(dest='access_token'   )

    return parser
# }}}

args = parseOptions().parse_args()

flaat = Flaat()

flaat.set_verbosity(args.verbose)

flaat.set_trusted_OP_list([
'https://b2access.eudat.eu/oauth2/',
'https://b2access-integration.fz-juelich.de/oauth2',
'https://unity.helmholtz-data-federation.de/oauth2/',
'https://unity.eudat-aai.fz-juelich.de/oauth2/',
'https://services.humanbrainproject.eu/oidc/',
'https://accounts.google.com/',
'https://aai.egi.eu/oidc/',
'https://aai-dev.egi.eu/oidc',
'https://login.elixir-czech.org/oidc/',
'https://iam-test.indigo-datacloud.eu/',
'https://iam.deep-hybrid-datacloud.eu/',
'https://iam.extreme-datacloud.eu/',
'https://aai.egi.eu/oidc/',
'https://aai-dev.egi.eu/oidc',
'https://oidc.scc.kit.edu/auth/realms/kit/',
'https://proxy.demo.eduteams.org'
])

# if -in -ui or -at are specified, we set all to false:
if args.show_user_info or args.show_access_token or args.show_introspection_info or args.quiet:
    args.show_all = False

accesstoken_info = flaat.get_info_thats_in_at(args.access_token)
if args.show_access_token or args.show_all:
    if accesstoken_info is None:
        print ('Your access token does not contain information (at least I cannot find it.)\n'\
                'Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong')
    else:
        print('Information stored inside the access token:')
        print(json.dumps(accesstoken_info, sort_keys=True, indent=4, separators=(',', ': ')))
    print('')


user_info = flaat.get_info_from_userinfo_endpoints(args.access_token)
if args.show_user_info or args.show_all:
    if user_info is None:
        print ('The response from the userinfo endpoint does not contain information (at least I cannot find it.)\n'\
                'Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong')
    else:
        print('Information retrieved from userinfo endpoint:')
        print(json.dumps(user_info, sort_keys=True, indent=4, separators=(',', ': ')))
    print('')


if args.client_id:
    flaat.set_client_id(args.client_id)
if args.client_secret:
    flaat.set_client_secret(args.client_secret)
introspection_info = flaat.get_info_from_introspection_endpoints(args.access_token)
if args.show_introspection_info:
    if introspection_info is None:
        print ('The response from the introspection endpoint does not contain information (at least I cannot find it.)\n'\
                'Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong')
    else:
        print('Information retrieved from introspection endpoint:')
        print(json.dumps(introspection_info, sort_keys=True, indent=4, separators=(',', ': ')))
    print('')

timeleft = tokentools.get_timeleft(tokentools.merge_tokens([accesstoken_info,
    user_info, introspection_info]))

if timeleft is not None:
    if timeleft > 0:
        print('Token valid for %.1f more seconds.' % timeleft)
    else:
        print('Your token is already EXPIRED for %.1f seconds!' % abs(timeleft))
    print('')
