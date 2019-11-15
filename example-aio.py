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
# pylint: disable=bad-whitespace, missing-docstring
# }}}
import os
import logging
from flaat import Flaat
from flask import request
from flaat import tokentools
import json
from aiohttp import web

logformat='[%(levelname)s] %(message)s'
logformat='[%(levelname)s] [%(filename)s:%(funcName)s:%(lineno)d] %(message)s'
logging.basicConfig(level=os.environ.get("LOG", "INFO"), format = logformat)

logger = logging.getLogger(__name__)


##########
## Basic config
# AIOHTTP
app = web.Application()
routes = web.RouteTableDef()

# FLAAT
flaat = Flaat()

flaat.set_web_framework('aiohttp')
flaat.set_cache_lifetime(120) # seconds; default is 300
flaat.set_trusted_OP_list([
'https://b2access.eudat.eu/oauth2/',
'https://b2access-integration.fz-juelich.de/oauth2',
'https://unity.helmholtz-data-federation.de/oauth2/',
'https://login.helmholtz-data-federation.de/oauth2/',
'https://unity.eudat-aai.fz-juelich.de/oauth2/',
'https://services.humanbrainproject.eu/oidc/',
'https://accounts.google.com/',
'https://login.elixir-czech.org/oidc/',
'https://iam-test.indigo-datacloud.eu/',
'https://iam.deep-hybrid-datacloud.eu/',
'https://iam.extreme-datacloud.eu/',
'https://aai.egi.eu/oidc/',
'https://aai-dev.egi.eu/oidc',
'https://oidc.scc.kit.edu/auth/realms/kit/',
'https://proxy.demo.eduteams.org'
])
# flaat.set_trusted_OP_file('/etc/oidc-agent/issuer.config')
# flaat.set_OP_hint("helmholtz")
# flaat.set_OP_hint("google")

# verbosity:
#     0: No output
#     1: Errors
#     2: More info, including token info
#     3: Max
flaat.set_verbosity(1)
# flaat.set_verify_tls(True)


# # Required for using token introspection endpoint:
# flaat.set_client_id('')
# flaat.set_client_secret('')


def my_failure_callback(message=''):
    return 'User define failure callback.\nError Message: "%s"' % message

@routes.get('/info')
async def info(request):
    access_token = tokentools.get_access_token_from_request(request)
    info = flaat.get_info_thats_in_at(access_token)
    # FIXME: Also display info from userinfo endpoint
    x = json.dumps(info, sort_keys=True, indent=4, separators=(',', ': '))
    return web.Response(text=str(x))

@routes.get('/valid_user')
@flaat.login_required()
async def valid_user(request):
    return web.Response(text='This worked: there was a valid login')

@routes.get('/valid_user_2')
@flaat.login_required(on_failure=my_failure_callback)
async def valid_user_own_callback(request):
    return web.Response(text='This worked: there was a valid login')

@routes.get('/group_test_kit')
@flaat.group_required(group=['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
        claim='eduperson_scoped_affiliation', match=2,
        on_failure=my_failure_callback)
async def demo_groups_kit(request):
    return web.Response(text='This worked: user is member of the requested group')

@routes.get('/group_test_iam')
@flaat.group_required(group='KIT-Cloud', claim='groups')
async def demo_groups_iam(request):
    return web.Response(text='This worked: user is member of the requested group')

@routes.get('/group_test_hdf')
@flaat.aarc_g002_group_required(group=['urn:geant:h-df.de:group:aai-admin',
        'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
        claim='eduperson_entitlement', match='all')
async def demo_groups_hdf(request):
    return web.Response(text='This worked: user has the required entitlement(s)')

app.add_routes(routes)

##########
# Main

if __name__ == '__main__':
    web.run_app(app, host="0.0.0.0", port=8080)
