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
# pylint: disable=logging-not-lazy, logging-format-interpolation, logging-fstring-interpolation
# }}}
import os
import logging
from flask import Flask
from flaat import Flaat
from flask import request
from flaat import tokentools
import json

logformat='[%(levelname)s] %(message)s'
logformat='[%(levelname)s] [%(filename)s:%(funcName)s:%(lineno)d] %(message)s'
logging.basicConfig(level=os.environ.get("LOG", "INFO"), format = logformat)

logger = logging.getLogger(__name__)


##########
## Basic config
# FLASK 
app=Flask(__name__)

# FLAAT
flaat = Flaat()

flaat.set_web_framework('flask')
flaat.set_cache_lifetime(120) # seconds; default is 300
flaat.set_trusted_OP_list([
'https://b2access.eudat.eu/oauth2/',
'https://b2access-integration.fz-juelich.de/oauth2',
'https://login-dev.helmholtz.de/oauth2/',
'https://login.helmholtz.de/oauth2/',
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
flaat.set_verbosity(2)
# flaat.set_verify_tls(True)


# # Required for using token introspection endpoint:
# flaat.set_client_id('')
# flaat.set_client_secret('')


def my_failure_callback(message=''):
    return 'User define failure callback.\nError Message: "%s"' % message

@app.route('/')
def root():
    text = '''This is an example for useing flaat with AIO. These endpoints are available:
    /info               General info about the access_token (if provided)
    /valid_user         Requires a valid user
    /valid_user_2       Requires a valid user, uses a custom callback on error
    /group_test_kit     Requires user to have two "eduperson_scoped_affiliation" of
                            ['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
    /group_test_iam     Requires user to be in the group "KIT-Cloud" transported in "groups"
    /group_test_hdf     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:aai-admin', 'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de']

    /group_test_hdf2     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
    /group_test_hdf3     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:aai-admin'],
        '''
    return (text)

@app.route('/info')
def info():
    access_token = tokentools.get_access_token_from_request(request)
    info = flaat.get_info_thats_in_at(access_token)
    # FIXME: Also display info from userinfo endpoint
    x = json.dumps(info, sort_keys=True, indent=4, separators=(',', ': '))
    return(str(x))
    return("yeah")

@app.route('/valid_user/<int:id>', methods=['POST', 'GET'])
@flaat.login_required()
def valid_user_id(id):
    retval = ""
    if request.method == 'POST':
        retval += "POST\n"
    if request.method == 'GET':
        retval += "GET\n"
    retval += F'This worked: there was a valid login, and an id: {id}\n'
    return (retval)

@app.route('/valid_user')
@flaat.login_required()
def valid_user():
    return('This worked: there was a valid login\n')

@app.route('/valid_user_2')
@flaat.login_required(on_failure=my_failure_callback)
def valid_user_own_callback():
    return('This worked: there was a valid login')

@app.route('/valid_user_3')
@flaat.login_required(on_failure=my_failure_callback)
def valid_user_no_param(**kwargs):
    logger.info("(**kwargs) - kwargs: %s" % (kwargs))
    return ('This worked: there was a valid login')

@app.route('/group_test_kit')
@flaat.group_required(group=['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
        claim='eduperson_scoped_affiliation', match=2,
        on_failure=my_failure_callback)
def demo_groups_kit():
    return('This worked: user is member of the requested group')

@app.route('/group_test_iam')
@flaat.group_required(group='KIT-Cloud', claim='groups')
def demo_groups_iam():
    return('This worked: user is member of the requested group')

@app.route('/group_test_hdf')
@flaat.aarc_g002_group_required(group=['urn:geant:h-df.de:group:aai-admin',
        'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
        claim='eduperson_entitlement', match='all')
def demo_groups_hdf():
    return('This worked: user is member of the requested group')

@app.route('/group_test_hdf2')
@flaat.aarc_g002_group_required(group=[
        'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
        claim='eduperson_entitlement', match='all')
def demo_groups_hdf2():
    return('This worked: user is member of the requested group')

@app.route('/group_test_hdf3')
@flaat.aarc_g002_group_required(group=['urn:geant:h-df.de:group:aai-admin'],
        claim='eduperson_entitlement', match='all')
def demo_groups_hdf3():
    return('This worked: user is member of the requested group')


##########
# Main
if __name__ == '__main__':
    # app.run(host="127.0.0.1", port=8081, debug=True)
    app.run(host="0.0.0.0", port=8080, debug=True)
