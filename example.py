#!/usr/bin/env python3
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace, missing-docstring
# }}}
from flask import Flask
from flat import Flat


##########
# Basic config
app=Flask(__name__)
app.config.SWAGGER_UI_DOC_EXPANSION = 'list'

flat = Flat()

# flat.
#TODO: Caching
# flat.set_OP('https://unity.helmholtz-data-federation.de/oauth2/')
flat.set_OP_list([
'https://b2access.eudat.eu/oauth2/',
'https://b2access-integration.fz-juelich.de/oauth2',
'https://unity.helmholtz-data-federation.de/oauth2/',
'https://unity.eudat-aai.fz-juelich.de/oauth2/',
'https://services.humanbrainproject.eu/oidc/',
'https://accounts.google.com/',
'https://aai.egi.eu/oidc/',
'https://aai-dev.egi.eu/oidc',
'https://login.elixir-czech.org/oidc/'
])
# flat.set_OP_file('/etc/oidc-agent/issuer.config')
flat.set_OP_hint("helmholtz")
# flat.set_OP_hint("google")

# verbosity:
#     0: No output
#     1: Errors
#     2: More info, including token info
#     3: Max
flat.set_verbosity(2)
# flat.set_verify_tls(True)
# # Required for using token introspection endpoint

# flat.set_client_id('')
# flat.set_client_secret('')


def my_failure_callback():
    return 'Failed login, caught by my own failure function'

@app.route('/valid_user')
@flat.login_required(on_failure=my_failure_callback())
def demo_login():
    return('This worked: there was a valid login')

@app.route('/group_test_kit')
@flat.group_required(group=['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
        claim='eduperson_scoped_affiliation', match=2)
def demo_groups_kit():
    return('This worked: user is member of the requested group')

@app.route('/group_test_iam')
@flat.group_required(group='KIT-Cloud', claim='groups')
def demo_groups_iam():
    return('This worked: user is member of the requested group')

@app.route('/group_test_hdf')
@flat.aarc_g002_group_required(group=['urn:geant:h-df.de:group:aai-admin',
        'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
        claim='eduperson_entitlement', match='all')
def demo_groups_hdf():
    return('This worked: user is member of the requested group')


##########
# Main / Boilerplate
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
