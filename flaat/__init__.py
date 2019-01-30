'''FLAsk support for OIDC Access Tokens -- FLAAT. A set of decorators for authorising
access to OIDC authenticated REST APIs.'''
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# pylint: disable=logging-not-lazy, logging-format-interpolation
# }}}

import os
import sys
from functools import wraps
import json
from flask import request

from . import tokentools
from . import issuertools

name = "flaat"

#defaults; May be overwritten per initialisation of flaat
verbose = 0
verify_tls = True


def aarc_g002_split(groupspec):# {{{
    '''return namespace, group, authority'''
    (namespace, tmp) = groupspec.split(':group:')
    try:
        (group_hierarchy, authority) = tmp.split('#')
    except ValueError:
        authority=None
        group_hierarchy = tmp
    return(namespace, group_hierarchy, authority)
# }}}
def aarc_g002_split_roles(groupspec):# {{{
    '''return group and roles'''
    group = None
    role  = None
    try:
        (group, role) = groupspec.split(':role=')
    except ValueError: # no roles found
        group = groupspec
    return (group, role)
# }}}
def aarc_g002_matcher(required_group, actual_group):# {{{
    ''' match if user is in subgroup, but not in supergroup
    match if Authority is different.
    This should comply to https://aarc-project.eu/guidelines/aarc-g002/'''
    #pylint: disable=too-many-return-statements,consider-using-enumerate

    (act_namespace, act_group_role, act_authority) = aarc_g002_split(actual_group)
    (req_namespace, req_group_role, req_authority) = aarc_g002_split(required_group)

    # Finish the two easy cases

    if act_namespace != req_namespace:
        return False

    if act_group_role == req_group_role:
        return True

    # Interesting cases:
    (act_group, act_role) = aarc_g002_split_roles(act_group_role)
    (req_group, req_role) = aarc_g002_split_roles(req_group_role)

    if act_group == req_group:
        if req_role is None:
            return True
        if act_role is None:
            return False
        if act_role == req_role:
            return True
        if act_role != req_role:
            return False
        return 'Error, unreachable code'

    act_group_tree = act_group.split(':')
    req_group_tree = req_group.split(':')

    # print (json.dumps(locals(), sort_keys=True, indent=4, separators=(',', ': ')))
    try:
        for i in range(0,len(req_group_tree)):
            if act_group_tree[i] != req_group_tree[i]: # wrong group name
                return False
    except IndexError: # user not in subgroup:
        return False

    return True
# }}}

class Flaat():# {{{
    '''FLAsk OIDc AUthentication and Authorisation.
    Provide decorators and configuration for OIDC'''
    # pylint: disable=too-many-instance-attributes
    def __init__(self):# {{{
        self.op_list       = None
        self.iss           = None
        self.op_hint       = None
        self.op_file       = None
        self.verbose       = 0
        self.verify_tls    = True
        self.client_id     = None
        self.client_secret = None

    def set_OP(self, iss):
        '''Define OIDC Provider. Must be a valid URL. E.g. 'https://aai.egi.eu/oidc/'
        This should not be required for OPs that put their address into the AT (e.g. keycloak, mitre,
        shibboleth)'''
        self.iss = iss
    def set_OP_list(self, op_list):
        '''Define a list of OIDC provider URLs.
            E.g. ['https://iam.deep-hybrid-datacloud.eu/', 'https://login.helmholtz-data-federation.de/oauth2/', 'https://aai.egi.eu/oidc/'] '''
        self.op_list = op_list
    def set_OP_file(self, filename='/etc/oidc-agent/issuer.config', hint=None):
        '''Set filename of oidc-agent's issuer.config. Requires oidc-agent to be installed.'''
        self.op_file = filename
        self.op_hint = hint
    def set_OP_hint(self, hint):
        '''String to specify the hint. This is used for regex searching in lists of providers for
        possible matching ones.'''
        self.op_hint = hint
    def set_verbosity(self, level):
        '''Verbosity level of flaat:
           0: No output
           1: Errors
           2: More info, including token info
           3: Max'''
        self.verbose        = level
        tokentools.verbose  = level
        issuertools.verbose = level
    def set_verify_tls(self, param_verify_tls=True):
        '''Whether to verify tls connections. Only use for development and debugging'''
        self.verify_tls        = param_verify_tls
        tokentools.verify_tls  = level
        issuertools.verify_tls = level
    def set_client_id(self, client_id):
        '''Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now.'''
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id
    def set_client_secret(self, client_secret):
        '''Client Secret. At the moment this one is sent to all matching providers.'''
        self.client_secret = client_secret

# }}}
    def _find_issuer_config_everywhere(self, access_token):# {{{
        '''Use many places to find issuer configs'''
        # 1: find info in the AT
        if self.verbose > 1:
            print ('Trying to find issuer in accesstoken')
        iss_config = issuertools.find_issuer_config_in_at(access_token)
        if iss_config is not None:
            return [iss_config]

        # 2: use a provided string
        if self.verbose > 1:
            print ('Trying to find issuer from "set_iss"')
        iss_config = issuertools.find_issuer_config_in_string(self.iss)
        if iss_config is not None:
            return [iss_config]

        # 3: Try the provided list of providers:
        if self.verbose > 1:
            print ('Trying to find issuer from "set_OIDC_provider_list"')
        iss_config = issuertools.find_issuer_config_in_list(self.op_list, self.op_hint)
        if iss_config is not None:
            return iss_config

        # 4: Try oidc-agent's issuer config file
        if self.verbose > 1:
            print ('Trying to find issuer from "set_OIDC_provider_file"')
        iss_config = issuertools.find_issuer_config_in_file(self.op_file, self.op_hint)
        if iss_config is not None:
            return iss_config

        return None
    # }}}
    def _get_all_info(self, param_request):# {{{
        '''gather all info about the user that we can find.
        Returns a "supertoken" json structure.'''

        access_token = tokentools.get_access_token_from_request(param_request)
        # get all possible issuer configs{{{
        issuer_configs = self._find_issuer_config_everywhere(access_token)
        accesstoken_info = tokentools.get_accesstoken_info(access_token)
        at_head=None
        at_body=None
        if accesstoken_info is not None and not {}:
            at_head = accesstoken_info['header']
            at_body = accesstoken_info['body']
            # now = time.time()
            # timeleft = accesstoken_info['body']['exp'] - now
        # }}}

        if issuer_configs is None:
            if self.verbose:
                print('No issuer config found, returning accesstoken info, only')
            return tokentools.merge_tokens([at_head, at_body])

        # get userinfo{{{
        for issuer_config in issuer_configs:
            user_info = issuertools.get_user_info(access_token, issuer_config)
            if user_info is not None:
                break
        # }}}

        # get introspection_token{{{
        for issuer_config in issuer_configs:
            introspection_info = issuertools.get_introspected_token_info(access_token, issuer_config,
                self.client_id, self.client_secret)
            if introspection_info is not None:
                break
        # }}}

        supertoken = tokentools.merge_tokens ([at_head, at_body, user_info, introspection_info])

        return supertoken
    # }}}

    def login_required(self, on_failure=None):# {{{
        '''Decorator to enforce a valid login.
        Optional on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                all_info = self._get_all_info(request)
                if all_info is not None:
                    if self.verbose>1:
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                    return view_func(*args, **kwargs)
                if on_failure:
                    return on_failure
                return ('No valid authentication found.')
            return decorated
        return wrapper
# }}}
    def group_required(self, group=None, claim=None, on_failure=None, match='all'):# {{{
        '''Decorator to enforce membership in a given group.
        group is the name (or list) of the group to match
        match specifies how many of the given groups must be matched. Valid values for match are
            'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                user_message = 'Not enough required group memberships found.'
                all_info = self._get_all_info(request)
                if all_info is None:
                    if on_failure:
                        return on_failure
                    return ('No valid authentication found.')

                # Make sure we have a list:
                if isinstance(group, str):
                    req_group_list = [group]
                else:
                    req_group_list = group

                # How many matches do we need?
                if match == 'all':
                    required_matches = len(req_group_list)
                if match == 'one':
                    required_matches = 1
                if isinstance (match, int):
                    required_matches = match
                if required_matches > len(req_group_list):
                    required_matches = len(req_group_list)

                if not required_matches:
                    print('Error interpreting the "match" parameter')
                    return('Error interpreting the "match" parameter')

                if self.verbose>1:
                    print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                # copy entries from incoming claim
                avail_group_entries = []
                try:
                    avail_group_entries = all_info[claim]
                except KeyError:
                    user_message = 'Claim does not exist: "%s".' % claim
                    if self.verbose:
                        print ('Claim does not exist: "%s".' % claim)
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                if not isinstance(avail_group_entries, list):
                    user_message = 'Claim does not point to a list: "%s".' % avail_group_entries
                    if self.verbose:
                        print ('Claim does not exist: "%s".' % avail_group_entries)
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))

                # now we do the actual checking
                matches_found = 0
                for entry in avail_group_entries:
                    for g in req_group_list:
                        if entry == g:
                            matches_found += 1
                if self.verbose > 0:
                    print('found %d of %d matches' % (matches_found, required_matches))
                if matches_found >= required_matches:
                    return view_func(*args, **kwargs)

                # Either we returned above or there was no matching group
                if on_failure:
                    return on_failure
                return (user_message)
            return decorated
        return wrapper
# }}}
    def aarc_g002_group_required(self, group=None, claim=None, on_failure=None, match='all'):# {{{
        '''Decorator to enforce membership in a given group defined according to AARC-G002.
        group is the name (or list) of the group to match
        match specifies how many of the given groups must be matched. Valid values for match are
            'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                user_message = 'Not enough required group memberships found.'
                all_info = self._get_all_info(request)
                if all_info is None:
                    if on_failure:
                        return on_failure
                    return ('No valid authentication found.')

                # Make sure we have a list:
                if isinstance(group, str):
                    req_group_list = [group]
                else:
                    req_group_list = group

                # How many matches do we need?
                if match == 'all':
                    required_matches = len(req_group_list)
                if match == 'one':
                    required_matches = 1
                if isinstance (match, int):
                    required_matches = match
                if required_matches > len(req_group_list):
                    required_matches = len(req_group_list)

                if not required_matches:
                    print('Error interpreting the "match" parameter')
                    return('Error interpreting the "match" parameter')

                if self.verbose>1:
                    print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                # actual check for group membership:
                avail_group_entries = []
                try:
                    avail_group_entries = all_info[claim]
                except KeyError:
                    user_message = 'Claim does not exist: "%s".' % claim
                    if self.verbose:
                        print ('Claim does not exist: "%s".' % claim)
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                if not isinstance(avail_group_entries, list):
                    user_message = 'Claim does not point to a list: "%s".' % avail_group_entries
                    if self.verbose:
                        print ('Claim does not exist: "%s".' % avail_group_entries)
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))

                # now we do the actual checking
                matches_found = 0
                for entry in avail_group_entries:
                    for g in req_group_list:
                        if aarc_g002_matcher(required_group=g, actual_group=entry):
                            matches_found += 1
                if self.verbose > 0:
                    print('found %d of %d matches' % (matches_found, required_matches))
                if matches_found >= required_matches:
                    return view_func(*args, **kwargs)

                # Either we returned above or there was no matching group
                if on_failure:
                    return on_failure
                return (user_message)
            return decorated
        return wrapper
# }}}
# }}}
