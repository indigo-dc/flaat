#!/usr/bin/env python3
'''FLask OIDc AUthentication and authorisation -- FLOIDAU. A set of decorators for authorising
access to OIDC authenticated REST APIs.'''
# pylint # {{{
# vim: tw=100 foldmethod=marker
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace, mixed-indentation
# pylint: disable=redefined-outer-name, logging-not-lazy, logging-format-interpolation
# }}}

import os
import sys
import base64
import re
import fileinput
from functools import wraps
import json
import requests
from flask import request


# FIXME: consider moving non-class functions to a tools package

#defaults; May be overwritten per initialisation of Floidau
verbose = 0
verify_tls = True

def get_access_token_from_request(request):# {{{
    '''Helper function to obtain the OIDC AT from the flask request variable'''
    token = None
    if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
        temp = request.headers['Authorization'].split('authorization header: ')[0]
        token = temp.split(' ')[1]
    if 'access_token' in request.form:
        token = request.form['access_token']
    elif 'access_token' in request.args:
        token = request.args['access_token']
    return token
# }}}
def base64url_encode(data):# {{{
    '''Decode base64 encode data'''
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    encode = base64.urlsafe_b64encode(data)
    return encode.decode('utf-8').rstrip('=')
# }}}
def base64url_decode(data):# {{{
    '''Encode base64 encode data'''
    size = len(data) % 4
    if size == 2:
        data += '=='
    elif size == 3:
        data += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return base64.urlsafe_b64decode(data.encode('utf-8'))
# }}}
def is_url(string):# {{{
    '''Return True if parameter is a URL, otherwise False'''
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, string)
# }}}
def get_accesstoken_info(access_token):# {{{
    '''Return information contained in the access token. Maybe None'''
    try:
        (header_enc, body_enc, signature_enc) = access_token.split('.')
        if verbose >5 :
            print('header_enc: '+str(header_enc))
            print('body_enc: '+str(body_enc))

        header = json.loads(base64url_decode(header_enc))
        body = json.loads(base64url_decode(body_enc))

        if verbose >3 :
            print ('header')
            print(json.dumps(header, sort_keys=True, indent=4, separators=(',', ': ')))
            print ('body')
            print(json.dumps(body, sort_keys=True, indent=4, separators=(',', ': ')))
        return ({'header': header, 'body': body, 'signature': signature_enc})
    except:
        return None
# }}}
def get_issuer_from_accesstoken_info(access_token):# {{{
    '''Return the issuer of the AT, if it can be found, otherwise None'''
    try:
        return get_accesstoken_info(access_token)['body']['iss']
    except ValueError:
        return None
    except TypeError:
        return None
    # }}}

def find_issuer_config_in_at(access_token):# {{{
    '''If there is an issuer in the AT, we fetch the ISS config and return it'''
    iss_config = None
    at_iss = get_issuer_from_accesstoken_info(access_token)
    if verbose > 2:
        print ('got iss from access_token: %s' % str(at_iss))
    if at_iss is not None:
        if is_url(at_iss):
            config_url = at_iss+'/.well-known/openid-configuration'
            iss_config = get_iss_config_from_endpoint(config_url)
    return iss_config
# }}}
def find_issuer_config_in_string(string):# {{{
    '''If the string provided is a URL: try several well known endpoints until the ISS config is
    found'''
    iss_config = None
    if string is not None:
        if is_url(string):
            iss_config = get_iss_config_from_endpoint(string)
            if iss_config:
                return [iss_config]
            iss_config = get_iss_config_from_endpoint(string+'/oauth2')
            if iss_config:
                return [iss_config]
            iss_config = get_iss_config_from_endpoint(string+'/.well-known/openid-configuration')
            if iss_config:
                return [iss_config]
            iss_config = get_iss_config_from_endpoint(string+'/oauth2'+'/.well-known/openid-configuration')
    return iss_config
# }}}
def find_issuer_config_in_list(op_list, op_hint = None):# {{{
    '''find the hinted issuer in configured op_list'''
    iss_config = None
    if op_list:
        iss_config=[]
        for issuer in op_list:
            if op_hint is None:
                issuer_wellknown=issuer.rstrip('/') + '/.well-known/openid-configuration'
                iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
            else:
                if re.search(op_hint, issuer):
                    issuer_wellknown=issuer.rstrip('/') + '/.well-known/openid-configuration'
                    iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
    return iss_config
# }}}
def find_issuer_config_in_file(op_file, op_hint = None):# {{{
    '''find the hinted issuer in a configured, oidc-agent compatible issuers.conf file
    we only use the first (space separated) entry of that file.'''
    iss_config = None
    if op_file:
        iss_config=[]
        for issuer in fileinput.input(op_file):
            issuer_from_conf=issuer.rstrip('\n').split(' ')[0]
            if issuer_from_conf == '':
                continue
            if op_hint is None:
                issuer_wellknown=issuer_from_conf.rstrip('/') + '/.well-known/openid-configuration'
                iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
            else:
                if re.search(op_hint, issuer):
                    issuer_wellknown=issuer_from_conf.rstrip('/') + '/.well-known/openid-configuration'
                    iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
    return iss_config
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

    if verbose:
        print('Getting config from: %s' % config_url)
    resp = requests.get (config_url, verify=verify_tls, headers=headers)
    if verbose > 2:
        print('Getconfig: resp: %s' % resp.status_code)
    try:
        return resp.json()
    except:
        print(str(resp.text))
        return None
# }}}
def get_user_info(access_token, issuer_config):# {{{
    '''Query the userinfo endpoint, using the AT as authentication'''
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    headers['Authorization'] = 'Bearer {0}'.format(access_token)
    if verbose > 2:
        print ('using this access token: %s' % access_token)
    if verbose > 1:
        print('Getting userinfo from %s' % issuer_config['userinfo_endpoint'])
    resp = requests.get (issuer_config['userinfo_endpoint'], verify=verify_tls, headers=headers)
    if resp.status_code != 200:
        if verbose > 2:
            print('userinfo: Error: %s' % resp.status_code)
            print('userinfo: Error: %s' % resp.text)
            print('userinfo: Error: %s' % str(resp.reason))
        return None
        # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})

    resp_json=resp.json()
    if verbose:
        print('Success')
    if verbose>1:
        print(json.dumps(resp_json, sort_keys=True, indent=4, separators=(',', ': ')))
    if verbose > 2:
        print('userinfo: resp: %s' % resp.status_code)
    return resp_json
# }}}
def get_introspected_token_info(access_token, issuer_config, client_id=None, client_secret=None):# {{{
    '''Query te token introspection endpoint, if there is a client_id and client_secret set'''
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}

    post_data = {'token': access_token}

    if client_id is None or client_secret is None:
        if verbose > 1:
            print ('You need to specify client_id and client_secret to query the introspection endpoint')
        return None

    if client_secret in ['', None]:
        basic_auth_string = '%s' % (client_id)
    else:
        basic_auth_string = '%s:%s' % (client_id, client_secret)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')

    headers['Authorization'] = 'Basic %s' % base64.b64encode(basic_auth_bytes).decode('utf-8')

    if verbose > 1:
        print('Getting introspection from %s' % issuer_config['userinfo_endpoint'])
    try:
        resp = requests.post (issuer_config['introspection_endpoint'], \
                              verify=verify_tls, headers=headers, data=post_data)
    except KeyError: # no introspection_endpoint found
        return None

    if verbose>2:
        print('introspect: resp: %s' % resp.status_code)
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
            print('Introspect: Error: %s' % resp.status_code)
            print('Introspect: Error: %s' % resp.text)
            print('Introspect: Error: %s' % str(resp.text))
            print('Introspect: Error: %s' % str(resp.reason))
            # return ({'error': '{}: {}'.format(resp.status_code, resp.reason)})
            return None

    return(resp.json())
# }}}
def merge_tokens(tokenlist):# {{{
    '''put all provided none None tokens into one token.'''
    supertoken={}
    for entry in tokenlist:
        try:
            for key in entry.keys():
                supertoken[key]=entry[key]
        except AttributeError:
            pass
    if supertoken == {}:
        return None
    return supertoken
# }}}

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

class Floidau():# {{{
    '''FLask OIDc AUthentication and Authorisation.
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
        '''Verbosity level of floidau:
           0: No output
           1: Errors
           2: More info, including token info
           3: Max'''
        self.verbose=level
    def set_verify_tls(self, verify_tls=True):
        '''Whether to verify tls connections. Only use for development and debugging'''
        self.verify_tls = verify_tls
    def set_client_id(self, client_id):
        '''Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now.'''
        # FIXME: client_id/client_secret per OP.
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
        iss_config = find_issuer_config_in_at(access_token)
        if iss_config is not None:
            return [iss_config]

        # 2: use a provided string
        if self.verbose > 1:
            print ('Trying to find issuer from "set_iss"')
        iss_config = find_issuer_config_in_string(self.iss)
        if iss_config is not None:
            return [iss_config]

        # 3: Try the provided list of providers:
        if self.verbose > 1:
            print ('Trying to find issuer from "set_OIDC_provider_list"')
        iss_config = find_issuer_config_in_list(self.op_list, self.op_hint)
        if iss_config is not None:
            return iss_config

        # 4: Try oidc-agent's issuer config file
        if self.verbose > 1:
            print ('Trying to find issuer from "set_OIDC_provider_file"')
        iss_config = find_issuer_config_in_file(self.op_file, self.op_hint)
        if iss_config is not None:
            return iss_config

        return None
    # }}}
    def _get_all_info(self, request):# {{{
        '''gather all info about the user that we can find.
        Returns a "supertoken" json structure.'''

        access_token = get_access_token_from_request(request)
        # get all possible issuer configs{{{
        issuer_configs = self._find_issuer_config_everywhere(access_token)
        accesstoken_info = get_accesstoken_info(access_token)
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
            return merge_tokens([at_head, at_body])

        # get userinfo{{{
        for issuer_config in issuer_configs:
            user_info = get_user_info(access_token, issuer_config)
            if user_info is not None:
                break
        # }}}

        # get introspection_token{{{
        for issuer_config in issuer_configs:
            introspection_info = get_introspected_token_info(access_token, issuer_config,
                self.client_id, self.client_secret)
            if introspection_info is not None:
                break
        # }}}

        supertoken = merge_tokens ([at_head, at_body, user_info, introspection_info])

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
