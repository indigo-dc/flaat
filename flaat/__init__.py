'''FLAsk support for OIDC Access Tokens -- FLAAT. A set of decorators for authorising
access to OIDC authenticated REST APIs.'''
# This code is distributed under the MIT License
# pylint
# vim: tw=100 foldmethod=indent
# pylint: disable=invalid-name, superfluous-parens
# pylint: disable=logging-not-lazy, logging-format-interpolation, logging-fstring-interpolation
# pylint: disable=wrong-import-position, no-self-use, line-too-long


from functools import wraps
import json
import os
import sys
is_py2 = sys.version[0] == '2'
if is_py2:
    # pylint: disable=import-error
    from Queue import Queue, Empty
else:
    from queue import Queue, Empty
from threading import Thread
import logging

from flask import request
from aiohttp import web
from aarc_g002_entitlement import Aarc_g002_entitlement
from . import tokentools
from . import issuertools
from . import flaat_exceptions

logger = logging.getLogger(__name__)

name = "flaat"

#defaults; May be overwritten per initialisation of flaat
verbose = 0
verify_tls = True

def ensure_is_list(item):
    '''Make sure we have a list'''
    if isinstance(item, str):
        return [item]
    return item

class Flaat():
    '''FLAsk support for OIDC Access Tokens.
    Provide decorators and configuration for OIDC'''
    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.trusted_op_list = None
        self.iss             = None
        self.op_hint         = None
        self.trusted_op_file = None
        self.verbose         = 0
        self.verify_tls      = True
        self.client_id       = None
        self.client_secret   = None
        self.last_error      = ''
        self.num_request_workers = 10
        self.client_connect_timeout = 1.2 # seconds
        self.ops_that_support_jwt = \
                    [ 'https://iam-test.indigo-datacloud.eu/',
                      'https://iam.deep-hybrid-datacloud.eu/',
                      'https://iam.extreme-datacloud.eu/',
                      'https://aai.egi.eu/oidc/',
                      'https://aai-dev.egi.eu/oidc',
                      'https://login-dev.helmholtz.de/oauth2/',
                      'https://login.helmholtz.de/oauth2/',
                      'https://oidc.scc.kit.edu/auth/realms/kit/']
        # unknown:
        # 'https://login.elixir-czech.org/oidc/',
        # 'https://services.humanbrainproject.eu/oidc/',
        self.supported_web_frameworks = ['flask', 'aiohttp']
        self.web_framework = 'flask'
        self.raise_error_on_return = True # else just return an error
    def set_cache_lifetime(self, lifetime):
        '''Set cache lifetime of requests_cache zn seconds, default: 300s'''
        issuertools.cache_options.set_lifetime(lifetime)
    def set_cache_allowable_codes(self, allowable_codes):
        '''set http status code that will be cached'''
        issuertools.cache_options.set_allowable_codes(allowable_codes)
    def set_cache_backend(self, backend):
        '''set the cache backend'''
        issuertools.cache_options.backend = backend
    def set_trusted_OP(self, iss):
        '''Define OIDC Provider. Must be a valid URL. E.g. 'https://aai.egi.eu/oidc/'
        This should not be required for OPs that put their address into the AT (e.g. keycloak, mitre,
        shibboleth)'''
        self.iss = iss.rstrip('/')
    def set_trusted_OP_list(self, trusted_op_list):
        '''Define a list of OIDC provider URLs.
            E.g. ['https://iam.deep-hybrid-datacloud.eu/', 'https://login.helmholtz.de/oauth2/', 'https://aai.egi.eu/oidc/'] '''
        self.trusted_op_list = []
        for issuer in trusted_op_list:
            self.trusted_op_list.append(issuer.rstrip('/'))
    def set_trusted_OP_file(self, filename='/etc/oidc-agent/issuer.config', hint=None):
        '''Set filename of oidc-agent's issuer.config. Requires oidc-agent to be installed.'''
        self.trusted_op_file = filename
        self.op_hint         = hint
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
        issuertools.verify_tls = param_verify_tls
    def set_client_id(self, client_id):
        '''Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now.'''
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id
    def set_client_secret(self, client_secret):
        '''Client Secret. At the moment this one is sent to all matching providers.'''
        self.client_secret = client_secret
    def set_last_error(self, error):
        '''Store an error message'''
        self.last_error = error
    def get_last_error(self):
        '''Retrieve and clear the error message'''
        retval = self.last_error
        self.last_error = ''
        return retval
    def set_num_request_workers(self, num):
        '''set number of request workers'''
        self.num_request_workers = num
        issuertools.num_request_workers = num
    def get_num_request_workers(self):
        '''get number of request workers'''
        return (self.num_request_workers)
    def set_client_connect_timeout(self, num):
        '''set timeout for flaat connecting to OPs'''
        self.client_connect_timeout = num
    def get_client_connect_timeout(self):
        '''get timeout for flaat connecting to OPs'''
        return (self.client_connect_timeout)
    def set_iss_config_timeout(self, num):
        '''set timeout for connections to get config from OP'''
        issuertools.timeout = num
    def get_iss_config_timeout(self):
        '''set timeout for connections to get config from OP'''
        return (issuertools.timeout)
    def set_timeout(self, num):
        '''set global timeouts for http connections'''
        self.set_iss_config_timeout(num)
        self.set_client_connect_timeout(num)
    def get_timeout(self):
        '''get global timeout for https connections'''
        return (self.timeout)

    def set_web_framework(self, framework_name):
        '''specify the web framework. Currently supported are 'flaat' and 'aiohttp' '''
        if framework_name in self.supported_web_frameworks:
            self.web_framework = framework_name
        else:
            logger.error("Specified Web Framework '%s' is not supported" % framework_name)
            sys.exit (42)
    def _find_issuer_config_everywhere(self, access_token):
        '''Use many places to find issuer configs'''

        # 1: find info in the AT
        at_iss = tokentools.get_issuer_from_accesstoken_info(access_token)
        if at_iss is not None:
            trusted_op_list_buf = []
            if self.trusted_op_list is not None:
                if len(self.trusted_op_list) >0:
                    trusted_op_list_buf = self.trusted_op_list
            if self.iss is not None:
                trusted_op_list_buf.append(self.iss)
            if at_iss.rstrip('/') not in trusted_op_list_buf:
                logger.warning(F'The issuer {at_iss} of the received access_token is not trusted')
                self.set_last_error(F'The issuer {at_iss} of the received access_token is not trusted')
                # newline="\n"
                # logger.warning(F"list: {newline.join(trusted_op_list_buf)}")
                return None

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
            print ('Trying to find issuer from trusted_op_list')
        iss_config = issuertools.find_issuer_config_in_list(self.trusted_op_list, self.op_hint,
                exclude_list = self.ops_that_support_jwt)
        if iss_config is not None:
            return iss_config

        # 4: Try oidc-agent's issuer config file
        if self.verbose > 1:
            print ('Trying to find issuer from "set_OIDC_provider_file"')
        iss_config = issuertools.find_issuer_config_in_file(self.trusted_op_file, self.op_hint,
                exclude_list = self.ops_that_support_jwt)
        if iss_config is not None:
            return iss_config

        self.set_last_error("Issuer config not found")
        return None
    # def verify_at_is_from_truested_iss(self, access_token):
    #     '''verify that the AT is issued by a trusted issuer'''
    def get_info_thats_in_at(self, access_token):
        # FIXME: Add here parameter verify=True, then go and verify the token
        '''return the information contained inside the access_token itself'''
        # '''analyse access_token and return info'''
        accesstoken_info = None
        if access_token:
            accesstoken_info = tokentools.get_accesstoken_info(access_token)
        # at_head=None
        # at_body=None
        # if accesstoken_info is not None and not {}:
        #     at_head = accesstoken_info['header']
        #     at_body = accesstoken_info['body']
        # return (at_head, at_body)
        return (accesstoken_info)
    def get_info_from_userinfo_endpoints(self, access_token):
        '''Traverse all reasonable configured userinfo endpoints and query them with the
        access_token. Note: For OPs that include the iss inside the AT, they will be directly
        queried, and are not included in the search (because that makes no sense).
        Returns user_info object or None.  If None is returned self.last_error is set with a
        meaningful message.'''
        # user_info = "" # return value
        user_info = None # return value

        # get all possible issuer configs
        issuer_configs = self._find_issuer_config_everywhere(access_token)
        if issuer_configs is None or len(issuer_configs) == 0 :
            logger.warning('No issuer config found, or issuer not supported')
            return None

        # get userinfo
        param_q  = Queue(self.num_request_workers*2)
        result_q = Queue(self.num_request_workers*2)

        def thread_worker_get_userinfo():
            '''Thread worker'''
            while True:
                item = param_q.get()
                if item is None:
                    break
                result = issuertools.get_user_info(item['access_token'], item['issuer_config'])
                result_q.put(result)
                param_q.task_done()
                result_q.task_done()

        for i in range (self.num_request_workers):
            t = Thread(target=thread_worker_get_userinfo)
            t.daemon = True
            t.start()

        logger.debug (F"len of issuer_configs: {len(issuer_configs)}")
        for issuer_config in issuer_configs:
            # user_info = issuertools.get_user_info(access_token, issuer_config)
            params = {}
            params['access_token'] = access_token
            params['issuer_config'] = issuer_config
            param_q.put(params)
        param_q.join()
        result_q.join()
        try:
            while not result_q.empty():
                user_info = result_q.get(block=False, timeout=self.client_connect_timeout)
                if user_info is not None:
                    return (user_info)
        except Empty:
            logger.info("EMPTY result in thead join")
            # pass
        except Exception as e:
            logger.info("Error: Uncaught Exception: {}".format(str(e)))
        if user_info is None:
            self.set_last_error ("User Info not found or not accessible. Something may be wrong with the Access Token.")
        return(user_info)
    def get_info_from_introspection_endpoints(self, access_token):
        '''If there's a client_id and client_secret defined, we access the token introspection
        endpoint and return the info obtained from there'''
        # get introspection_token
        introspection_info = None
        issuer_configs = self._find_issuer_config_everywhere(access_token)
        if issuer_configs is None:
            logger.info("Issuer Configs yielded None")
            self.set_last_error("Issuer of Access Token is not supported")
            return None
        for issuer_config in issuer_configs:
            introspection_info = issuertools.get_introspected_token_info(access_token, issuer_config,
                self.client_id, self.client_secret)
            if introspection_info is not None:
                break
        return(introspection_info)
    def get_all_info_by_at(self, access_token):
        '''Collect all possible user info and return them as one json
        object.'''
        if access_token is None:
            self.set_last_error('No access token found')
            return None

        accesstoken_info   = self.get_info_thats_in_at(access_token)
        user_info          = self.get_info_from_userinfo_endpoints(access_token)
        introspection_info = self.get_info_from_introspection_endpoints(access_token)
        # FIXME: We have to verify the accesstoken
        # And verify that it comes from a trusted issuer!!

        if accesstoken_info is not None:
            timeleft = tokentools.get_timeleft(accesstoken_info)

            if timeleft < 0:
                # print ('\n\n: TIMELEFT: %d' % timeleft)
                self.set_last_error('Token expired for %d seconds' % abs(timeleft))
                return None

        if user_info is None:
            return None

        # return tokentools.merge_tokens ([accesstoken_info['header'], accesstoken_info['body'], user_info, introspection_info])
        return tokentools.merge_tokens ([accesstoken_info, user_info, introspection_info])
    def _find_request_based_on_web_framework(self, request, args):
        '''use configured web_framework and return the actual request object'''
        if self.web_framework == 'flask':
            return request
        if self.web_framework == 'aiohttp':
            return args[0]
        return None
    def _return_formatter_wf(self, return_value, status=200):
        '''Return the object appropriate for the chosen web framework'''
        if self.raise_error_on_return:
            if self.web_framework == 'flask':
                raise flaat_exceptions.FlaatExceptionFlask(reason=return_value, status_code=status)
            if self.web_framework == 'aiohttp':
                raise flaat_exceptions.FlaatExceptionAio(reason=return_value, status_code=status)
        else:
            if self.web_framework == 'flask':
                return (return_value, status)
            if self.web_framework == 'aiohttp':
                return web.Response(text=return_value, status=status)
        return None
    def _get_all_info_from_request(self, param_request):
        '''gather all info about the user that we can find.
        Returns a "supertoken" json structure.'''
        access_token = tokentools.get_access_token_from_request(param_request)
        if access_token is None:
            self.set_last_error("No Access Token Found.")
            return None
        # logger.info (F"access_token: {access_token}")
        return self.get_all_info_by_at(access_token)
    def login_required(self, on_failure=None):
        '''Decorator to enforce a valid login.
        Optional on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                try:
                    if os.environ['DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER'].lower() == 'yes':
                        return view_func(*args, **kwargs)
                except KeyError: # i.e. the environment variable was not set
                    pass
                request_object = self._find_request_based_on_web_framework(request, args)
                all_info = self._get_all_info_from_request(request_object)
                # logger.info (F"all info: {all_info}")

                if all_info is not None:
                    if self.verbose>1:
                        print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
                    return view_func(*args, **kwargs)
                if on_failure:
                    return self._return_formatter_wf(on_failure(self.get_last_error()), 401)

                return self._return_formatter_wf(\
                        ('No valid authentication found: %s' % self.get_last_error()), 401)
            return decorated
        return wrapper
    def _determine_number_of_required_matches(self, match, req_group_list):
        '''determine the number of requi`example.py`red matches from parameters'''
        # How many matches do we need?
        required_matches = None
        if match == 'all':
            required_matches = len(req_group_list)
        if match == 'one':
            required_matches = 1
        if isinstance (match, int):
            required_matches = match
        if required_matches > len(req_group_list):
            required_matches = len(req_group_list)
        if self.verbose > 1:
            print ('    required matches: {}'.format(required_matches))
        return required_matches
    def _get_entitlements_from_claim(self, all_info, claim):
        '''extract entitlements from given claim in userinfo'''
        # copy entries from incoming claim
        try:
            avail_group_entries = all_info[claim]
        except KeyError:
            user_message = 'Not authorised (claim does not exist: "%s".)' % claim
            if self.verbose:
                print ('Claim does not exist: "%s".' % claim)
                print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
            return (None, user_message)
        if not isinstance(avail_group_entries, list):
            user_message = 'Not authorised (claim does not point to a list: "%s".)' % avail_group_entries
            if self.verbose:
                print ('Claim does not point to a list: "%s".' % avail_group_entries)
                print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))
            return (None, user_message)

        return (avail_group_entries, None)
    def group_required(self, group=None, claim=None, on_failure=None, match='all'):
        '''Decorator to enforce membership in a given group.
        group is the name (or list) of the group to match
        match specifies how many of the given groups must be matched. Valid values for match are
        'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                try:
                    if os.environ['DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER'].lower() == 'yes':
                        return view_func(*args, **kwargs)
                except KeyError: # i.e. the environment variable was not set
                    pass

                user_message = 'Not enough required group memberships found.'

                request_object = self._find_request_based_on_web_framework(request, args)
                all_info = self._get_all_info_from_request(request_object)

                if all_info is None:
                    if on_failure:
                        return self._return_formatter_wf(on_failure(self.get_last_error()), 401)
                    return self._return_formatter_wf('No valid authentication found. %s' % self.get_last_error(), 401)

                req_group_list = ensure_is_list (group)
                required_matches = self._determine_number_of_required_matches(match, req_group_list)
                if not required_matches:
                    print('Error interpreting the "match" parameter')
                    return self._return_formatter_wf('Error interpreting the "match" parameter', 403)

                if self.verbose>1:
                    print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))

                # copy entries from incoming claim
                (avail_group_entries, user_message) = self._get_entitlements_from_claim(all_info, claim)
                if not avail_group_entries:
                    return self._return_formatter_wf(user_message, 403)

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

                user_message = 'You are not authorised'

                # Either we returned above or there was no matching group
                if on_failure:
                    return self._return_formatter_wf(on_failure(user_message), 403)
                return self._return_formatter_wf(user_message, 403)
            return decorated
        return wrapper
    def aarc_g002_entitlement_required(self, entitlement=None, claim=None, on_failure=None, match='all'):
        '''Decorator to enforce membership in a given group defined according to AARC-G002.
        entitlement is the name (or list) of the entitlement to match
        match specifies how many of the given groups must be matched. Valid values for match are
        'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''
        return self.aarc_g002_group_required(entitlement, claim, on_failure, match)
    def aarc_g002_group_required(self, group=None, claim=None, on_failure=None, match='all'):
        '''Decorator to enforce membership in a given group defined according to AARC-G002.
        group is the name (or list) of the entitlement to match
        match specifies how many of the given groups must be matched. Valid values for match are
        'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page'''

        # rename for clarity, don't use group below
        entitlement=group
        del(group)

        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                try:
                    if os.environ['DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER'].lower() == 'yes':
                        return view_func(*args, **kwargs)
                except KeyError: # i.e. the environment variable was not set
                    pass

                user_message = 'Not enough required entitlements found.'

                request_object = self._find_request_based_on_web_framework(request, args)
                all_info = self._get_all_info_from_request(request_object)

                if all_info is None:
                    if on_failure:
                        return self._return_formatter_wf(on_failure(self.get_last_error()), 401)
                    return self._return_formatter_wf('No valid authentication found. %s' % self.get_last_error(), 401)

                req_entitlement_list = ensure_is_list (entitlement)
                # # # Make sure we have a list:
                # # if isinstance(entitlement, str):
                # #     req_entitlement_list = [entitlement]
                # # else:
                # #     req_entitlement_list = entitlement

                required_matches = self._determine_number_of_required_matches(match, req_entitlement_list)
                if not required_matches:
                    print('Error interpreting the "match" parameter')
                    return self._return_formatter_wf('Error interpreting the "match" parameter', 403)

                if self.verbose>1:
                    print (json.dumps(all_info, sort_keys=True, indent=4, separators=(',', ': ')))

                # copy entries from incoming claim
                (avail_entitlement_entries, user_message) = self._get_entitlements_from_claim(all_info, claim)
                if not avail_entitlement_entries:
                    return self._return_formatter_wf(user_message, 403)

                if self.verbose > 1:
                    print ('\nAvailable Entitlements:')
                    print (str(avail_entitlement_entries))
                    print ('\nRequired Entitlements:')
                    print (str(req_entitlement_list))

                # generate entitlement objects from input strings
                logger.info("Parsing entitlements")
                try:
                    avail_entitlements = [ Aarc_g002_entitlement(es, strict=False, raise_error_if_unparseable=True) for es in avail_entitlement_entries ]
                    req_entitlements   = [ Aarc_g002_entitlement(es, strict=False, raise_error_if_unparseable=True) for es in req_entitlement_list ]
                except ValueError as e:
                    logger.error (F"Failed to parse entitlement: {e}")
                    logger.error (F"    available entitlement_entries: {avail_entitlement_entries}")
                    logger.error (F"    required  entitlement_list:    {req_entitlement_list}")
                logger.info("done")

                if self.verbose > 1:
                    print ('\nAvailable Entitlements:')
                    print ('{}'.format('\n\n'.join([x.__mstr__() for x in avail_entitlements])))
                    print ('\n\nRequired Entitlements:')
                    print ('{}'.format('\n\n'.join([x.__mstr__() for x in req_entitlements])))

                # now we do the actual checking
                matches_found = 0

                for required in req_entitlements:
                    for avail in req_entitlements:
                        if required.is_contained_in(avail):
                            matches_found += 1

                if self.verbose > 0:
                    print('found %d of %d matches' % (matches_found, required_matches))
                if matches_found >= required_matches:
                    return view_func(*args, **kwargs)

                user_message = 'You are not authorised'

                # Either we returned above or there was no matching entitlement
                if on_failure:
                    return self._return_formatter_wf(on_failure(user_message), 403)
                return self._return_formatter_wf(user_message, 403)
            return decorated
        return wrapper
