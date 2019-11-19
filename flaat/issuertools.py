'''Tools for token handling in FLAAT'''
# This code is distributed under the MIT License
# pylint 
# vim: tw=100 foldmethod=indent
# pylint: disable=bad-continuation, invalid-name, superfluous-parens
# pylint: disable=bad-whitespace
# pylint: disable=logging-not-lazy, logging-format-interpolation
# pylint: disable=wrong-import-position

import sys
is_py2 = sys.version[0] == '2'
if is_py2:
    from Queue import Queue, Empty
else:
    from queue import Queue, Empty
from threading import Thread
import re
import fileinput
from base64 import b64encode
import json
import requests
import requests_cache

from . import tokentools

# default values:
requests_cache.install_cache(include_get_headers=True, expire_after=300)

verbose = 1
verify_tls = True
timeout = 1.2 #(seconds)
num_request_workers = 10
param_q  = Queue(num_request_workers*2)
result_q = Queue(num_request_workers*2)

def find_issuer_config_in_at(access_token):
    '''If there is an issuer in the AT, we fetch the ISS config and return it'''
    iss_config = None
    at_iss = tokentools.get_issuer_from_accesstoken_info(access_token)
    if verbose > 2:
        print ('got iss from access_token: %s' % str(at_iss))
    if at_iss is not None:
        if tokentools.is_url(at_iss):
            config_url = at_iss+'/.well-known/openid-configuration'
            iss_config = get_iss_config_from_endpoint(config_url)
    return iss_config

def find_issuer_config_in_string(string):
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

def thread_worker_issuerconfig():
    '''Thread worker'''
    while True:
        item = param_q.get()
        if item is None:
            break
        result = get_iss_config_from_endpoint(item)
        param_q.task_done()
        result_q.put(result)
        result_q.task_done()

def find_issuer_config_in_list(op_list, op_hint = None, exclude_list = []):
    '''find the hinted issuer in configured op_list'''

    iss_config = None
    for i in range (num_request_workers):
        t = Thread(target=thread_worker_issuerconfig)
        # t = Thread(target=worker)
        t.daemon = True
        t.start()

    if op_list:
        iss_config=[]
        for issuer in op_list:
            if issuer in exclude_list:
                if verbose>1:
                    print ('skipping %s due to exclude list' % issuer)
                continue
            issuer_wellknown=issuer.rstrip('/') + '/.well-known/openid-configuration'
            if op_hint is None:
                # print ('getting issuer config from {}'.format(issuer))
                # iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
                param_q.put(issuer_wellknown)
            else:
                if re.search(op_hint, issuer):
                    # iss_config.append(get_iss_config_from_endpoint(issuer_wellknown))
                    param_q.put(issuer_wellknown)
        param_q.join()
        result_q.join()
        try:
            for entry in iter(result_q.get_nowait, None):
                iss_config.append(entry)
        except Empty:
            pass

    return iss_config

def find_issuer_config_in_file(op_file, op_hint = None, exclude_list=[]):
    '''find the hinted issuer in a configured, oidc-agent compatible issuers.conf file
    we only use the first (space separated) entry of that file.'''
    iss_config = None
    op_list = []
    if op_file:
        iss_config=[]
        for issuer in fileinput.input(op_file):
            issuer_from_conf=issuer.rstrip('\n').split(' ')[0]
            if issuer_from_conf == '':
                continue
            if issuer_from_conf in exclude_list:
                if verbose>1:
                    print ('skipping %s due to exclude list' % issuer)
                continue
            op_list.append(issuer_from_conf)
        return (find_issuer_config_in_list(op_list, op_hint, exclude_list))
    return iss_config

def get_iss_config_from_endpoint(issuer_url):
    '''Get issuer_wellknown/configuration from url; return json if true, None otherwise.
    Note that this endpoint is called more often than necessary. We rely on requests_cache to keep
    this efficient'''
    # If requests_cache is not wanted. Here would be one place to implement caching

    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    config_url = issuer_url
    # remove slashes:
    config_url = re.sub('^https?://', '', config_url)
    config_url = config_url.replace('//', '/')
    config_url = config_url.replace('//', '/')
    config_url = 'https://'+config_url

    if verbose>1:
        print('Getting config from: %s' % config_url)
    try:
        resp = requests.get (config_url, verify=verify_tls, headers=headers, timeout=timeout)
        if verbose > 2:
            print('Getconfig: resp: %s' % resp.status_code)
    except requests.exceptions.ConnectionError as e:
        if verbose > 0:
            print ('Warning: cannot obtain iss_config from endpoint: {}'.format(config_url))
            # print ('Additional info: {}'.format (e))
        return None
    except requests.exceptions.ReadTimeout as e:
        if verbose > 0:
            print ('Warning: cannot obtain iss_config from endpoint: {}'.format(config_url))
            # print ('Additional info: {}'.format (e))
        return None
    try:
        return resp.json()
    except:
        print(str(resp.text))
        return None

def get_user_info(access_token, issuer_config):
    '''Query the userinfo endpoint, using the AT as authentication'''
    headers = {}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    headers['Authorization'] = 'Bearer {0}'.format(access_token)
    if verbose > 2:
        print ('using this access token: %s' % access_token)
    if verbose > 1:
        print('Getting userinfo from %s' % issuer_config['userinfo_endpoint'])
    resp = requests.get (issuer_config['userinfo_endpoint'], verify=verify_tls, headers=headers,
            timeout=timeout)
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

def get_introspected_token_info(access_token, issuer_config, client_id=None, client_secret=None):
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

    headers['Authorization'] = 'Basic %s' % b64encode(basic_auth_bytes).decode('utf-8')

    if verbose > 1:
        print('Getting introspection from %s' % issuer_config['userinfo_endpoint'])
    try:
        resp = requests.post (issuer_config['introspection_endpoint'], \
                              verify=verify_tls, headers=headers, data=post_data, timeout=timeout)
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

