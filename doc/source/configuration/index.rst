Configuration Options
=====================

The configuration for flaat is handled by a set of calls to the flaat
class, described below.


* set_web_framework (string): set one of the supported web frameworks
  (currently 'aiohttp', 'flask', and 'fastapi')

* set_cache_lifetime(integer):  seconds; default is 300

* set_trusted_OP_list(list): List of URLs to OIDC-Providers (OPs).
  Examples:
    * 'https://b2access.eudat.eu/oauth2/'
    * 'https://proxy.demo.eduteams.org'
    * 'https://aai.egi.eu/oidc/'

* set_verbosity(0): verbosity:
    * 0: No output
    * 1: Errors
    * 2: More info, including token info
    * 3: Max

* def set_cache_backend(self, backend): Supported backends are those
  supported also by the requests_cache python module (examples: 'memory'
  (default), 'sqlite3')


* set_trusted_OP_file(self, filename='/etc/oidc-agent/issuer.config', hint=None):

* set_verify_tls(self, param_verify_tls=True):

* set_num_request_workers(self, num):

* set_client_connect_timeout(self, num):

* set_iss_config_timeout(self, num):
  
* set_timeout(self, num):
