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
  Load the list of trusted OPs from a file. The file is compatible as the
  one shipped with [oidc-agent](https://github.com/indigo-dc/oidc-agent)

* set_verify_tls(self, param_verify_tls=True): Whether to verify TLS
  connections. Use **only** for debugging.

* set_num_request_workers(self, num): Number of threads for collecting
  remote information (userinfo endpoint, oidc-.wellknown endpoints),
  Default: 10

* set_client_connect_timeout(self, num): Timeout per remote connection.
  Default: 1.2 seconds

* set_iss_config_timeout(self, num): Timeout for connection to obtain
  static issuer configuration.
  Default: 1.2 seconds
  
* set_timeout(self, num): Set timeout for both of the above
