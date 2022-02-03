import logging
from typing import List

from flaat import issuers
from flaat.caches import IssuerConfigCache

logger = logging.getLogger(__name__)

# DEFAULT VALUES

CLAIM_SEARCH_PRECEDENCE = ["userinfo", "access_token"]

# No leading slash ('/') in ops_that_support_jwt !!!
OPS_THAT_SUPPORT_JWT = [
    "https://aai-dev.egi.eu/oidc",
    "https://aai.egi.eu/oidc",
    "https://b2access-integration.fz-juelich.de/oauth2",
    "https://b2access.eudat.eu/oauth2",
    "https://iam-test.indigo-datacloud.eu",
    "https://iam.deep-hybrid-datacloud.eu",
    "https://iam.extreme-datacloud.eu",
    "https://login-dev.helmholtz.de/oauth2",
    "https://login.elixir-czech.org/oidc",
    "https://login.helmholtz-data-federation.de/oauth2",
    "https://login.helmholtz.de/oauth2",
    "https://oidc.scc.kit.edu/auth/realms/kit",
    "https://services.humanbrainproject.eu/oidc",
    "https://unity.helmholtz-data-federation.de/oauth2",
    "https://wlcg.cloud.cnaf.infn.it",
]


class FlaatConfig:
    def __init__(self):
        self.trusted_op_list: List[str] = []
        self.iss: str = ""
        self.op_hint: str = ""
        self.trusted_op_file: str = ""
        self.verify_tls: bool = True
        self.client_id: str = ""
        self.client_secret: str = ""
        self.num_request_workers: int = 10
        self.client_connect_timeout: float = 1.2  # seconds
        self.ops_that_support_jwt: List[str] = OPS_THAT_SUPPORT_JWT
        self.claim_search_precedence: List[str] = CLAIM_SEARCH_PRECEDENCE
        self.raise_error_on_return = True  # else just return an error
        self.issuer_config_cache = IssuerConfigCache()

    def set_verbosity(self, verbosity: int):
        if verbosity < 0 or verbosity > 3:
            raise ValueError("Verbosity needs to be [0-3]")
        level = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO,
            3: logging.DEBUG,
        }[verbosity]
        # TODO also set the framework specific loggers
        logger.setLevel(level)

    def set_issuer(self, iss):
        """Use set_issuer to only use this issuer"""
        self.iss = iss.rstrip("/")

    def set_trusted_OP_list(self, trusted_op_list: List[str]):
        """Define a list of OIDC provider URLs.
        E.g. ['https://iam.deep-hybrid-datacloud.eu/', 'https://login.helmholtz.de/oauth2/', 'https://aai.egi.eu/oidc/']"""

        self.trusted_op_list = list(map(lambda iss: iss.rstrip("/"), trusted_op_list))

        # LOW PRIO: Make this parallel
        for iss in self.trusted_op_list:
            self.issuer_config_cache.get(iss)

    def set_trusted_OP_file(self, filename="/etc/oidc-agent/issuer.config", hint=None):
        """Set filename of oidc-agent's issuer.config. Requires oidc-agent to be installed."""
        self.trusted_op_file = filename
        self.op_hint = hint

    def set_OP_hint(self, hint):
        """String to specify the hint. This is used for regex searching in lists of providers for
        possible matching ones."""
        self.op_hint = hint

    def set_verify_tls(self, param_verify_tls=True):
        """Whether to verify tls connections. Only use for development and debugging"""
        self.verify_tls = param_verify_tls
        issuers.verify_tls = param_verify_tls

    def set_client_id(self, client_id):
        """Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now."""
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id

    def set_client_secret(self, client_secret):
        """Client Secret. At the moment this one is sent to all matching providers."""
        self.client_secret = client_secret

    def set_num_request_workers(self, num):
        """set number of request workers"""
        self.num_request_workers = num
        issuers.num_request_workers = num

    def get_num_request_workers(self):
        """get number of request workers"""
        return self.num_request_workers

    def set_client_connect_timeout(self, num):
        """set timeout for flaat connecting to OPs"""
        self.client_connect_timeout = num

    def get_client_connect_timeout(self):
        """get timeout for flaat connecting to OPs"""
        return self.client_connect_timeout

    def set_iss_config_timeout(self, num):
        """set timeout for connections to get config from OP"""
        issuers.timeout = num

    def get_iss_config_timeout(self):
        """set timeout for connections to get config from OP"""
        return issuers.timeout

    def set_timeout(self, num):
        """set global timeouts for http connections"""
        self.set_iss_config_timeout(num)
        self.set_client_connect_timeout(num)

    def get_timeout(self):
        """get global timeout for https connections"""
        return (self.get_iss_config_timeout(), self.get_client_connect_timeout())

    def set_claim_search_precedence(self, a_list):
        """set order in which to search for specific claim"""
        self.claim_search_precedence = a_list

    def get_claim_search_precedence(self):
        """get order in which to search for specific claim"""
        return self.claim_search_precedence