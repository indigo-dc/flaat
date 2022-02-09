import logging
from typing import List

from flaat import issuers

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
        self.client_id: str = ""
        self.client_secret: str = ""
        self.client_connect_timeout: float = 1.2  # seconds
        self.claim_search_precedence: List[str] = CLAIM_SEARCH_PRECEDENCE

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
        """Pins the given issuer. Only users of this issuer can be used."""
        self.iss = iss.rstrip("/")

    def set_trusted_OP_list(self, trusted_op_list: List[str]):
        """Define a list of OIDC provider URLs.
        E.g. ['https://iam.deep-hybrid-datacloud.eu/', 'https://login.helmholtz.de/oauth2/', 'https://aai.egi.eu/oidc/']"""

        self.trusted_op_list = list(map(lambda iss: iss.rstrip("/"), trusted_op_list))

    def set_verify_tls(self, param_verify_tls=True):
        """Whether to verify tls connections. Only use for development and debugging"""
        issuers.VERIFY_TLS = param_verify_tls

    def set_client_id(self, client_id):
        """Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now."""
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id

    def set_client_secret(self, client_secret):
        """Client Secret. At the moment this one is sent to all matching providers."""
        self.client_secret = client_secret

    def set_client_connect_timeout(self, num):
        """set timeout for flaat connecting to OPs"""
        self.client_connect_timeout = num

    def set_iss_config_timeout(self, num):
        """set timeout for connections to get config from OP"""
        issuers.TIMEOUT = num

    def set_timeout(self, num):
        """set global timeouts for http connections"""
        self.set_iss_config_timeout(num)
        self.set_client_connect_timeout(num)

    def set_claim_search_precedence(self, a_list):
        """set order in which to search for specific claim"""
        self.claim_search_precedence = a_list
