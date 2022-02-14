import logging
from typing import List

from flaat import issuers

logger = logging.getLogger(__name__)

LOG_LEVEL_OVERRIDES = {
    "requests_cache": logging.WARN,
    "urllib3": logging.WARN,
    "asyncio": logging.WARN,
}


def _apply_log_level_overrides():
    for name, level in LOG_LEVEL_OVERRIDES.items():
        logging.getLogger(name).setLevel(level)


# DEFAULT VALUES

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

    def set_verbosity(self, verbosity: int, set_global=False):
        """
        Set the logging verbosity.

        :param verbosity: Verbosity integer from 0 (= error) to 3 (= debug)
        :param set_global: If set to `True` the logging level will be set for all loggers
        """
        if verbosity < 0 or verbosity > 3:
            raise ValueError("Verbosity needs to be [0-3]")

        level = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO,
            3: logging.DEBUG,
        }[verbosity]

        if set_global:
            logging.getLogger().setLevel(level)
            logger.debug("Setting global log level to: %s", level)
        else:
            logger.setLevel(level)
            logger.debug("Setting flaat log level to: %s", level)

        _apply_log_level_overrides()

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
        """Client id for token introspection"""
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id

    def set_client_secret(self, client_secret):
        """client secret for token introspection"""
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
