from dataclasses import dataclass
import logging
from typing import List

from flaat.requirements import HasSubIss, REQUIREMENT, Satisfied, Unsatisfiable

logger = logging.getLogger(__name__)

LOG_LEVEL_OVERRIDES = {
    "requests_cache": logging.WARN,
    "urllib3": logging.WARN,
    "asyncio": logging.WARN,
}


def _apply_log_level_overrides():
    for name, level in LOG_LEVEL_OVERRIDES.items():
        logging.getLogger(name).setLevel(level)


@dataclass
class AccessLevel:
    """Access levels are basically named requirements.
    An example would be two access levels 'user' and 'admin', which have requirements for the respective level.

    In order to use an access level with a flaat instance, you need to use :meth:`flaat.BaseFlaat.set_access_levels` to add them to the list.
    """

    name: str
    """ The name of the access level. This is used in  :meth:`flaat.BaseFlaat.access_level` to identify this access level."""

    requirement: REQUIREMENT
    """ The requirement that users of this access level need to satisfy.
    If this is a callable, then the requirement is lazily loaded at runtime using the callable.
    """


# DEFAULT VALUES
Anyone = AccessLevel("ANYONE", Satisfied())
NoOne = AccessLevel("NOONE", Unsatisfiable())
Identified = AccessLevel("IDENTIFIED", HasSubIss())

DEFAULT_ACCESS_LEVELS = [
    Anyone,
    NoOne,
    Identified,
]

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
    """
    The configuration for Flaat instances.
    """

    def __init__(self):
        self.trusted_op_list: List[str] = []
        self.iss: str = ""
        self.op_hint: str = ""
        self.client_id: str = ""
        self.client_secret: str = ""
        self.request_timeout: float = 1.2  # seconds
        self.verify_tls = True

        # access levels for the self.access_level decorator
        self.access_levels = DEFAULT_ACCESS_LEVELS

    def set_access_levels(self, access_levels: List[AccessLevel]):
        """
        Set the list of access levels for use with :meth:`flaat.BaseFlaat.access_level`.
        This list will overwrite the default access levels.

        :param access_level: List of :class:`AccessLevel` instances.
        """
        self.access_levels = access_levels

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

    def set_issuer(self, issuer: str):
        """Pins the given issuer. Only users of this issuer will be able to use services.

        :param issuer: Issuer URL of the pinned issuer.
        """
        self.iss = issuer.rstrip("/")

    def set_trusted_OP_list(self, trusted_op_list: List[str]):
        """
        Sets a list of OIDC providers that you trust. This means that users of these OPs will be able
        to use your services.

        :param trusted_op_list: A list of the issuer URLs that you trust.
            An example issuer is: 'https://iam.deep-hybrid-datacloud.eu/'.
        """

        self.trusted_op_list = list(map(lambda iss: iss.rstrip("/"), trusted_op_list))

    def set_verify_tls(self, verify_tls=True):
        """*Only* use for development and debugging.
        Set to `False` to skip TLS certificate verification while processing requests.
        """
        self.verify_tls = verify_tls

    def set_client_id(self, client_id=""):
        """Set a client id for token introspection"""
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id

    def set_client_secret(self, client_secret=""):
        """Set a client secret for token introspection"""
        self.client_secret = client_secret

    def set_request_timeout(self, timeout: float = 1.2):
        """
        Set the timeout for individual requests (retrieving issuer configs, user infos and introspection infos).
        Note that the total runtime of a decorator could be significantly more, based on your `trusted_op_list`.

        :param timeout: Request timeout in seconds.
        """
        self.request_timeout = timeout
