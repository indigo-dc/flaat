import logging
import os
import json
from pathlib import Path
from configparser import ConfigParser

logger = logging.getLogger(__name__)

# No leading slash ('/') in ops_that_support_jwt !!!
DEFAULT_OPS_THAT_SUPPORT_JWT = [
    "https://aai-dev.egi.eu/oidc",
    "https://aai.egi.eu/oidc",
    "https://aai-dev.egi.eu/auth/realms/egi",
    "https://aai-demo.egi.eu/auth/realms/egi",
    "https://aai.egi.eu/auth/realms/egi",
    "https://aai-dev.egi.eu/auth/realms/egi",
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

# No leading slash ('/') in ops_that_support_audience !!!
DEFAULT_OPS_THAT_SUPPORT_AUDIENCE = [
    "https://iam-test.indigo-datacloud.eu",
    "https://iam.deep-hybrid-datacloud.eu",
    "https://iam.extreme-datacloud.eu",
    "https://wlcg.cloud.cnaf.infn.it",
]


class Config:
    """
    The configuration for OPs and what they support.
    """

    def __init__(self, ops_that_support_jwt: list, ops_that_support_audience: list):
        self.ops_that_support_jwt = list(
            set(DEFAULT_OPS_THAT_SUPPORT_JWT + ops_that_support_jwt)
        )
        self.ops_that_support_audience = list(
            set(DEFAULT_OPS_THAT_SUPPORT_AUDIENCE + ops_that_support_audience)
        )

    @property
    def OPS_THAT_SUPPORT_JWT(self):
        return self.ops_that_support_jwt

    @property
    def OPS_THAT_SUPPORT_AUDIENCE(self):
        return self.ops_that_support_audience

    @staticmethod
    def load():
        """
        Load OP specific configuration from config file.
            Config locations, by priority:
            $FLAAT_CONFIG
            ./flaat.conf
            ~/.config/flaat/flaat.conf
            /etc/flaat/flaat.conf
        """
        config_files = []
        filename = os.environ.get("FLAAT_CONFIG")
        if filename:
            config_files += [Path(filename)]
        config_files += [
            Path("flaat.conf").absolute(),
            Path("~/.config/flaat/flaat.conf").expanduser(),
        ]
        config_files += [Path("/etc/flaat/flaat.conf")]
        config_parser = ConfigParser()
        for filename in config_files:
            fpath = Path(filename)
            if fpath.exists():
                try:
                    files_read = config_parser.read(fpath)
                    logging.getLogger(__name__).debug("Read config from %s", files_read)
                except Exception as e:
                    logging.getLogger(__name__).warning(
                        "Invalid OP config file: %s. Trying next file of falling back to default values.",
                        e,
                    )
                    continue
                try:
                    ops_that_support_jwt = json.loads(
                        config_parser.get("ops", "ops_that_support_jwt")
                    )
                except Exception as e:
                    logging.getLogger(__name__).warning(
                        "Failed to load OPs that support JWT from config file: %s. Using default values.",
                        e,
                    )
                    ops_that_support_jwt = []
                try:
                    ops_that_support_audience = json.loads(
                        config_parser.get("ops", "ops_that_support_audience")
                    )
                except Exception as e:
                    logging.getLogger(__name__).warning(
                        "Failed to load OPs that support audience from config file: %s. Using default values.",
                        e,
                    )
                    ops_that_support_audience = []
                logging.getLogger(__name__).debug(
                    "loaded OPs that support JWT %s", ops_that_support_jwt
                )
                logging.getLogger(__name__).debug(
                    "loaded OPs that support audience %s", ops_that_support_audience
                )
                return Config(ops_that_support_jwt, ops_that_support_audience)
        return Config([], [])


CONFIG = Config.load()
