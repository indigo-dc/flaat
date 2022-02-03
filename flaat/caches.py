# This code is distributed under the MIT License

# pylint: disable=consider-using-dict-items,consider-iterating-dictionary

import logging
from typing import Dict, Optional

from flaat.issuers import IssuerConfig

logger = logging.getLogger(__name__)


class IssuerConfigCache:
    """Cache: Issuer -> Issuer Config"""

    def __init__(self):
        # maps 'iss' to the whole issuer config
        self.entries: Dict[str, IssuerConfig] = {}
        self.n = 0

    def set(self, iss, issuer_config: IssuerConfig):
        """add entry"""
        logger.info("Setting: %s - %s", iss, issuer_config)
        self.entries[iss] = issuer_config

    def get(self, iss) -> Optional[IssuerConfig]:
        """get entry"""
        issuer_config = self.entries.get(iss, None)
        if issuer_config is not None:
            logger.debug("Cache hit for issuer: %s", iss)
            return issuer_config

        logger.info("Cache miss for issuer: %s", iss)

        # try to fetch it now
        issuer_config = IssuerConfig.get_from_string(iss)
        if issuer_config is not None:
            self.set(iss, issuer_config)
            return issuer_config

        return None

    def __iter__(self):
        self.n = 0
        return self

    def __next__(self):
        keys = self.entries.keys()
        my_length = len(keys)
        if self.n < my_length:
            retval = self.entries[list(keys)[self.n]]
            self.n += 1
            return retval
        raise StopIteration

    def __len__(self):
        """return length"""
        return len(self.entries.keys())
