# This code is distributed under the MIT License

# pylint: disable=consider-using-dict-items,consider-iterating-dictionary

import logging

from flaat import issuertools

logger = logging.getLogger(__name__)


class Issuer_config_cache:
    """Caching of issuer configs"""

    def __init__(self):
        self.entries = {}  # maps 'iss' to the whole issuer config
        self.n = 0

    def add_config(self, iss, issuer_config):
        """add entry"""
        logger.info("Adding: %s", iss)
        self.entries[iss] = issuer_config

    def get(self, iss):
        """get entry"""
        try:
            return self.entries[iss]
        except KeyError:
            logger.debug("No issuer config for issuer in cache: %s", iss)

            # try to fetch it now
            issuer_config = issuertools.find_issuer_config_in_string(iss)
            if issuer_config is not None:
                self.add_config(iss, issuer_config)
                return issuer_config

            return None

    def remove(self, iss):
        """remove entry"""
        del self.entries[iss]

    def dump_to_log(self):
        """display cache"""
        logger.info("Issuer Cache:")
        for iss in self.entries:
            logger.info(
                "%s -> %s",
                self.entries[iss]["issuer"],
                self.entries[iss]["userinfo_endpoint"],
            )

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

    def has(self, iss):
        """do we have an entry"""
        return iss in self.entries.keys()
