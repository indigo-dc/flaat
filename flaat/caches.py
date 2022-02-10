from cachetools import LRUCache, TTLCache

from flaat.user_infos import UserInfos


class UserInfoCache(LRUCache):
    """This caches user_infos for access tokens for an unspecified time.
    Before yielding UserInfos, the validity of user infos is checked."""

    def __getitem__(self, key):
        def _fail(msg):
            self.__delitem__(key)
            raise KeyError(msg)

        item = super().__getitem__(key)
        if isinstance(item, UserInfos):
            if item.valid_for_secs is None:
                _fail("Cache entry validity can not be determined")
            if item.valid_for_secs <= 0:
                _fail("Cache entry has expired")
        return item


# cache at most 1024 user infos until they are expired
user_infos_cache = UserInfoCache(maxsize=1024)

# cache issuer configs for an hour
issuer_config_cache = TTLCache(maxsize=128, ttl=3600)

# cache access_token_issuer mappings indefinitely
access_token_issuer_cache = LRUCache(maxsize=1024)
