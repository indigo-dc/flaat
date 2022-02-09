from cachetools import LRUCache

from flaat.user_infos import UserInfos


class UserInfoCache(LRUCache):
    """This caches user_infos for access tokens for an unspecified time.
    Before yielding UserInfos, the validity of user infos is checked."""

    def __getitem__(self, key):
        item = super().__getitem__(key)
        if isinstance(item, UserInfos) and item.valid_for_secs < 0:
            raise KeyError()
        return item


user_infos_cache = UserInfoCache(maxsize=1024)
