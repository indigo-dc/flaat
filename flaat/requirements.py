import json
import logging
import os
from typing import List, Union

import aarc_entitlement

from flaat.exceptions import FlaatException, FlaatForbidden
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)


def ensure_is_list(item: Union[list, str]) -> List[str]:
    """Make sure we have a list"""
    if isinstance(item, str):
        return [item]
    return item


def check_environment_for_override(env_key):
    """Override the actual group membership, if environment is set."""
    env_val = os.getenv(env_key)
    try:
        if env_val is not None:
            avail_entitlement_entries = json.loads(env_val)
            return avail_entitlement_entries
    except (TypeError, json.JSONDecodeError) as e:
        logger.error(
            "Cannot decode JSON group list from the environment: %s\n%s", env_val, e
        )
    return None


class Requirement:
    def satisfied_by(self, user_infos: UserInfos) -> bool:
        _ = user_infos
        return False


class ValidLogin(Requirement):
    def satisfied_by(self, user_infos: UserInfos):
        return (
            user_infos is not None
            and user_infos.subject != ""
            and user_infos.issuer != ""
        )


class HasGroups(Requirement):
    def __init__(
        self,
        required: Union[str, List[str]],
        claim: str,  # claim in the user info
        match: Union[str, int] = "all",
    ):
        self.required = self._parse_all(required)
        self.claim = claim
        self.match = match
        self.required_matches = self._determine_number_of_required_matches(
            match,
            self.required,
        )

    def _determine_number_of_required_matches(
        self, match: Union[str, int], req_group_list: list
    ) -> int:
        """determine the number of required matches from parameters"""

        if match == "all":
            return len(req_group_list)

        if isinstance(match, int):
            return min(match, len(req_group_list))

        raise FlaatException("Argument 'match' has invalid value: Must be 'all' or int")

    def _compare(self, req, avail):
        """possibly overwritten is subclass"""
        return req == avail

    def _parse(self, raw):
        """possibly overwritten is subclass"""
        return raw

    def _parse_all(self, raw: Union[str, List[str]]) -> list:
        """parses groups or entitlements"""

        raw_list = ensure_is_list(raw)

        parsed_list = []
        for raw_ent in raw_list:
            parsed = self._parse(raw_ent)
            if parsed is None:
                raise FlaatException(f"Can not parse entitelment: {raw_ent}")
            parsed_list.append(parsed)

        return parsed_list

    def _get_effective_entitlements_from_claim(
        self, user_infos: UserInfos, claim: str
    ) -> List[str]:
        override_entitlement_entries = check_environment_for_override(
            "DISABLE_AUTHENTICATION_AND_ASSUME_ENTITLEMENTS"
        )
        if override_entitlement_entries is not None:
            logger.info("Using entitlement override: %s", override_entitlement_entries)
            return override_entitlement_entries

        return user_infos.get_entitlements_from_claim(claim)

    def satisfied_by(self, user_infos: UserInfos) -> bool:
        avail_raw = self._get_effective_entitlements_from_claim(user_infos, self.claim)
        if avail_raw is None:
            raise FlaatForbidden("No group memberships found")

        avail_parsed = self._parse_all(avail_raw)

        logger.debug("Required: %s - Available: %s", self.required, avail_parsed)
        matches_found = 0
        for req in self.required:
            for avail in avail_parsed:
                if self._compare(req, avail):
                    matches_found += 1

        logger.info("Found %d of %d matches", matches_found, self.required_matches)

        if matches_found < self.required_matches:
            raise FlaatForbidden(
                f"Matched {matches_found} groups, but needed {self.required_matches}"
            )

        return True


class HasAARCEntitlement(HasGroups):
    def _parse(self, raw: str):
        try:
            return aarc_entitlement.G069(raw)
        except aarc_entitlement.Error as e:
            logger.error("Error parsing aarc entitlement: %s", e)
            return None

    def _compare(
        self, req: aarc_entitlement.Base, avail: aarc_entitlement.Base
    ) -> bool:
        return avail.satisfies(req)
