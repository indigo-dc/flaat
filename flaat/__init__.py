"""FLAsk support for OIDC Access Tokens -- FLAAT.
Use decorators for authorising access to OIDC authenticated REST APIs.
"""
# This code is distributed under the MIT License

from asyncio import iscoroutinefunction
from functools import wraps
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Union

from flaat.config import FlaatConfig
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.issuers import IssuerConfig
from flaat.requirements import CheckResult, Requirement
from flaat.tokentools import AccessTokenInfo, get_access_token_info
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)


class BaseFlaat(FlaatConfig):
    """FLAsk support for OIDC Access Tokens.
    Provide decorators and configuration for OIDC"""

    def __init__(self):
        super().__init__()
        self.accesstoken_issuer_cache: Dict[str, str] = {}  # maps accesstoken to issuer

    # SUBCLASS STUBS
    def _get_request(self, *args, **kwargs):  # pragma: no cover
        """overwritten in subclasses"""
        # raise NotImplementedError("implement in subclass")
        _ = args
        _ = kwargs
        return {}

    def _map_exception(self, exception: FlaatException):  # pragma: no cover
        _ = exception

    def get_access_token_from_request(self, request) -> str:  # pragma: no cover
        """Helper function to obtain the OIDC AT from the flask request variable"""
        _ = request
        return ""

    # END SUBCLASS STUBS

    def _issuer_is_trusted(self, issuer):
        return issuer.rstrip("/") in self.trusted_op_list

    def _find_issuer_config_everywhere(
        self, access_token, access_token_info: Optional[AccessTokenInfo]
    ) -> Optional[IssuerConfig]:

        # 0: Manually set in the config
        if self.iss != "":
            iss_config = self.issuer_config_cache.get(self.iss)
            if iss_config is None:
                raise FlaatException(
                    f"Misconfigured: issuer is set to '{self.iss}', but we cant find a config for that issuer"
                )
            return iss_config

        # 1: JWT AT
        if access_token_info is not None:
            logger.debug("Access token is a JWT")
            at_iss = access_token_info.issuer
            if at_iss is not None:
                if not self._issuer_is_trusted(at_iss):
                    raise FlaatUnauthenticated(f"Issuer is not trusted: {at_iss}")

                iss_config = self.issuer_config_cache.get(at_iss)
                if iss_config is None:
                    raise FlaatUnauthenticated(
                        f"Unable to fetch issuer config for: {at_iss}"
                    )

                return iss_config

        # 2: Try AT -> Issuer cache
        if access_token in self.accesstoken_issuer_cache:
            logger.debug("Cache hit for access_token")
            issuer = self.accesstoken_issuer_cache[access_token]

            iss_config = self.issuer_config_cache.get(issuer)
            if iss_config is None:
                raise FlaatUnauthenticated(f"Invalid Issuer URL in cacher: {issuer}")

            return iss_config

        return None

    def get_user_infos_from_access_token(self, access_token) -> Optional[UserInfos]:
        logger.debug("Access token: %s", access_token)
        access_token_info = get_access_token_info(access_token)
        issuer_config = self._find_issuer_config_everywhere(
            access_token, access_token_info
        )
        if issuer_config is not None:
            return issuer_config.get_user_infos(access_token)

        logger.debug("Issuer could not be determined -> trying all trusted OPs")
        # TODO parallel would speed up things here
        for cached_config in self.issuer_config_cache:
            user_infos = cached_config.get_user_infos(
                access_token, access_token_info=access_token_info
            )
            if user_infos is not None:
                self.accesstoken_issuer_cache[access_token] = cached_config.issuer
                return user_infos

        return None

    def get_user_infos_from_request(self, request_object) -> Optional[UserInfos]:
        try:
            access_token = self.get_access_token_from_request(request_object)
            user_infos = self.get_user_infos_from_access_token(access_token)
            if user_infos is None:
                raise FlaatUnauthenticated("Unable to retrieve user infos")

            return user_infos
        except FlaatException as e:
            return self._map_exception(e)

    def authenticate_user(self, *args, **kwargs) -> Optional[UserInfos]:
        """authenticate user needs the same arguments as the view_func it is called from."""

        request_object = self._get_request(*args, **kwargs)
        return self.get_user_infos_from_request(request_object)

    def _wrap_view_func(
        self,
        view_func: Callable,
        process_kwargs: Callable[[tuple, dict], dict],
        handle_exception=None,
    ) -> Callable:
        def _handle_exception(self, e):
            if handle_exception is not None:
                logger.debug("Passing exception to provided handler: %s", e)
                try:
                    return handle_exception(e)
                except FlaatException as exc:
                    return self._map_exception(exc)

            return self._map_exception(e)

        def _process_kwargs(*args, **kwargs):
            try:
                return process_kwargs(*args, **kwargs)
            except FlaatException as e:
                _handle_exception(self, e)
                return kwargs

        @wraps(view_func)
        def wrapper(*args, **kwargs):
            logger.debug("wrapper: view_func args=%s kwargs=%s", args, kwargs)
            kwargs = _process_kwargs(*args, **kwargs)
            return view_func(*args, **kwargs)

        @wraps(view_func)
        async def async_wrapper(*args, **kwargs):
            kwargs = _process_kwargs(*args, **kwargs)
            logger.debug("async_wrapper: view_func args=%s kwargs=%s", args, kwargs)
            return await view_func(*args, **kwargs)

        if iscoroutinefunction(view_func):
            return async_wrapper

        return wrapper

    @staticmethod
    def _add_value_to_kwargs(kwargs, key, value):
        if key in kwargs:
            logger.warning("Overwriting already existing kwarg: %s", kwargs[key])

        kwargs[key] = value
        return kwargs

    def inject_user(
        self,
        infos_to_user: Callable[[UserInfos], Any],
        key="user",
        strict=True,
    ) -> Callable:
        """Injects a user into a view function given a method to translate a UserInfos instance into the user
        If strict is set to True this decorator will fail when theire is nothing to inject
        """

        def _inject_user(*args, **kwargs):
            user_infos = self.authenticate_user(*args, **kwargs)
            if user_infos is None or user_infos.is_empty:
                if strict:
                    raise FlaatUnauthenticated(
                        "Needed user infos could not be retrieved"
                    )
                logger.debug("Unable to inject: No user infos")
                return kwargs

            user = infos_to_user(user_infos)
            kwargs = self._add_value_to_kwargs(kwargs, key, user)
            return kwargs

        def decorator(view_func: Callable) -> Callable:
            return self._wrap_view_func(view_func, process_kwargs=_inject_user)

        return decorator

    def inject_user_infos(self, key="user_infos", strict=True) -> Callable:
        return self.inject_user(infos_to_user=lambda info: info, key=key, strict=strict)

    def _requirement_auth_disabled(self):
        return (
            "yes"
            == os.environ.get(
                "DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER", ""
            ).lower()
        )

    def requires(
        self,
        requirements: Union[Requirement, List[Requirement]],
        on_failure: Optional[Callable] = None,
    ):
        def _user_has_authorization(user_infos: UserInfos) -> CheckResult:
            reqs = []
            if isinstance(requirements, list):
                reqs = requirements
            else:
                reqs = [requirements]

            satisfied = True
            failure_messages = []
            for req in reqs:
                check_result = req.is_satisfied_by(user_infos)
                if not check_result.is_satisfied:
                    failure_messages.append(check_result.message)
                    satisfied = False

            if satisfied:
                return CheckResult(True, "")

            return CheckResult(
                False, f"User does not meet requirements: {failure_messages}"
            )

        def _authenticate(*args, **kwargs):
            if not self._requirement_auth_disabled():
                user_infos = self.authenticate_user(self, *args, **kwargs)
                if user_infos is None or user_infos.is_empty:
                    raise FlaatUnauthenticated("Could not determine identity of user")

                authz_check = _user_has_authorization(user_infos)
                if not authz_check.is_satisfied:
                    raise FlaatForbidden(authz_check.message)

            return kwargs

        def decorator(view_func: Callable) -> Callable:
            return self._wrap_view_func(
                view_func,
                process_kwargs=_authenticate,
                handle_exception=on_failure,
            )

        return decorator
