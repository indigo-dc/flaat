"""Python support for OIDC Access Tokens -- FLAAT.
Use decorators for authorising access to OIDC authenticated REST APIs.
"""
# This code is distributed under the MIT License

from __future__ import annotations
from asyncio import iscoroutinefunction
from dataclasses import dataclass
from functools import wraps
import logging
import os
from typing import Any, Callable, Dict, List, NoReturn, Optional, Tuple, Union

from flaat.access_tokens import AccessTokenInfo, get_access_token_info
from flaat.config import FlaatConfig, OPS_THAT_SUPPORT_JWT
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.issuers import IssuerConfig
from flaat.requirements import (
    CheckResult,
    HasSubIss,
    Requirement,
    Satisfied,
    Unsatisfiable,
    REQUIREMENT,
    REQUEST_REQUIREMENT,
)
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

# MAP_EXCEPTION is the type for self.map_exception
# It map our exceptions to framework specific or custom exceptions
MAP_EXCEPTION = Callable[[FlaatException], NoReturn]

# ON_FAILURE is the type for on_failure functions
# these are called in place of a view function, if the authentication process resulted in an error
# on_failure functions may raise a framework specific exception, or return a valid response for the respective framework.
ON_FAILURE = Callable[[FlaatException, Optional[UserInfos]], Union[Any, NoReturn]]


@dataclass
class AccessLevel:
    name: str
    requirement: REQUIREMENT


Anyone = AccessLevel("ANYONE", Satisfied())
NoOne = AccessLevel("NOONE", Unsatisfiable())
Identified = AccessLevel("IDENTIFIED", HasSubIss())

DEFAULT_ACCESS_LEVELS = [
    Anyone,
    NoOne,
    Identified,
]


class BaseFlaat(FlaatConfig):
    """FLAsk support for OIDC Access Tokens.
    Provide decorators and configuration for OIDC"""

    def __init__(self):
        super().__init__()
        self._accesstoken_issuer_cache: Dict[
            str, str
        ] = {}  # maps accesstoken to issuer

        # access levels for the self.access_level decorator
        self.access_levels = DEFAULT_ACCESS_LEVELS

    # SUBCLASS STUBS
    def _get_request(self, *args, **kwargs):  # pragma: no cover
        """overwritten in subclasses"""
        # raise NotImplementedError("implement in subclass")
        _ = args
        _ = kwargs
        return {}

    def map_exception(self, exception: FlaatException) -> NoReturn:  # pragma: no cover
        raise exception

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
        if access_token in self._accesstoken_issuer_cache:
            logger.debug("Cache hit for access_token")
            issuer = self._accesstoken_issuer_cache[access_token]

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
            # skip OPs that would have provided a JWT
            if cached_config.issuer in OPS_THAT_SUPPORT_JWT:
                continue

            user_infos = cached_config.get_user_infos(
                access_token, access_token_info=access_token_info
            )
            if user_infos is not None:
                logger.debug("Found issuer for access token: %s", cached_config.issuer)
                self._accesstoken_issuer_cache[access_token] = cached_config.issuer
                return user_infos

        return None

    def get_user_infos_from_request(self, request_object) -> Optional[UserInfos]:
        access_token = self.get_access_token_from_request(request_object)
        user_infos = self.get_user_infos_from_access_token(access_token)
        return user_infos

    def authenticate_user(self, *args, **kwargs) -> Optional[UserInfos]:
        """authenticate user needs the same arguments as the view_func it is called from."""
        request_object = self._get_request(*args, **kwargs)
        user_infos = self.get_user_infos_from_request(request_object)
        return user_infos

    def inject_object(
        self,
        infos_to_object: Optional[Callable[[UserInfos], Any]] = None,
        key="object",
        strict=True,
    ) -> Callable:
        """Injects a object into a view function given a method to translate a UserInfos instance into the object.
        This is useful for injecting user instances.
        If `strict` is set to True this decorator will fail when there is nothing to inject
        """

        def _add_value_to_kwargs(kwargs: dict, key: str, value) -> dict:
            if key in kwargs:
                logger.warning("Overwriting already existing kwarg: %s", kwargs[key])

            kwargs[key] = value
            return kwargs

        def _infos_to_object(user_infos: UserInfos):
            if infos_to_object is not None:
                return infos_to_object(user_infos)
            return user_infos

        def _inject_object(
            user_infos: UserInfos, *args, **kwargs
        ) -> Tuple[tuple, dict]:
            obj = _infos_to_object(user_infos)
            kwargs = _add_value_to_kwargs(kwargs, key, obj)
            return (args, kwargs)

        return AuthWorkflow(
            self, process_arguments=_inject_object, ignore_no_authn=(not strict)
        ).decorate_view_func

    def inject_user_infos(self, key="user_infos", strict=True) -> Callable:
        return self.inject_object(key=key, strict=strict)

    def _requirement_auth_disabled(self):
        return (
            "yes"
            == os.environ.get(
                "DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER", ""
            ).lower()
        )

    def requires(
        self,
        requirements: Union[REQUIREMENT, List[REQUIREMENT]],
        on_failure: Optional[ON_FAILURE] = None,
    ):
        """returns decorator that only allows users, which fit the requirements
        If the requirements are callables, they are evaluated at runtime of the view_func,
        not at import time.
        """
        return AuthWorkflow(
            self, user_requirements=requirements, on_failure=on_failure
        ).decorate_view_func

    def _get_access_level_requirement(self, access_level_name: str) -> Requirement:
        requirement = None
        for level in self.access_levels:
            if level.name == access_level_name:
                requirement = level.requirement
                break

        if requirement is None:
            raise FlaatException(
                f"Access level name '{access_level_name}' not found. Configure in 'access_levels'"
            )

        if callable(requirement):
            # we already get lazy evaluated. So we don't stack levels of lazyness here
            return requirement()

        return requirement

    def access_level(
        self, access_level_name: str, on_failure: Optional[ON_FAILURE] = None
    ):
        """access_level only allows users which fit the requirement of the given access level.
        The requirements are specified in self.access_level_requirement
        """

        return self.requires(
            self._get_access_level_requirement(access_level_name), on_failure=on_failure
        )


class AuthWorkflow:
    """
    Encapsulate the complete workflow of a decorator
    - authenticating the users
    - checking its authorization
    - checking the request parameters against the authorization
    - ...
    """

    def __init__(
        self,
        flaat: BaseFlaat,
        user_requirements: Union[REQUIREMENT, List[REQUIREMENT]] = None,
        request_requirements: Union[
            REQUEST_REQUIREMENT, List[REQUEST_REQUIREMENT]
        ] = None,
        process_arguments: Callable[
            [UserInfos, tuple, dict], Tuple[tuple, dict]
        ] = None,
        on_failure: Callable[
            [FlaatException, Optional[UserInfos]], Union[Any, NoReturn]
        ] = None,
        ignore_no_authn=False,
    ):
        self.flaat = flaat
        self.user_requirements = (
            user_requirements if user_requirements is not None else []
        )
        self.request_requirements = (
            request_requirements if request_requirements is not None else []
        )
        self._process_arguments = process_arguments
        self.on_failure = on_failure
        self.ignore_no_authn = ignore_no_authn

    def authenticate_user(self, *args, **kwargs) -> Optional[UserInfos]:
        return self.flaat.authenticate_user(*args, **kwargs)

    def check_user_authorization(self, user_infos: UserInfos) -> CheckResult:
        reqs = []
        for req in (
            self.user_requirements
            if isinstance(self.user_requirements, list)
            else [self.user_requirements]
        ):
            reqs.append(req() if callable(req) else req)

        satisfied = True
        failure_messages = []
        for req in reqs:
            check_result = req.is_satisfied_by(user_infos)
            if not check_result.is_satisfied:
                failure_messages.append(check_result.message)
                satisfied = False

        if satisfied:
            return CheckResult(True, "")

        failure_message = "\n".join(failure_messages)
        return CheckResult(
            False, f"User {user_infos} does not meet requirements: {failure_message}"
        )

    def check_request_authorization(
        self, user_infos: UserInfos, *args, **kwargs
    ) -> CheckResult:
        satisfied = True
        failure_messages = []
        for req in (
            self.request_requirements
            if isinstance(self.request_requirements, list)
            else [self.request_requirements]
        ):
            check_result = req(user_infos, *args, **kwargs)
            if not check_result.is_satisfied:
                failure_messages.append(check_result.message)
                satisfied = False

        if satisfied:
            return CheckResult(True, "")

        failure_message = "\n".join(failure_messages)
        return CheckResult(
            False,
            f"Request from user {user_infos} does not meet requirements: {failure_message}",
        )

    def handle_failure(
        self, exception: FlaatException, user_infos: Optional[UserInfos]
    ) -> Union[Any, NoReturn]:
        if self.on_failure is not None:
            try:
                return self.on_failure(exception, user_infos)
            except FlaatException as e:
                return self.flaat.map_exception(e)

        return self.flaat.map_exception(exception)

    def handle_no_user_authentication(self, message) -> Union[Any, NoReturn]:
        self.handle_failure(FlaatUnauthenticated(message), None)

    def handle_no_user_authorization(
        self, message, user_infos: UserInfos
    ) -> Union[Any, NoReturn]:
        self.handle_failure(FlaatForbidden(message), user_infos)

    def handle_no_request_authorization(
        self, message, user_infos: UserInfos
    ) -> Union[Any, NoReturn]:
        self.handle_failure(FlaatForbidden(message), user_infos)

    def process_arguments(
        self, user_infos: UserInfos, *args, **kwargs
    ) -> Tuple[tuple, dict]:
        if self._process_arguments is not None:
            return self._process_arguments(user_infos, *args, **kwargs)
        return (args, kwargs)

    def _run_work_flow(
        self, *args, **kwargs
    ) -> Tuple[Tuple[tuple, dict], Optional[Any]]:
        """
        returns: (((args, kwargs) | None), (error_response | None))
        """
        user_infos = self.authenticate_user(*args, **kwargs)
        if user_infos is None:
            if self.ignore_no_authn:
                # No error, but also do nothing else
                return ((args, kwargs), None)

            # Fail without user infos
            return (
                (args, kwargs),
                self.handle_no_user_authentication(
                    "User identity could not be determined"
                ),
            )

        user_authz_check = self.check_user_authorization(user_infos)
        if not user_authz_check.is_satisfied:
            return (
                (args, kwargs),
                self.handle_no_user_authorization(user_authz_check.message, user_infos),
            )

        request_authz_check = self.check_request_authorization(
            user_infos, *args, **kwargs
        )
        if not request_authz_check.is_satisfied:
            return (
                (args, kwargs),
                self.handle_no_request_authorization(
                    request_authz_check.message, user_infos
                ),
            )

        return (self.process_arguments(user_infos, *args, **kwargs), None)

    def decorate_view_func(self, view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            ((args, kwargs), error_response) = self._run_work_flow(*args, **kwargs)
            if error_response is not None:
                return error_response
            return view_func(*args, **kwargs)

        @wraps(view_func)
        async def async_wrapper(*args, **kwargs):
            ((args, kwargs), error_response) = self._run_work_flow(*args, **kwargs)
            if error_response is not None:
                return error_response
            return await view_func(*args, **kwargs)

        if iscoroutinefunction(view_func):
            return async_wrapper
        return wrapper
