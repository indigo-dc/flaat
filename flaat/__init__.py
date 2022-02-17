"""
Python support for OIDC Access Tokens -- FLAAT.
Use decorators for authorising access to OIDC authenticated REST APIs.
"""
# This code is distributed under the MIT License

from __future__ import annotations
from asyncio import iscoroutinefunction
from functools import wraps
import logging
import os
from typing import Any, Callable, List, NoReturn, Optional, Tuple, Union

from cachetools import cached

from flaat.access_tokens import AccessTokenInfo, get_access_token_info
from flaat.caches import (
    access_token_issuer_cache,
    issuer_config_cache,
    user_infos_cache,
)
from flaat.config import FlaatConfig, OPS_THAT_SUPPORT_JWT
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.issuers import IssuerConfig
from flaat.requirements import (
    CheckResult,
    REQUEST_REQUIREMENT,
    REQUIREMENT,
    HasSubIss,
    Requirement,
)
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

ENV_VAR_AUTHN_OVERRIDE = "DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER"
ENV_VAR_AUTHZ_OVERRIDE = "DISABLE_AUTHORIZATION_AND_ASSUME_AUTHORIZED_USER"

# MAP_EXCEPTION is the type for self.map_exception
# It map our exceptions to framework specific or custom exceptions
MAP_EXCEPTION = Callable[[FlaatException], NoReturn]

# ON_FAILURE is the type for on_failure functions
# these are called in place of a view function, if the authentication process resulted in an error
# on_failure functions may raise a framework specific exception, or return a valid response for the respective framework.
ON_FAILURE = Callable[[FlaatException, Optional[UserInfos]], Union[Any, NoReturn]]


class BaseFlaat(FlaatConfig):
    """
    Uses OIDC access tokens to provide authentication and authorization for multiple webframe works. This is the base class.
    Use the framework specific classes :class:`flaat.flask.Flaat`, :class:`flaat.aio.Flaat` and :class:`flaat.fastapi.Flaat` directly.

    You usually use a global instance of Flaat, configure it (see :class:`flaat.config.FlaatConfig`) and then access its decorators
    (e.g. :meth:`is_authenticated`, :meth:`requires`, :meth:`inject_object` and :meth:`access_level`).
    """

    @property
    def authentication_disabled(self):
        return "YES" == os.environ.get(ENV_VAR_AUTHN_OVERRIDE, "")

    @property
    def authorization_disabled(self):
        return "YES" == os.environ.get(ENV_VAR_AUTHZ_OVERRIDE, "")

    # SUBCLASS STUBS
    def _get_request(self, *args, **kwargs):  # pragma: no cover
        """overwritten in subclasses"""
        # raise NotImplementedError("implement in subclass")
        _ = args
        _ = kwargs
        return {}

    def map_exception(self, exception: FlaatException) -> NoReturn:  # pragma: no cover
        raise exception

    def _get_header_from_request(self, request, name: str) -> str:  # pragma: no cover
        """overwritten in subclasses"""
        _ = request
        return ""

    # END SUBCLASS STUBS

    def _get_access_token_from_request(self, request) -> str:
        value = self._get_header_from_request(request, "Authorization")
        if value == "":
            raise FlaatUnauthenticated("No authorization header")

        prefix = "Bearer "
        if not value.startswith(prefix):
            raise FlaatUnauthenticated("No bearer token in authorization header")

        return value.replace(prefix, "")

    def _issuer_is_trusted(self, issuer):
        return issuer.rstrip("/") in self.trusted_op_list

    @cached(cache=issuer_config_cache)
    def _get_issuer_config(self, iss) -> Optional[IssuerConfig]:
        issuer_config = IssuerConfig.get_from_string(
            iss, timeout=self.request_timeout, verify_tls=self.verify_tls
        )
        if issuer_config is None:
            return None

        # FIXME Having per issuer secrets would make more sense
        issuer_config.client_id = self.client_id
        issuer_config.client_secret = self.client_secret
        return issuer_config

    def _find_issuer_config(
        self, access_token, access_token_info: Optional[AccessTokenInfo], issuer_hint=""
    ) -> Optional[IssuerConfig]:

        # Issuer hint provided by user
        if issuer_hint != "":
            iss_config = self._get_issuer_config(issuer_hint)
            if iss_config is None:
                raise FlaatException(
                    f"Unable to retrieve issuer config: Issuer '{issuer_hint}' is probably invalid."
                )
            return iss_config

        # Manually set in the config
        if self.iss != "":
            iss_config = self._get_issuer_config(self.iss)
            if iss_config is None:
                raise FlaatException(
                    f"Unable to retrieve issuer config: Issuer from flaat config '{self.iss}' is probably invalid. Use `set_iss` to set a different issuer."
                )
            return iss_config

        # JWT AT
        if access_token_info is not None:
            logger.debug("Access token is a JWT")
            at_iss = access_token_info.issuer
            if at_iss is not None:
                if not self._issuer_is_trusted(at_iss):
                    raise FlaatUnauthenticated(f"Issuer is not trusted: {at_iss}")

                iss_config = self._get_issuer_config(at_iss)
                if iss_config is None:
                    raise FlaatUnauthenticated(
                        f"Unable to fetch issuer config for: {at_iss}"
                    )

                return iss_config

        # Try AT -> Issuer cache
        if access_token in access_token_issuer_cache:
            logger.debug("Cache hit for access_token")
            issuer = access_token_issuer_cache[access_token]
            iss_config = self._get_issuer_config(issuer)
            if iss_config is not None:
                return iss_config

        return None

    def _get_user_infos_brute_force(self, access_token) -> Optional[UserInfos]:
        logger.info("Issuer could not be determined -> trying all trusted OPs")
        # Nice to have: parallel would speed up things here
        for issuer in self.trusted_op_list:
            # skip OPs that would have provided a JWT
            if issuer in OPS_THAT_SUPPORT_JWT:
                continue

            logger.debug("Trying issuer: %s", issuer)
            issuer_config = self._get_issuer_config(issuer)
            if issuer_config is not None:
                user_infos = issuer_config.get_user_infos(access_token)
                if user_infos is not None:
                    logger.debug(
                        "Found issuer for access token: %s", issuer_config.issuer
                    )
                    access_token_issuer_cache[access_token] = issuer_config.issuer
                    return user_infos

        logger.warning("No trusted OP produced a user info for access token")
        return None

    @cached(cache=user_infos_cache)
    def get_user_infos_from_access_token(
        self, access_token: str, issuer_hint: str = ""
    ) -> Optional[UserInfos]:
        """
        This method is used to retrieve all infos about an user.
        You don't need to call this manually, as the decorators will automatically do it for you.


        :param access_token: The access token of the user. The token must not start with 'Bearer '.
        :return: A :class:`flaat.user_infos.UserInfos` instance with all the infos that could be retrieved.
            If no info could be retrieved, then `None` is returned.
        """
        if access_token == "":
            raise FlaatUnauthenticated("No access token")

        logger.debug("Access token: %s", access_token)
        access_token_info = get_access_token_info(access_token)
        issuer_config = self._find_issuer_config(
            access_token, access_token_info, issuer_hint=issuer_hint
        )
        if issuer_config is not None:
            return issuer_config.get_user_infos(
                access_token, access_token_info=access_token_info
            )

        # Last resort: Try all OPs
        return self._get_user_infos_brute_force(access_token)

    def get_user_infos_from_request(self, request_object) -> Optional[UserInfos]:
        access_token = self._get_access_token_from_request(request_object)
        if access_token == "":
            raise FlaatException("No access token from request")

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
        """
        Injects an object into a view function given a method to translate a UserInfos instance into the object.
        This is useful for injecting user model instances.

        :param infos_to_object: A function that translates a :class:`flaat.user_infos.UserInfos` instance to a custom object.
        :param key: The key with which the generated object is injected into the `kwargs` of the view function.
        :param strict: If set to `True` this decorator if fail when there is nothing to inject.
        :return: A decorator for a view function.
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
        """
        A decorator which injects the current users :class:`flaat.user_infos.UserInfos` into
        the view function.

        :param key: The key with which the user info is injected.
        :param strict: If set to `True`, an unauthenticated user will not be able to use the view functions
            and cause an error instead.
        :return: A decorator for a view function.
        """
        return self.inject_object(key=key, strict=strict)

    def requires(
        self,
        requirements: Union[REQUIREMENT, List[REQUIREMENT]],
        on_failure: Optional[ON_FAILURE] = None,
    ) -> Callable:
        """
        This returns a decorator that will make sure, that the user fits the requirements before the view function is called. If the user does not, an exception
            for the respective web framework will be thrown, so the user sees the correct error.

        :param requirements: One :class:`flaat.requirements.Requirement` instance or a list of requirements the user needs to fit to have access to the decorated function.
            If the requirements are wrapped in a callable, it will be lazy evaluated once the view_func is called.
        :param on_failure: Optional function to customize the handling of an error. This function can
            either raise an exception or return a response which should be returned in place of the response
            from the view function.
        :return: A decorator for a view function."""

        return AuthWorkflow(
            self,
            user_requirements=requirements,
            on_failure=on_failure,
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
        """
        :param access_level_name: The name of the access_level that the user needs to use the view function.
        :param on_failure: Can be used to either deliver an error response to the user, or raise a specific exception.
        :return: A decorator, that can be used to decorate a view function.
        """

        return self.requires(
            self._get_access_level_requirement(access_level_name), on_failure=on_failure
        )

    def is_authenticated(self, on_failure: ON_FAILURE = None) -> Callable:
        """
        This can be used to make sure that users are identified (as in they have a subject and an issuer).
        If you actually want to access the users infos we recommend using :meth:`inject_user_infos` or
        :meth:`inject_object` instead.

        :param on_failure: Can be used to either deliver an error response to the user, or raise a specific exception.
        :return: A decorator for a view function
        """
        return self.requires(HasSubIss, on_failure=on_failure)


class AuthWorkflow:
    """
    This class can be used if you need maximum customizability for your decorator.
    It encapsulates the complete workflow of a decorator.

    :param flaat: The flaat instance that is currently in use.
    :param user_requirements: Requirement which the user all needs to match, like with :meth:`requires`.
    :param request_requirements: A callable which determines if a users request is allowed to proceed.
        This function is handy if you want to evaluate the arguments for the view function before against the users permissions.
    :param process_arguments: As with :meth:`inject_object`, this can be used to inject data into the view function.
    :param on_failure: Can be used to either deliver an error response to the user, or raise a specific exception.
    :param ignore_no_authn: If set to `True` a failing authentication of the user will not cause exceptions.
    :returns: A class instance, which is used by decorating view functions with its :meth:`decorate_view_func` method.
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
        if self.flaat.authentication_disabled:
            logger.info(
                "Authentication and authorization are bypassed: Environment variable is set"
            )
            # No error, but also do nothing else
            return ((args, kwargs), None)

        user_infos = None
        try:
            user_infos = self.authenticate_user(*args, **kwargs)
        except FlaatException as e:
            return ((args, kwargs), self.handle_failure(e, None))

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

        if self.flaat.authorization_disabled:
            logger.info("Authorization is bypassed: Environment variable is set")
        else:
            user_authz_check = self.check_user_authorization(user_infos)
            if not user_authz_check.is_satisfied:
                return (
                    (args, kwargs),
                    self.handle_no_user_authorization(
                        user_authz_check.message, user_infos
                    ),
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
        """
        :param view_func: The view function to decorate.
        :return: The decorated view function.
        """

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
