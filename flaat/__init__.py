"""FLAsk support for OIDC Access Tokens -- FLAAT.
Use decorators for authorising access to OIDC authenticated REST APIs.
"""
# This code is distributed under the MIT License

from asyncio import iscoroutinefunction
from functools import wraps
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Union

from flaat import issuertools
from flaat.config import FlaatConfig
from flaat.caches import Issuer_config_cache
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.requirements import Requirement
from flaat.tokentools import AccessTokenInfo
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)


class BaseFlaat(FlaatConfig):
    """FLAsk support for OIDC Access Tokens.
    Provide decorators and configuration for OIDC"""

    def __init__(self):
        super().__init__()
        self.issuer_config_cache = Issuer_config_cache()
        # maps issuer to issuer configs
        self.accesstoken_issuer_cache: Dict[str, str] = {}  # maps accesstoken to issuer
        # self.request_id = "unset"

    # SUBCLASS STUBS
    def get_request_id(self, request_object) -> str:
        _ = request_object
        # raise NotImplementedError("use framework specific sub class")
        return ""

    def _get_request(self, *args, **kwargs):
        """overwritten in subclasses"""
        # raise NotImplementedError("implement in subclass")
        _ = args
        _ = kwargs
        return {}

    def _map_exception(self, exception: FlaatException):
        _ = exception

    def _wrap_async_call(self, func, *args, **kwargs):
        """may be overwritten in in sub class"""
        return func(*args, **kwargs)

    def get_access_token_from_request(self, request) -> str:
        """Helper function to obtain the OIDC AT from the flask request variable"""
        _ = request
        return ""

    # END SUBCLASS STUBS

    def _issuer_is_trusted(self, issuer):
        return issuer.rstrip("/") in self.trusted_op_list

    # TODO this method is way too long
    def _find_issuer_config_everywhere(
        self, access_token, access_token_info: Optional[AccessTokenInfo]
    ) -> dict:

        # 0: Use accesstoken_issuer cache to find issuerconfig:
        logger.debug("find_issuer - 0: In cache")
        if access_token in self.accesstoken_issuer_cache:
            issuer = self.accesstoken_issuer_cache[access_token]
            iss_config = self.issuer_config_cache.get(issuer)

            if iss_config is None:
                raise FlaatUnauthenticated(
                    f"Issuer config in cache but None for: {issuer}"
                )

            return iss_config

        # 1: find info in the AT
        logger.debug("find_issuer - 1: In access_token")
        if access_token_info is not None:
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

        # 2: use a provided string
        logger.debug('find_issuer - 2: From "set_iss"')
        iss_config = issuertools.find_issuer_config_in_string(self.iss)
        if iss_config is not None:
            return iss_config

        # 3: Try the provided list of providers:
        logger.debug("find_issuer - 3: From trusted_op_list")
        iss_config = issuertools.find_issuer_config_in_list(
            self.trusted_op_list, self.op_hint, exclude_list=self.ops_that_support_jwt
        )
        if iss_config is not None:
            return iss_config

        raise FlaatUnauthenticated("Could not determine issuer config")

    def get_all_info_from_request(self, param_request):
        try:
            access_token = self.get_access_token_from_request(param_request)
            logger.debug("Access token: %s", access_token)
            return UserInfos(self, access_token)
        except FlaatException as e:
            return self._map_exception(e)

    def _auth_get_all_info(self, *args, **kwargs):
        request_object = self._get_request(*args, **kwargs)
        return self.get_all_info_from_request(request_object)

    def authenticate_user(self, *args, **kwargs) -> UserInfos:
        """authenticate user needs the same arguments as the view_func it is called from."""

        request_object = self._get_request(*args, **kwargs)
        access_token = self.get_access_token_from_request(request_object)
        logger.debug("Access token: %s", access_token)

        infos = UserInfos(self, access_token)
        logger.info("Authenticated user: %s @ %s", infos.subject, infos.issuer)

        return infos

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

    def inject_user_infos(self, view_func: Callable, key="user_infos") -> Callable:
        def _add_user_infos(*args, **kwargs):
            request_object = self._get_request(self, *args, **kwargs)
            infos = self.get_all_info_from_request(request_object)
            kwargs = self._add_value_to_kwargs(kwargs, key, infos)
            return kwargs

        return self._wrap_view_func(view_func, process_kwargs=_add_user_infos)

    def inject_user(
        self,
        infos_to_user: Callable[[UserInfos], Any],
        key="user",
    ) -> Callable:
        """Injects a user into a view function given a method to translate a UserInfos instance into the user"""

        def _inject_user(*args, **kwargs):
            request_object = self._get_request(self, *args, **kwargs)
            infos = self.get_all_info_from_request(request_object)
            user = None

            if infos is not None:
                user = infos_to_user(infos)
                kwargs = self._add_value_to_kwargs(kwargs, key, user)

            return kwargs

        def decorator(view_func: Callable) -> Callable:
            return self._wrap_view_func(view_func, process_kwargs=_inject_user)

        return decorator

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
        def _user_has_authorization(user_infos: UserInfos) -> bool:
            reqs = []
            if isinstance(requirements, list):
                reqs = requirements
            else:
                reqs = [requirements]

            # pylint: disable=use-a-generator
            return all(req.satisfied_by(user_infos) for req in reqs)

        def _authenticate(*args, **kwargs):
            if not self._requirement_auth_disabled():
                user_infos = self.authenticate_user(self, *args, **kwargs)
                if user_infos is None:
                    raise FlaatUnauthenticated("Could not determine identity of user")

                if not _user_has_authorization(user_infos):
                    raise FlaatForbidden("User is not permitted to use service")

            return kwargs

        def decorator(view_func: Callable) -> Callable:
            return self._wrap_view_func(
                view_func,
                process_kwargs=_authenticate,
                handle_exception=on_failure,
            )

        return decorator
