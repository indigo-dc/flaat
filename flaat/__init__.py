"""FLAsk support for OIDC Access Tokens -- FLAAT.
Use decorators for authorising access to OIDC authenticated REST APIs.
"""
# This code is distributed under the MIT License

from asyncio import iscoroutinefunction
from functools import wraps
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Union

import aarc_entitlement

from flaat import issuertools
from flaat.tokentools import AccessTokenInfo
from flaat.caches import Issuer_config_cache
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated
from flaat.user_infos import UserInfos

logger = logging.getLogger(__name__)

# No leading slash ('/') in ops_that_support_jwt !!!
OPS_THAT_SUPPORT_JWT = [
    "https://iam-test.indigo-datacloud.eu",
    "https://iam.deep-hybrid-datacloud.eu",
    "https://iam.extreme-datacloud.eu",
    "https://wlcg.cloud.cnaf.infn.it",
    "https://aai.egi.eu/oidc",
    "https://aai-dev.egi.eu/oidc",
    "https://oidc.scc.kit.edu/auth/realms/kit",
    "https://unity.helmholtz-data-federation.de/oauth2",
    "https://login.helmholtz-data-federation.de/oauth2",
    "https://login-dev.helmholtz.de/oauth2",
    "https://login.helmholtz.de/oauth2",
    "https://b2access.eudat.eu/oauth2",
    "https://b2access-integration.fz-juelich.de/oauth2",
    "https://services.humanbrainproject.eu/oidc",
    "https://login.elixir-czech.org/oidc",
]


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


class FlaatConfig:
    def __init__(self):
        self.trusted_op_list: List[str] = []
        self.iss: str = ""
        self.op_hint: str = ""
        self.trusted_op_file: str = ""
        self.verify_tls: bool = True
        self.client_id: str = ""
        self.client_secret: str = ""
        self.num_request_workers: int = 10
        self.client_connect_timeout: float = 1.2  # seconds
        self.ops_that_support_jwt: List[str] = OPS_THAT_SUPPORT_JWT
        self.claim_search_precedence: List[str] = ["userinfo", "access_token"]
        self.raise_error_on_return = True  # else just return an error

    def set_verbosity(self, verbosity: int):
        if verbosity < 0 or verbosity > 3:
            raise ValueError("Verbosity needs to be [0-3]")
        level = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO,
            3: logging.DEBUG,
        }[verbosity]
        # TODO also set the framework specific loggers
        logger.setLevel(level)

    def set_cache_lifetime(self, lifetime):
        """Set cache lifetime of requests_cache zn seconds, default: 300s"""
        issuertools.cache_options.set_lifetime(lifetime)

    def set_cache_allowable_codes(self, allowable_codes):
        """set http status code that will be cached"""
        issuertools.cache_options.set_allowable_codes(allowable_codes)

    def set_cache_backend(self, backend):
        """set the cache backend"""
        issuertools.cache_options.backend = backend

    def set_trusted_OP(self, iss):
        """Define OIDC Provider. Must be a valid URL. E.g. 'https://aai.egi.eu/oidc/'
        This should not be required for OPs that put their address into the AT (e.g. keycloak, mitre,
        shibboleth)"""
        self.iss = iss.rstrip("/")

    def set_trusted_OP_list(self, trusted_op_list: List[str]):
        """Define a list of OIDC provider URLs.
        E.g. ['https://iam.deep-hybrid-datacloud.eu/', 'https://login.helmholtz.de/oauth2/', 'https://aai.egi.eu/oidc/']"""
        self.trusted_op_list = []
        for issuer in trusted_op_list:
            self.trusted_op_list.append(issuer.rstrip("/"))

        # iss_config = issuertools.find_issuer_config_in_list(self.trusted_op_list, self.op_hint,
        #         exclude_list = [])
        # self.issuer_config_cache.add_list(iss_config)

    def set_trusted_OP_file(self, filename="/etc/oidc-agent/issuer.config", hint=None):
        """Set filename of oidc-agent's issuer.config. Requires oidc-agent to be installed."""
        self.trusted_op_file = filename
        self.op_hint = hint

    def set_OP_hint(self, hint):
        """String to specify the hint. This is used for regex searching in lists of providers for
        possible matching ones."""
        self.op_hint = hint

    def set_verify_tls(self, param_verify_tls=True):
        """Whether to verify tls connections. Only use for development and debugging"""
        self.verify_tls = param_verify_tls
        issuertools.verify_tls = param_verify_tls

    def set_client_id(self, client_id):
        """Client id. At the moment this one is sent to all matching providers. This is only
        required if you need to access the token introspection endpoint. I don't have a use case for
        that right now."""
        # FIXME: consider client_id/client_secret per OP.
        self.client_id = client_id

    def set_client_secret(self, client_secret):
        """Client Secret. At the moment this one is sent to all matching providers."""
        self.client_secret = client_secret

    def set_num_request_workers(self, num):
        """set number of request workers"""
        self.num_request_workers = num
        issuertools.num_request_workers = num

    def get_num_request_workers(self):
        """get number of request workers"""
        return self.num_request_workers

    def set_client_connect_timeout(self, num):
        """set timeout for flaat connecting to OPs"""
        self.client_connect_timeout = num

    def get_client_connect_timeout(self):
        """get timeout for flaat connecting to OPs"""
        return self.client_connect_timeout

    def set_iss_config_timeout(self, num):
        """set timeout for connections to get config from OP"""
        issuertools.timeout = num

    def get_iss_config_timeout(self):
        """set timeout for connections to get config from OP"""
        return issuertools.timeout

    def set_timeout(self, num):
        """set global timeouts for http connections"""
        self.set_iss_config_timeout(num)
        self.set_client_connect_timeout(num)

    def get_timeout(self):
        """get global timeout for https connections"""
        return (self.get_iss_config_timeout(), self.get_client_connect_timeout())

    def set_claim_search_precedence(self, a_list):
        """set order in which to search for specific claim"""
        self.claim_search_precedence = a_list

    def get_claim_search_precedence(self):
        """get order in which to search for specific claim"""
        return self.claim_search_precedence


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

    def _auth_disabled(self):
        return (
            "yes"
            == os.environ.get(
                "DISABLE_AUTHENTICATION_AND_ASSUME_AUTHENTICATED_USER", ""
            ).lower()
        )

    def _auth_get_all_info(self, *args, **kwargs):
        request_object = self._get_request(*args, **kwargs)
        return self.get_all_info_from_request(request_object)

    def _determine_number_of_required_matches(
        self, match: Union[str, int], req_group_list: list
    ) -> int:
        """determine the number of required matches from parameters"""

        if match == "all":
            return len(req_group_list)

        if isinstance(match, int):
            return min(match, len(req_group_list))

        raise FlaatException("Argument 'match' has invalid value: Must be 'all' or int")

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

    def authenticate_user(self, *args, **kwargs) -> UserInfos:
        """authenticate user needs the same arguments as the view_func it is called from."""

        request_object = self._get_request(*args, **kwargs)
        access_token = self.get_access_token_from_request(request_object)
        logger.debug("Access token: %s", access_token)

        infos = UserInfos(self, access_token)
        logger.info("Authenticated user: %s @ %s", infos.subject, infos.issuer)

        return infos

    def _get_required_authz_func(
        self,
        # list of required claim values
        required: list,
        claim: str,
        match: Union[str, int],
        # parse an entitlement
        parser: Callable[[str], Any] = None,
        # compare two parsed entitlements
        comparator: Callable[[Any, Any], bool] = None,
    ) -> Callable[[UserInfos], bool]:

        inner_comparator = comparator
        if inner_comparator is None:
            inner_comparator = lambda r, a: r == a

        def authz_func(user_infos: UserInfos):
            avail_raw = self._get_effective_entitlements_from_claim(user_infos, claim)
            if avail_raw is None:
                raise FlaatForbidden("No group memberships found")

            avail_parsed = []

            if parser is None:
                avail_parsed = avail_raw
            else:
                avail_parsed = [parser(r) for r in avail_raw]

            logger.debug("Required: %s - Available: %s", required, avail_parsed)
            required_matches = self._determine_number_of_required_matches(
                match, required
            )
            matches_found = 0

            for req in required:
                for avail in avail_parsed:
                    if inner_comparator(req, avail):
                        matches_found += 1

            logger.info("Found %d of %d matches", matches_found, required_matches)

            if matches_found < required_matches:
                raise FlaatForbidden(
                    f"Matched {matches_found} groups, but needed {required_matches}"
                )

            return True

        return authz_func

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
                except FlaatException as e:
                    return self._map_exception(e)

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

    def _get_auth_decorator(
        self,
        authn_func: Callable,  # authenticate the user
        authz_func: Callable[[UserInfos], bool],  # has the user authorization?
        on_failure: Callable[[FlaatException], Any] = None,
    ) -> Callable[[Callable], Callable]:
        def _authenticate(*args, **kwargs):
            if not self._auth_disabled():
                # auth_func raises an exception if unauthorized
                logger.debug("Executing authn_func")
                user_infos = authn_func(self, *args, **kwargs)
                if user_infos is None:
                    raise FlaatUnauthenticated("Could not determine identity of user")

                logger.debug("Executing authz_func")
                if not authz_func(user_infos):
                    raise FlaatForbidden("User is not permitted to use service")

            return kwargs

        def decorator(view_func: Callable) -> Callable:
            return self._wrap_view_func(
                view_func,
                process_kwargs=_authenticate,
                handle_exception=on_failure,
            )

        return decorator

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

    def login_required(
        self,
        # manually check the user infos for a login condition
        check_user: Callable[[UserInfos], bool] = None,
        on_failure: Callable = None,
    ):
        def hasIssuerAndSub(infos: UserInfos) -> bool:
            return infos.issuer != "" and infos.subject != ""

        if check_user is None:
            check_user = hasIssuerAndSub

        return self._get_auth_decorator(
            authn_func=self.authenticate_user,
            authz_func=check_user,
            on_failure=on_failure,
        )

    def group_required(
        self,
        group: Union[str, List[str]],
        claim: str,
        on_failure: Callable = None,
        # python >= 3.8 could use:
        # match: Union[Literal["all"], Literal["one"], int] = "all",
        match: Union[str, int] = "all",
    ) -> Callable:
        """Decorator to enforce membership in a given group.
        group is the name (or list) of the group to match
        match specifies how many of the given groups must be matched. Valid values for match are
        'all', 'one', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page"""

        required = self._parse(group)

        return self._get_auth_decorator(
            authn_func=self.authenticate_user,
            authz_func=self._get_required_authz_func(required, claim, match),
            on_failure=on_failure,
        )

    @staticmethod
    def _aarc_entitlement_parser(
        entitlement: str,
    ):
        try:
            return aarc_entitlement.G069(entitlement)
        except aarc_entitlement.Error as e:
            logger.error("Error parsing aarc entitlement: %s", e)
            return None

    @staticmethod
    def _parse(
        raw_ents: Union[str, List[str]], parser: Optional[Callable] = None
    ) -> list:
        """parses groups or entitlements"""
        raw_ents_list = ensure_is_list(raw_ents)
        if parser is None:
            return raw_ents_list

        parsed_ents = []
        for raw_ent in raw_ents_list:
            parsed = parser(raw_ent)
            if parsed is None:
                raise FlaatException(f"Can not parse entitelment: {raw_ent}")
            parsed_ents.append(parsed)

        return parsed_ents

    @staticmethod
    def _aarc_entitlement_comparator(
        req: aarc_entitlement.Base, avail: aarc_entitlement.Base
    ) -> bool:
        return avail.satisfies(req)

    def aarc_entitlement_required(
        self,
        entitlement: Union[str, List[str]],
        claim: str,
        on_failure: Callable = None,
        match: Union[str, int] = "all",
    ) -> Callable:
        """Decorator to enforce membership in a given group defined according to AARC-G002.

        entitlement is the name (or list) of the entitlement to match
        match specifies how many of the given groups must be matched. Valid values for match are
        'all', or an integer
        on_failure is a function that will be invoked if there was no valid user detected.
        Useful for redirecting to some login page
        """
        parsed_ents = self._parse(entitlement, parser=self._aarc_entitlement_parser)

        return self._get_auth_decorator(
            authn_func=self.authenticate_user,
            authz_func=self._get_required_authz_func(
                parsed_ents,
                claim,
                match,
                parser=self._aarc_entitlement_parser,
                comparator=self._aarc_entitlement_comparator,
            ),
            on_failure=on_failure,
        )
