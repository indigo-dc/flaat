import logging

from aiohttp.web_exceptions import HTTPForbidden, HTTPServerError, HTTPUnauthorized

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthorized

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _map_exception(self, exception):
        framework_exception = HTTPServerError

        if isinstance(exception, FlaatUnauthorized):
            framework_exception = HTTPUnauthorized
        elif isinstance(exception, FlaatForbidden):
            framework_exception = HTTPForbidden

        message = str(exception)
        logger.info("%s: %s", framework_exception.__name__, message)
        raise framework_exception(reason=message) from exception

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        # request_object = self._find_request_based_on_web_framework(request, args, kwargs)
        the_id = ""
        try:
            the_id = str(request_object.remote) + "--" + str(request_object.url)
        except AttributeError as e:
            logger.error("Cannot identify the request: %s\n%s", e, the_id)
        return the_id

    def _get_request(self, *args, **_):
        if len(args) < 2:
            raise FlaatException("Need argument 'request' for framework 'aio'")
        return args[1]

    def get_access_token_from_request(self, request) -> str:
        logger.debug("Request headers: %s", request.headers)
        if request.headers.get("Authorization", "").startswith("Bearer "):
            temp = request.headers["Authorization"].split("authorization header: ")[0]
            token = temp.split(" ")[1]
            return token

        raise FlaatUnauthorized("No access token")
