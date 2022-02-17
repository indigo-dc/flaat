import logging

from aiohttp.web_exceptions import HTTPForbidden, HTTPServerError, HTTPUnauthorized
from aiohttp.web import Request

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def map_exception(self, exception: FlaatException):
        framework_exception = HTTPServerError

        if isinstance(exception, FlaatUnauthenticated):
            framework_exception = HTTPUnauthorized
        elif isinstance(exception, FlaatForbidden):
            framework_exception = HTTPForbidden

        message = str(exception)
        logger.info("%s: %s", framework_exception.__name__, message)
        raise framework_exception(reason=message) from exception

    def _get_request(self, *args, **kwargs):
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, Request):
                return arg

        logger.debug("args: %s - kwargs: %s", args, kwargs)
        raise FlaatException(
            f"Need argument 'request' for framework 'aio': Got args={args} kwargs={kwargs}"
        )

    def _get_header_from_request(self, request: Request, name) -> str:
        return request.headers.get(name, "")
