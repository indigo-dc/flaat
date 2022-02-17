import logging

from werkzeug.exceptions import Unauthorized, Forbidden, InternalServerError

from flask import request

from flaat import BaseFlaat, FlaatException, FlaatUnauthenticated, FlaatForbidden

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def map_exception(self, exception: FlaatException):
        framework_exception = InternalServerError

        if isinstance(exception, FlaatForbidden):
            framework_exception = Forbidden
        elif isinstance(exception, FlaatUnauthenticated):
            framework_exception = Unauthorized

        message = str(exception)
        logger.info("%s: %s", framework_exception, message)
        raise framework_exception(description=message) from exception

    def _get_request(self, *_, **__):
        return request

    def _get_header_from_request(self, _, name) -> str:
        # using flask global "request" here, not an argument
        return request.headers.get(name, "")
