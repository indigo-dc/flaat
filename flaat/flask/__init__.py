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

    def get_access_token_from_request(self, _) -> str:
        # using flask global "request" here, not an argument
        if not "Authorization" in request.headers:
            raise FlaatUnauthenticated("No authorization header in request")

        header = request.headers.get("Authorization")
        if not header.startswith("Bearer "):
            raise FlaatUnauthenticated("Authorization header must contain bearer token")

        return header.replace("Bearer ", "")
