import logging

from fastapi import HTTPException, Request

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def map_exception(self, exception: FlaatException):
        framework_exception = HTTPException
        status_code = 500

        if isinstance(exception, FlaatUnauthenticated):
            status_code = 401
        elif isinstance(exception, FlaatForbidden):
            status_code = 403

        message = str(exception)
        logger.info(
            "%s (Status: %d): %s", framework_exception.__name__, status_code, message
        )
        raise framework_exception(
            status_code=status_code, detail=message
        ) from exception

    def _get_request(self, *_, **kwargs):
        if "request" not in kwargs:  # pragma: no cover
            raise FlaatException("No request parameter in view function!")

        return kwargs["request"]

    def _get_header_from_request(self, request: Request, name: str) -> str:
        return request.headers.get(name, "")
