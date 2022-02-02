import asyncio
import logging

from fastapi import HTTPException, Request

from flaat import BaseFlaat
from flaat.exceptions import FlaatException, FlaatForbidden, FlaatUnauthenticated

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _map_exception(self, exception):
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

    # FIXME this is probably broken: kwargs and args are
    def _get_request(self, *args, **kwargs):
        if "request" not in kwargs:
            raise FlaatException("No request parameter in view function!")

        return kwargs["request"]

    def get_access_token_from_request(self, request: Request) -> str:
        if not "Authorization" in request.headers:
            raise FlaatUnauthenticated("No authorization header in request")

        header = request.headers.get("Authorization")
        if not header.startswith("Bearer "):
            raise FlaatUnauthenticated("Authorization header must contain bearer token")

        return header.replace("Bearer ", "")
