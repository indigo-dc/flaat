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

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        try:
            return f"{str(request_object.client.host)}:{str(request_object.client.port)}--{str(request_object.url)}"
        except AttributeError as e:
            logger.error(f"Cannot identify the request: {e}\n{request_object}")
            raise e

    def _wrap_async_call(self, func, *args, **kwargs):
        """wrap function call so that it is awaited when necessary"""

        def get_or_create_eventloop():
            try:
                return asyncio.get_event_loop()
            except RuntimeError:
                # if "There is no current event loop in thread" in str(ex):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return asyncio.get_event_loop()

        # TODO was this ever needed? pyright complains about func not being callable in this
        # case
        # if (asyncio.iscoroutine(func)):
        #     return get_or_create_eventloop().run_until_complete(func(*args, **kwargs))
        if asyncio.iscoroutinefunction(func):
            return get_or_create_eventloop().run_until_complete(func(*args, **kwargs))

        return func(*args, **kwargs)

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
