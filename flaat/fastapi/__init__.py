from .. import Flaat

# framework specific imports
import asyncio
from fastapi.responses import JSONResponse
from fastapi import HTTPException

import logging

logger = logging.getLogger(__name__)


# TODO remove these questionable custom exceptions
class FlaatExceptionFastapi(HTTPException):
    """Call the corresponding web framework exception, with a custom reason"""

    def __init__(self, status_code, reason=None, **_):
        self.code = status_code
        if reason:
            self.description = reason
            super().__init__(status_code=status_code, detail=reason)
        else:
            super().__init__(status_code=status_code)


class FlaatAIO(Flaat):
    def _return_formatter_wf(self, return_value, status=200):
        """Return the object appropriate for the chosen web framework"""
        if status != 200:
            logger.error(
                f"Incoming request [{self.request_id}] http status: {status} - {self.get_last_error()}"
            )
            if self.raise_error_on_return:
                raise FlaatExceptionFastapi(reason=return_value, status_code=status)

        return JSONResponse(content=return_value, status_code=status)

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

        logger.info(f"Incoming request [{self.request_id}] Success")
        return func(*args, **kwargs)

    # FIXME this is probably broken: kwargs and args are
    def _find_request_based_on_web_framework(self, *args, **kwargs):
        return kwargs["request"]
