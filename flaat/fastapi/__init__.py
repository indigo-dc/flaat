import asyncio
import logging

# framework specific imports
from fastapi import HTTPException

from flaat import BaseFlaat
from flaat.exceptions import FlaatForbidden, FlaatUnauthorized

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _map_exception(self, e):
        if isinstance(e, FlaatUnauthorized):
            raise HTTPException(status_code=401, detail=str(e)) from e
        elif isinstance(e, FlaatForbidden):
            raise HTTPException(status_code=403, detail=str(e)) from e
        else:
            raise HTTPException(status_code=500, detail=str(e)) from e

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
        return kwargs["request"]
