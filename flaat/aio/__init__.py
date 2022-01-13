import logging

# framework specific imports
from aiohttp import web
from aiohttp.web_exceptions import HTTPError

from .. import BaseFlaat

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _return_formatter_wf(self, return_value, status=200):
        """Return the object appropriate for the chosen web framework"""
        if status != 200:
            logger.error(
                f"Incoming request [{self.request_id}] http status: {status} - {self.get_last_error()}"
            )
            if self.raise_error_on_return:
                raise HTTPError(text=str(self.get_last_error))

        return web.Response(text=return_value, status=status)

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        # request_object = self._find_request_based_on_web_framework(request, args, kwargs)
        the_id = ""
        try:
            the_id = str(request_object.remote) + "--" + str(request_object.url)
        except AttributeError as e:
            logger.error(f"Cannot identify the request: {e}\n{the_id}")
        return the_id

    # FIXME
    def _get_request(self, *args, **_):
        """overwritten in subclasses"""
        return args[0]
