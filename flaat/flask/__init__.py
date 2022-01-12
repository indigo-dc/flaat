from .. import Flaat
import logging

from flask import request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


class FlaatExceptionFlask(HTTPException):
    """Call the corresponding web framework exception, with a custom reason"""

    def __init__(self, status_code, reason=None, **_):
        self.code = status_code
        if reason:
            self.description = reason
        super().__init__()


class FlaatFlask(Flaat):
    def _return_formatter_wf(self, return_value, status=200):
        """Return the object appropriate for the chosen web framework"""
        if status != 200:
            logger.error(
                f"Incoming request [{self.request_id}] http status: {status} - {self.get_last_error()}"
            )
        if self.raise_error_on_return:
            raise FlaatExceptionFlask(reason=return_value, status_code=status)
        return (return_value, status)

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        # request_object = self._find_request_based_on_web_framework(request, args, kwargs)
        the_id = ""
        try:
            the_id = f"{str(request_object.remote_addr)}--" + str(
                request_object.base_url
            )
        except AttributeError as e:
            logger.error(f"Cannot identify the request: {e}\n{the_id}")
        return the_id

    def _find_request_based_on_web_framework(self, *args, **kwargs):
        # FIXME this is probably broken
        return args[0]
