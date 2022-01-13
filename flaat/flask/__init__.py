import logging

from werkzeug.exceptions import HTTPException

from flask import request

from .. import BaseFlaat

logger = logging.getLogger(__name__)


class FlaatExceptionFlask(HTTPException):
    """Call the corresponding web framework exception, with a custom reason"""

    def __init__(self, status_code, reason=None, **_):
        self.code = status_code
        if reason:
            self.description = reason
        super().__init__()


class Flaat(BaseFlaat):
    def _return_formatter_wf(self, return_value, status=200):
        """Return the object appropriate for the chosen web framework"""
        logger.error(f"[{self.request_id}] {status} - {self.get_last_error()}")
        if status != 200 and self.raise_error_on_return:
            raise HTTPException(description=return_value)
        return (return_value, status)

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        try:
            return f"{request_object.remote_addr}--{request_object.base_url}"
        except AttributeError as e:
            logger.error(f"Cannot identify the request: {e}")
            raise e

    def _get_request(self, *_, **__):
        return request
