import logging

from werkzeug.exceptions import Unauthorized, Forbidden, InternalServerError

from flask import request

from flaat import BaseFlaat, FlaatException, FlaatUnauthorized, FlaatForbidden

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _map_exception(self, exception: FlaatException):
        framework_exception = InternalServerError

        if isinstance(exception, FlaatForbidden):
            framework_exception = Forbidden
        elif isinstance(exception, FlaatUnauthorized):
            framework_exception = Unauthorized

        description = str(exception)
        logger.error(f"{framework_exception}: {description}")
        raise framework_exception(description=description)

    def get_request_id(self, request_object):
        """Return a string identifying the request"""
        try:
            return f"{request_object.remote_addr}--{request_object.base_url}"
        except AttributeError as e:
            logger.error(f"Cannot identify the request: {e}")
            raise e

    def _get_request(self, *_, **__):
        return request
