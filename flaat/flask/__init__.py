import json
import logging

from flask import request
from flask.wrappers import Response
from werkzeug.exceptions import Forbidden, InternalServerError, Unauthorized

from flaat import BaseFlaat, FlaatException, FlaatForbidden, FlaatUnauthenticated

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _get_request(self, *_, **__):
        return request

    def _get_header_from_request(self, _, name) -> str:
        # using flask global "request" here, not an argument
        return request.headers.get(name, "")

    def _make_response(self, data, status_code: int):
        return Response(
            response=json.dumps(data),
            status=status_code,
            mimetype="application/json",
        )
