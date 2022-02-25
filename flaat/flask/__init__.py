import json
import logging

from flask import request
from flask.wrappers import Response

from flaat import BaseFlaat

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
