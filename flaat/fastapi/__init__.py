import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from flaat import BaseFlaat
from flaat.exceptions import FlaatException


logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _get_request(self, *_, **kwargs):
        if "request" not in kwargs:  # pragma: no cover
            raise FlaatException("No request parameter in view function!")

        return kwargs["request"]

    def _get_header_from_request(self, request: Request, name: str) -> str:
        return request.headers.get(name, "")

    def _make_response(self, data, status_code: int):
        return JSONResponse(
            data,
            status_code=status_code,
        )
