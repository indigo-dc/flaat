import logging

from aiohttp.web import Request, json_response

from flaat import BaseFlaat
from flaat.exceptions import FlaatException

logger = logging.getLogger(__name__)


class Flaat(BaseFlaat):
    def _get_request(self, *args, **kwargs):  # pyright: ignore
        for arg in list(args) + list(kwargs.values()):
            if isinstance(arg, Request):
                return arg

        logger.debug("args: %s - kwargs: %s", args, kwargs)
        raise FlaatException(
            f"Need argument 'request' for framework 'aio': Got args={args} kwargs={kwargs}"
        )

    def _get_header_from_request(self, request: Request, name) -> str:
        return request.headers.get(name, "")

    def _make_response(self, data: dict, status_code: int):
        return json_response(
            data=data,
            status=status_code,
        )
