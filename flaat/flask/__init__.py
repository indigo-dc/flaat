# type: ignore
# ignore all pyright errors in this file
import json
import logging
from typing import List

from flaat import BaseFlaat, config

from flask import current_app, request
from flask.wrappers import Response

logger = logging.getLogger(__name__)


# Standard Flask Extension, see:
# https://flask.palletsprojects.com/en/2.1.x/extensiondev/
class Flaat(BaseFlaat):
    def __init__(self, access_levels=config.DEFAULT_ACCESS_LEVELS, app=None):
        self.app = app
        self.access_levels = access_levels
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault("TRUSTED_OP_LIST", [])
        app.config.setdefault("FLAAT_ISS", "")
        app.config.setdefault("FLAAT_CLIENT_ID", "")
        app.config.setdefault("FLAAT_CLIENT_SECRET", "")
        app.config.setdefault("FLAAT_REQUEST_TIMEOUT", 1.2)  # seconds
        app.config.setdefault("FLAAT_VERIFY_TLS", True)
        app.config.setdefault("FLAAT_VERIFY_JWT", True)

    # Now here comes the dirty code to make the think possible, so
    # ATTENTION! This overrides FlaatConfig attr with properties

    @property
    def trusted_op_list(self):
        """Returns the list of Flaat trusted OIDC providers.
        :return: List of strings
        """
        return current_app.config["TRUSTED_OP_LIST"]

    def set_trusted_OP_list(self, trusted_ops: List[str]):
        """Sets a list of OIDC providers that you trust. This means that
        users of these OPs will be able to use your services.
        :param trusted_ops: A list of the issuer URLs that you trust.
            An example issuer is: 'https://iam.deep-hybrid-datacloud.eu/'.
        """
        trusted_ops = list(map(lambda iss: iss.rstrip("/"), trusted_ops))
        current_app.config["TRUSTED_OP_LIST"] = trusted_ops

    @property
    def iss(self):
        """Returns the Flaat configured issuer URL.
        :return: Issuer URL of the pinned issuer
        """
        return current_app.config["FLAAT_ISS"]

    def set_issuer(self, issuer: str):
        """Pins the given issuer. Only users of this issuer will be able
        to use services.
        :param issuer: Issuer URL of the pinned issuer.
        """
        current_app.config["FLAAT_ISS"] = issuer.rstrip("/")

    @property
    def client_id(self):
        """Returns the configured OIDC client id in Flaat.
        :return: OIDC client id
        """
        return current_app.config["FLAAT_CLIENT_ID"]

    def set_client_id(self, client_id=""):
        """Set a client id for token introspection.
        :param client_id: OIDC client id, default is empty string
        """
        # FIXME: consider client_id/client_secret per OP.
        current_app.config["FLAAT_CLIENT_ID"] = client_id

    @property
    def client_secret(self):
        """Returns the configured OIDC client secret in Flaat.
        :return: OIDC client secret
        """
        return current_app.config["FLAAT_CLIENT_SECRET"]

    def set_client_secret(self, client_secret=""):
        """Set a client secret for token introspection
        :param client_secret: OIDC client id, default is empty string
        """
        current_app.config["FLAAT_CLIENT_ID"] = client_secret

    @property
    def request_timeout(self):
        """Returns the timeout for individual requests.
        :return: Request timeout in seconds
        """
        return current_app.config["FLAAT_REQUEST_TIMEOUT"]

    def set_request_timeout(self, timeout: float = 1.2):
        """Set the timeout for individual requests (retrieving issuer configs,
        user infos and introspection infos). Note that the total runtime
        of a decorator could be significantly more, based on your
        `trusted_op_list`.
        :param timeout: Request timeout in seconds
        """
        current_app.config["FLAAT_REQUEST_TIMEOUT"] = timeout

    @property
    def verify_tls(self):
        """Skip TLS certificate verification while processing requests.
        :return: Boolean, indicates if TLS is enabled
        """
        return current_app.config["FLAAT_VERIFY_TLS"]

    def set_verify_tls(self, verify_tls=True):
        """*Only* use for development and debugging. Set to `False` to
        skip TLS certificate verification while processing requests.
        :param verify_tls: Boolean, false disables verification TLS
        """
        current_app.config["FLAAT_VERIFY_TLS"] = verify_tls

    @property
    def verify_jwt(self):
        """Skip JWT verification while processing requests.
        :return: Boolean, indicates if TLS is enabled
        """
        return current_app.config["FLAAT_VERIFY_JWT"]

    def set_verify_jwt(self, verify_jwt=True):
        """Set to `False` to skip JWT verification while processing requests.
        :param verify_jwt: Boolean, false disables JWT verification
        """
        current_app.config["FLAAT_VERIFY_JWT"] = verify_jwt

    # End of dirty code
    # Specific Flask methods to run flaat

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
