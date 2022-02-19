from typing import Optional, Any


class FlaatException(Exception):
    """
    An error occured inside flaat. The cause can be misconfiguration
    or other not user related errors.
    This exception will cause a response with status 500 if unhandled.
    """

    name = "Error"
    status_code = 500
    data: Optional[Any] = None

    def render(self) -> dict:
        data = {
            "error": self.name,
            "error_description": str(self),
        }
        if self.data is not None:
            data["error_details"] = self.data
        return data


class FlaatForbidden(FlaatException):
    """
    The user is forbidden from using the service.
    This exception will cause a response with status 403 if unhandled.
    """

    name = "Forbidden"
    status_code = 403


class FlaatUnauthenticated(FlaatException):
    """
    The users identity could not be determined. Probably there was no access token
    or the access tokens issuer could not be determined.

    This exception will cause a response with status 401 if unhandled.
    """

    name = "Unauthenticated"
    status_code = 401
