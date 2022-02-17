class FlaatException(Exception):
    """
    An error occured inside flaat. The cause can be misconfiguration
    or other not user related errors.
    This exception will cause a response with status 500 if unhandled.
    """


class FlaatForbidden(FlaatException):
    """
    The user is forbidden from using the service.
    This exception will cause a response with status 403 if unhandled.
    """


class FlaatUnauthenticated(FlaatException):
    """
    The users identity could not be determined. Probably there was no access token
    or the access tokens issuer could not be determined.

    This exception will cause a response with status 401 if unhandled.
    """
