class FlaatException(Exception):
    """500"""


class FlaatForbidden(FlaatException):
    """403"""


class FlaatUnauthenticated(FlaatException):
    """401"""
