class FlaatException(Exception):
    """500"""


class FlaatForbidden(FlaatException):
    """403"""


class FlaatUnauthorized(FlaatException):
    """401"""
