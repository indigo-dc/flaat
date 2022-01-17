class FlaatException(Exception):
    """500"""

    pass


class FlaatForbidden(FlaatException):
    """403"""

    pass


class FlaatUnauthorized(FlaatException):
    """401"""

    pass
