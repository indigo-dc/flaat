import logging
import sys


def setup_logging():
    """setup logging"""
    formatter = logging.Formatter("%(levelname)s - %(message)s")

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    rootLogger = logging.getLogger()
    rootLogger.addHandler(handler)
    rootLogger.setLevel(logging.DEBUG)

    # turn off other logging:
    for other in ["werkzeug", "urllib3"]:
        other_log = logging.getLogger(other)
        other_log.setLevel(logging.CRITICAL)
