import logging
import os

logger = logging.getLogger("")  # => This is the key to allow logging from other modules


class PathTruncatingFormatter(logging.Formatter):
    """formatter for logging"""

    def format(self, record):
        pathname = record.pathname
        if len(pathname) > 23:
            pathname = f"...{pathname[-19:]}"
        record.pathname = pathname
        return super(PathTruncatingFormatter, self).format(record)


def setup_logging():
    """setup logging"""

    # Remove all other logging handlers
    for h in logger.handlers:
        logger.removeHandler(h)

    formatter = PathTruncatingFormatter(
        "[%(levelname)8s] [%(asctime)s] {%(pathname)23s:%(lineno)-3d} - %(message)s"
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Loglevel setup (similar as file)
    loglevel = os.environ.get("LOG", None)
    if loglevel is None:  # set the default:
        loglevel = "WARNING"
    logger.setLevel(loglevel)

    # turn off other logging:
    for other in ["werkzeug", "urllib3", "requests_cache"]:
        other_log = logging.getLogger(other)
        other_log.setLevel(logging.CRITICAL)
        other_log.addHandler(handler)

    return logger
