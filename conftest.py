import logging

logging.getLogger("requests_cache").setLevel(logging.WARN)
logging.getLogger("urllib3").setLevel(logging.WARN)
logging.getLogger("asyncio").setLevel(logging.WARN)
