import logging
from .gui import GUI

LOG_FORMAT = "%(levelname)s | %(asctime)s | %(name)s: %(message)s"


class Logger():
    def __init__(self, name, log_path, extra_handlers=[]):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.DEBUG)

        logger_handlers = [
            logging.FileHandler(log_path),
            logging.StreamHandler(),
        ]
        logger_handlers.extend(extra_handlers)

        for handler in logger_handlers:
            handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt="%d-%m-%Y,%H:%M:%S"))
            self._logger.addHandler(handler)

    def get_logger(self):
        return self._logger


class FTPGuiLogger(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        msg = self.format(record)
        GUI.add_ftp_log(msg)


class HTTPGuiLogger(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record):
        msg = self.format(record)
        GUI.add_http_log(msg)
