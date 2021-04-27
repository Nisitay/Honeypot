import logging
from .gui import GUI

LOG_PATH = r"Honeypot\common\app.log"
LOG_FORMAT = "%(levelname)s | %(asctime)s | %(name)s: %(message)s"

loggers = {}


class Logger:
    def __init__(self, name: str):
        if loggers.get(name):
            self._logger = loggers.get(name)
        else:
            self._logger = logging.getLogger(name)
            self._logger.setLevel(logging.DEBUG)
            loggers[name] = self._logger
            self.initialize_handlers()

    def initialize_handlers(self):
        logger_handlers = [
            logging.FileHandler(LOG_PATH),
            GuiLogger()
        ]
        for handler in logger_handlers:
            handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt="%d/%m/%Y,%H:%M:%S"))
            self._logger.addHandler(handler)

    def get_logger(self):
        return self._logger


class GuiLogger(logging.Handler):
    def __init__(self):
        super().__init__()

    def emit(self, record: str):
        msg = self.format(record)
        GUI.add_log(msg)
