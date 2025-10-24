import logging
import colorlog
from datetime import datetime
import queue  # Needed to catch queue.Empty in timeout handling

class LogEvent():
    def __init__(self, log_level, name, message):
        self.log_level = log_level
        self.name = name
        self.message = message
        self.timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def __repr__(self):
        return f"{self.timestamp} [{self.name}] {self.message}"


class Logger():
    def __init__(self, log_queue, log_level, log_file, dead_pill):
        self.log_queue = log_queue
        self.log_level = log_level
        self.log_file = log_file
        self.dead_pill = dead_pill

    def run(self):
        colored_formatter = colorlog.ColoredFormatter(
            "%(log_color)s%(message)s",
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red'
            })

        log = logging.getLogger(__name__)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(colored_formatter)

        fileHandler = logging.FileHandler(self.log_file)
        clean_formatter = logging.Formatter("%(levelname)s %(message)s")
        fileHandler.setFormatter(clean_formatter)

        log.addHandler(fileHandler)
        log.addHandler(stream_handler)
        log.setLevel(self.log_level)

        while True:
            try:
                log_event = self.log_queue.get(timeout=2)
            except queue.Empty:
                continue  # No log to process, continue polling
            except Exception:
                break  # Likely a multiprocessing disconnect (Python 3.12)

            if log_event == self.dead_pill:
                break

            if log_event.log_level == "DEBUG": 
                log.debug(log_event)
            elif log_event.log_level == "INFO": 
                log.info(log_event)
            elif log_event.log_level == "WARNING": 
                log.warning(log_event)
            elif log_event.log_level == "ERROR": 
                log.error(log_event)
            elif log_event.log_level == "CRITICAL": 
                log.critical(log_event)
