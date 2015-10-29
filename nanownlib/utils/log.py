import logging


HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'


def configure_logging(debug):
    console = ColorLog()
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(logging.DEBUG)


class ColorLog(logging.Handler):
    """
    A class to print colored messages to stdout
    """

    COLORS = {logging.CRITICAL: FAIL,
              logging.ERROR: FAIL,
              logging.WARNING: WARNING,
              logging.INFO: OKBLUE,
              logging.DEBUG: ''}

    def __init__(self):
        logging.Handler.__init__(self)

    def usesTime(self):
        return False

    def emit(self, record):
        color = self.COLORS.get(record.levelno, '')
        print('%s%s%s' % (color, record.msg, ENDC if color else ''))
