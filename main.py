import logging

from exceptionservice.config import *

__author__ = 'Miel Donkers <miel.donkers@codecentric.nl>'

"""
    Execution script, initializes logging and starts server
"""

HOST, PORT = '0.0.0.0', 3000


def _init_log():
    # create console handler with with formatting and log level
    _formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    _console_handler = logging.StreamHandler()
    _console_handler.setLevel(logging.DEBUG)
    _console_handler.setFormatter(_formatter)
    # add the handlers to the logger
    _root_logger = logging.getLogger()
    _root_logger.addHandler(_console_handler)
    _root_logger.setLevel(logging.DEBUG)


# -----------------------------------------------------------------
# Main
# -----------------------------------------------------------------
_init_log()

if __name__ == '__main__':
    from exceptionservice import app

    if HTTPS_ENABLED:
        log.info('HTTPS enabled, using cert file \'{}\' and key file \'{}\''.format(HTTPS_CERT, HTTPS_KEY))
        app.run(host=HOST, port=PORT, debug=True, ssl_context=(HTTPS_CERT, HTTPS_KEY))
    else:
        app.run(host=HOST, port=PORT, debug=True)
