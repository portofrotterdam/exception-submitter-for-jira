import logging

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
    app.run(host=HOST, port=PORT, debug=True)
