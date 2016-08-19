from flask import Flask

"""
About this project
==================

The Exception Submitter Service is a Python 3 project for receiving exception stack traces and submitting them to Jira.


Project Authors
===============

 * Miel Donkers (miel.donkers@codecentric.nl)

Current code lives on github: https://github.com/mdonkers/exception-submitter-for-jira

"""

__all__ = [
    "server"
]

__docformat__ = "epytext"


app = Flask(__name__)

import exceptionservice.server
