from exceptionservice import app
from flask import Flask, session, redirect, url_for, escape, request
import logging

"""
This is the base-class with views
"""

__author__ = 'Miel Donkers <miel.donkers@codecentric.nl>'

log = logging.getLogger(__name__)



# def request_handler(parsed_question):
#     handler_method = get_handler_method_for_question(parsed_question)
#     print_unknown = handler_method == fallback_handler
#
#     if print_unknown:
#         print("Received Question: {}".format(parsed_question))
#         print("Using handler method: {}".format(str(handler_method)))
#
#     response = str(handler_method(parsed_question))
#     print("Response: {}".format(response))
#     return response


@app.route('/')
def receive_exception():
    # log.info('Received request; ' + request.get_json())
    # q = request.args.get("q", "")
    # parsed_question = parse_request_string(q)
    return "Hello World!"

