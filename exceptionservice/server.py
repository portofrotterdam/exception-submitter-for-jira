import configparser
import logging

import requests
from exceptionservice import app
from flask import request, jsonify
from urllib.parse import urljoin


"""
This is the base-class with views
"""

__author__ = 'Miel Donkers <miel.donkers@codecentric.nl>'

log = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read("config.ini")

JIRA_URI = urljoin(config['JIRA']['url'], '/rest/api/latest/search')
JIRA_USER_PASSWD = (config['JIRA']['user'], config['JIRA']['passwd'])
JIRA_FIELDS = ['id', 'key', 'created', 'status', 'labels', 'summary', 'description']


def add_jira_exception(json_data):
    log.info('Received json data: {}'.format(json_data))
    pass


def show_all_open_issues():
    headers = {'Content-Type': 'application/json'}
    # Make sure character case for Jira keywords is correct
    query = {'jql': 'project=HAMISTIRF&status in (Open,"In Progress",Reopened)&issuetype=Bevinding',
             'fields': JIRA_FIELDS}

    resp = requests.post(JIRA_URI,
                         json=query,
                         headers=headers,
                         auth=JIRA_USER_PASSWD)

    if resp.status_code != 200:
        # This means something went wrong.
        return 'Could not get open Jira issues, resp code; {}'.format(resp.status_code)

    return resp.json()


@app.route('/', methods=['GET', 'POST'])
def receive_exception():
    if request.method == 'POST' and request.is_json:
        add_jira_exception(request.get_json())
        return 'Jira issue added', 201, {}
    else:
        return jsonify(show_all_open_issues())
