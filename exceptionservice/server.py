import logging
from urllib.parse import urljoin

import requests
from exceptionservice import app
from exceptionservice.config import *
from flask import request, jsonify, json

"""
This is the base-class with views
"""

__author__ = 'Miel Donkers <miel.donkers@codecentric.nl>'

log = logging.getLogger(__name__)

_JIRA_URI_SEARCH = urljoin(JIRA_URI, '/rest/api/latest/search')
_JIRA_URI_CREATE = urljoin(JIRA_URI, '/rest/api/latest/issue')
_JIRA_USER_PASSWD = (JIRA_USER, JIRA_PASSWD)
_JIRA_FIELDS = ['id', 'key', 'created', 'status', 'labels', 'summary', 'description']
_CONTENT_JSON_HEADER = {'Content-Type': 'application/json'}


def add_to_jira(summary, stacktrace):
    description = 'Test issue {{noformat}}{}{{noformat}}'.format(stacktrace)
    issue = {'project': {'key': 'HAMISTIRF'}, 'summary': summary, 'description': description,
             'issuetype': {'name': 'Bevinding'}, 'labels': ['Beheer']}
    fields = {'fields': issue}

    log.info('Sending:\n{}'.format(json.dumps(fields)))

    resp = requests.post(_JIRA_URI_CREATE,
                         json=fields,
                         headers=_CONTENT_JSON_HEADER,
                         auth=_JIRA_USER_PASSWD)
    return resp.status_code, resp.json() if resp.status_code == 201 else None


def add_jira_exception(json_data):
    log.info('Received json data: {}'.format(json_data))
    result = add_to_jira('Test issue', 'NPE: blabla stacktrace')

    if result[0] == 201:
        return 'Jira issue added: {}'.format(result[1]['key']), 201, {}
    else:
        return 'Could not create new Jira issue, resp code; {}'.format(result[0])


def show_all_open_issues():
    query = {'jql': 'project=HAMISTIRF&status in (Open,"In Progress",Reopened)&issuetype=Bevinding',
             'fields': _JIRA_FIELDS}
    resp = requests.post(_JIRA_URI_SEARCH,
                         json=query,
                         headers=_CONTENT_JSON_HEADER,
                         auth=_JIRA_USER_PASSWD)

    if resp.status_code != 200:
        return 'Could not get open Jira issues, resp code; {}'.format(resp.status_code)

    return resp.json()


@app.route('/', methods=['GET', 'POST'])
def receive_exception():
    if request.method == 'POST' and request.is_json:
        return add_jira_exception(request.get_json())
    else:
        return jsonify(show_all_open_issues())
