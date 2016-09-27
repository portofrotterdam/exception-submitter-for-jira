import logging
import io
from copy import deepcopy
from difflib import SequenceMatcher
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


@app.route('/', methods=['GET', 'POST'])
def receive_exception():
    if request.method == 'POST' and request.is_json:
        return add_jira_exception(request.get_json())
    else:
        return jsonify(show_all_open_issues())


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


def add_jira_exception(json_data):
    log.info('Received json data: {}'.format(json.dumps(json_data)))
    is_duplicate = determine_if_duplicate(json_data)
    if is_duplicate[0]:
        return 'Jira issue already exists: {}'.format(is_duplicate[1])

    result = add_to_jira(get_summary_from_message(json_data), create_details_string_from_json(json_data), get_stacktrace_from_message(json_data))
    if result[0] == 201:
        return 'Jira issue added: {}'.format(result[1]['key']), 201, {}
    else:
        return 'Could not create new Jira issue, resp code; {}'.format(result[0])


def determine_if_duplicate(json_data):
    exception = get_summary_from_message(json_data)
    query = {'jql': 'project=HAMISTIRF&issuetype=Bevinding&summary ~ ' + exception, 'fields': _JIRA_FIELDS}
    resp = requests.post(_JIRA_URI_SEARCH,
                         json=query,
                         headers=_CONTENT_JSON_HEADER,
                         auth=_JIRA_USER_PASSWD)

    if resp.status_code != 200:
        return True, 'Could not query Jira issues, cancel processing issue. Resp code; {}'.format(resp.status_code)

    # log.info('QUERY result: \n' + json.dumps(resp.json()) + '\n\n')
    for issue in resp.json()['issues']:
        issue_stacktrace = get_stacktrace_from_issue(issue)
        s = SequenceMatcher(lambda x: x == ' ' or x == '\n' or x == '\t',
                            get_stacktrace_from_message(json_data),
                            issue_stacktrace)

        match_ratio = s.ratio() if s.real_quick_ratio() > 0.6 else 0
        if match_ratio > 0.95:
            log.info('\nMatch ratio: {} for stacktrace:\n{}'.format(match_ratio, issue_stacktrace))
            return True, issue['key']

    return False, ''


def get_stacktrace_from_issue(issue):
    description = issue['fields']['description']
    descr_blocks = description.split('{noformat}')
    if len(descr_blocks) >= 3:
        return descr_blocks[1]
    else:
        return ''


def create_details_string_from_json(json_data):
    dict_without_stacktrace = deepcopy(json_data)
    del dict_without_stacktrace['stacktrace']

    output = ''
    for key, value in dict_without_stacktrace.items():
        output += '  {}: {}\n'.format(key, value)

    return output


def get_summary_from_message(json_data):
    # Get the original exception, which is the last in the list
    stacks = json_data['stacktrace']
    return stacks[len(stacks) - 1]['message']


def get_stacktrace_from_message(json_data):
    traces = json_data['stacktrace']
    output = io.StringIO()
    for trace in traces:
        output.write('Caused by: {}\n'.format(trace['message']))
        for line in trace['stacktrace']:
            if not line['nativeMethod']:  # Filter out native Java methods
                output.write('\tat {}.{}:{}\n'.format(line['className'], line['methodName'], line['lineNumber']))

    result = output.getvalue()
    output.close()
    return result


def add_to_jira(summary, details, stacktrace):
    title = 'HaMIS Exception: ' + summary
    description = '{}\n\nDetails:\n{}\n\nStacktrace:\n{{noformat}}{}{{noformat}}'.format(summary, details, stacktrace)
    issue = {'project': {'key': 'HAMISTIRF'}, 'summary': title, 'description': description,
             'issuetype': {'name': 'Bevinding'}, 'labels': ['Beheer']}
    fields = {'fields': issue}

    log.info('Sending:\n{}'.format(json.dumps(fields)))

    resp = requests.post(_JIRA_URI_CREATE,
                         json=fields,
                         headers=_CONTENT_JSON_HEADER,
                         auth=_JIRA_USER_PASSWD)
    return resp.status_code, resp.json() if resp.status_code == 201 else None
