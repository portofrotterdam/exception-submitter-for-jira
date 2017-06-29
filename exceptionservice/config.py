import configparser
import logging
import os

__author__ = 'Miel Donkers <miel.donkers@gmail.com>'

log = logging.getLogger(__name__)

config = configparser.ConfigParser(allow_no_value=True)
config.read("config.ini")

JIRA_URI = config.get('JIRA', 'url', fallback=os.getenv('JIRA_URL'))
JIRA_USER = config.get('JIRA', 'user', fallback=os.getenv('JIRA_USER'))
JIRA_PASSWD = config.get('JIRA', 'passwd', fallback=os.getenv('JIRA_PASSWD'))
JIRA_PROJECT = config.get('JIRA', 'project', fallback=os.getenv('JIRA_PROJECT'))
JIRA_ISSUE_TITLE = config.get('JIRA', 'issue_title', fallback=os.getenv('JIRA_ISSUE_TITLE'))
JIRA_BOARD_ID = config.get('JIRA', 'board_id')

if JIRA_URI is None or JIRA_USER is None or JIRA_PASSWD is None:
    log.warning(
        'Some config values are EMPTY, check if correctly set! JIRA_URL={}, JIRA_USER={}, JIRA_PASSWD={}'.format(JIRA_URI, JIRA_USER, JIRA_PASSWD))

HTTPS_ENABLED = config.getboolean('JIRA', 'https_enabled', fallback=False)

HTTPS_CERT = config.get('JIRA', 'https_cert', fallback=os.getenv('HTTPS_CERT'))
HTTPS_KEY = config.get('JIRA', 'https_key', fallback=os.getenv('HTTPS_KEY'))

if HTTPS_ENABLED and (HTTPS_CERT is None or HTTPS_KEY is None):
    raise ValueError('HTTPS is not configured properly, please provide a valid cert and key file')

if JIRA_PROJECT is None:
    raise ValueError('Please provide a Jira project by passing JIRA_PROJECT')

if JIRA_ISSUE_TITLE is None:
    JIRA_ISSUE_TITLE = 'Exception'
