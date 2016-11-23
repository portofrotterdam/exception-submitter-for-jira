import configparser
import os
import logging

__author__ = 'Miel Donkers <miel.donkers@gmail.com>'

log = logging.getLogger(__name__)


config = configparser.ConfigParser(allow_no_value=True)
config.read("config.ini")

JIRA_URI = config.get('JIRA','url', fallback=os.getenv('JIRA_URL'))
JIRA_USER = config.get('JIRA','user', fallback=os.getenv('JIRA_USER'))
JIRA_PASSWD = config.get('JIRA','passwd', fallback=os.getenv('JIRA_PASSWD'))

if JIRA_URI is None or JIRA_USER is None or JIRA_PASSWD is None:
    log.warning(
        'Some config values are EMPTY, check if correctly set! JIRA_URL={}, JIRA_USER={}, JIRA_PASSWD={}'.format(JIRA_URI, JIRA_USER, JIRA_PASSWD))
