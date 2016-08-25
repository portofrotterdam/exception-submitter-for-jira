import configparser

__author__ = 'Miel Donkers <miel.donkers@gmail.com>'


config = configparser.ConfigParser()
config.read("config.ini")

JIRA_URI = config['JIRA']['url']
JIRA_USER = config['JIRA']['user']
JIRA_PASSWD = config['JIRA']['passwd']
