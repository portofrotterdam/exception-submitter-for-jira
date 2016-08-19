# exception-submitter-for-jira
This REST service will receive exceptions (stack traces) for which new issues in Jira are created. It will try to de-duplicate to prevent too many new issues from being created.

install:
  - pip3 install -r requirements.txt
