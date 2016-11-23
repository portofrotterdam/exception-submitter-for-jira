# exception-submitter-for-jira
This REST service will receive exceptions (stack traces) for which new issues in Jira are created. It will try to de-duplicate to prevent too many new issues from being created.

install:
  - pip3 install -r requirements.txt

## Docker build and run
Building container:

    docker build -t exception-submitter .

Running container:

    docker pull miel/exception-submitter-for-jira
    docker run -d -p 3000:3000 -e "JIRA_URL=<url>" -e "JIRA_USER=<user>" -e "JIRA_PASSWD=<passwd>" --name exception-submitter miel/exception-submitter-for-jira

## Docker Repo
Automatic builds: [https://hub.docker.com/r/miel/exception-submitter-for-jira/](https://hub.docker.com/r/miel/exception-submitter-for-jira/)

