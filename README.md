# exception-submitter-for-jira
This REST service will receive exceptions (stack traces) for which new issues in Jira are created. It will try to de-duplicate to prevent too many new issues from being created.

install:
  - pip3 install -r requirements.txt

## Docker build and run
Building container:

    docker build -t exception-submitter .

Running container:

    docker run -d -p 3000:3000 --name exception-submitter exception-submitter

## Docker Repo
Automatic builds: [https://hub.docker.com/r/miel/exception-submitter-for-jira/](https://hub.docker.com/r/miel/exception-submitter-for-jira/)

