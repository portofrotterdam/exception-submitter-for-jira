# exception-submitter-for-jira
This REST service will receive exceptions (stack traces) for which new issues in Jira are created. It will try to de-duplicate to prevent too many new issues from being created.

install:
  - pip3 install -r requirements.txt

## Docker build and run
Building container:

    docker build -t exception-submitter .

Running container:

    docker pull miel/exception-submitter-for-jira
    docker run -d -p 3000:3000 -e "JIRA_URL=<url>" \ 
                               -e "JIRA_USER=<user>" \ 
                               -e "JIRA_PASSWD=<passwd>" \ 
                               -e "CUSTOM_FIELD_MAPPINGS={"customfield_123456": "myJsonFieldName", "customfield_654321": "myOtherJsonFieldName"}" \ 
                               --name exception-submitter miel/exception-submitter-for-jira

### Custom field mappings
The 'CUSTOM_FIELD_MAPPINGS' are optional. They provide a way to map data field names to custon JIRA fields. 
With the data field names the data wil be extracted from the json and assigned to the custom JIRA fields.
This works currently only for fields at the root of the json, thus not for nested ones.

There are two ways to provide custom mappings:
  - Via config.ini file


    [CUSTOM_FIELD_MAPPINGS]
    customfield_123456: myJsonFieldName 
    customfield_654321: myOtherJsonFieldName 

  - Via environment variable as JSON


    CUSTOM_FIELD_MAPPINGS={"customfield_123456": "myJsonFieldName", "customfield_654321": "myOtherJsonFieldName"}  

## Docker Repo
Automatic builds: [https://hub.docker.com/r/miel/exception-submitter-for-jira/](https://hub.docker.com/r/miel/exception-submitter-for-jira/)

# Credits
Credits to Serkan Demirel for fixing issues and adding stuff like posting images and log files to Jira

