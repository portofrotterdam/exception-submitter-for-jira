#!/usr/bin/env python

from setuptools import setup, find_packages


with open('../README.md') as f:
    readme = f.read()

long_description = """
The Exception Submitter Service is a Python 3 project for receiving exception stack traces and submitting them to Jira.

----

%s

----

Run the server with::

    $ python3 -m exceptionservice

""" % readme


setup(
    name='ExceptionSubmitterService',
    version='1.0',
    description='The Exception Submitter Service receives exception stack traces and submits them to Jira.',
    long_description=long_description,
    author='Miel Donkers',
    author_email='miel.donkers@codecentric.nl',
    url='https://github.com/mdonkers/exception-submitter-for-jira',
    packages=find_packages(exclude=["*.tests", "tests"]),
    install_requires=['Flask'],
    tests_require=['nose'],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'exception-submitter-service = exceptionservice.server:run',
            ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GPLv3',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        ],
    )
