# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Base class for importing stuff
"""

from github import Github
import os
from ..utils import red, gray, yellow
from .flaw import *


class Base:
    """ Base class for importing stuff in RVD

        Used both by importers of content as well as by
        other RVD utilities to fetch data from the database
    """

    def token(self):
        """Fetch token from GITHUB_TOKEN env. variable"""
        # Authentication for user filing issue (must have read/write access to
        # repository to add issues to)
        try:
            self.token = os.environ['GITHUB_TOKEN']
        except KeyError:
            red("ERROR, make sure that you've GITHUB_TOKEN exported")
            exit(1)
        # First create a Github instance:
        # or using an access token
        self.g = Github(self.token)

    def __init__(self, username="aliasrobotics", repo="RVD"):
        """Init with other repo as target"""
        # Fetch the Github token
        self.token()

        # No username/repo provided thereby, default to RVD ones
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username+"/"+self.repo_name)

    def new_ticket(self, flaw, labels=None):
        """Make a new ticket/issue reporting a new flaw at RVD"""
        yellow("New ticket: " + str(flaw.title))
        # log title
        print("title: ", end="")
        gray(flaw.title)
        # log body
        print("body: ", end="")
        gray(flaw.yml_markdown())
        # log labels
        print("labels: ", end="")
        gray(labels)

        # # Create the ticket
        # self.repo.create_issue(title=flaw.title,
        #                        body=flaw.yml_markdown(),
        #                        labels=labels)

    def update_ticket(self, issue, flaw):
        """Push updates to the 'issue' according to 'flaw'"""
        # fetch past labels
        labels = [l.name for l in issue.labels]
        if flaw.vendor:
            if flaw.vendor != "N/A":
                labels.append(flaw.vendor)

        yellow("Updating " + str(issue))
        # log title
        print("title: ", end="")
        gray(issue.title)
        # log body
        print("body: ", end="")
        gray(flaw.yml_markdown())
        # log assignees
        print("assignees: ", end="")
        gray(issue.assignees)
        # log labels
        print("labels: ", end="")
        gray(labels)

        # # Push updates
        # issue.edit(title=issue.title,
        #            body=flaw.yml_markdown(),
        #            assignees=issue.assignees,
        #            labels=labels)
