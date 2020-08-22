# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Base class for importing stuff
"""

import os
import sys
from github import Github
import yaml
from .flaw import *
from ..utils import red, gray, yellow, cyan


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
            self.token = os.environ["GITHUB_TOKEN"]
        except KeyError:
            red("ERROR, make sure that you've GITHUB_TOKEN exported")
            sys.exit(1)
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
        self.repo = self.g.get_repo(self.username + "/" + self.repo_name)

    def get_issues_filtered(self, state="open"):
        """
        Import all valid issues (open and close), discarding all those
        with the `invalid` label

        return list(Issues)
        """
        issues = self.repo.get_issues(state=state)
        filtered_issues = []
        for issue in issues:
            labels = [l.name for l in issue.labels]
            # print(labels)
            if "invalid" in labels:
                # yellow("discarding...")
                continue
            else:
                filtered_issues.append(issue)
        return filtered_issues

    def import_issue(self, id, issue=None, debug=True):
        """
        Imports an issue from RVD and returns a Flaw instance

        :return Flaw
        """
        if not issue:
            try:
                issue = self.repo.get_issue(int(id))
            except TypeError:
                red("ERROR: something went wrong with the id: " + str(id))
                yellow("Should be the issue number")
            except:
                red("ERROR: something went wrong with the id: " + str(id))
                yellow("Maybe you reached the end?")
                sys.exit(1)

        document_raw = issue.body
        document_raw = document_raw.replace("```yaml", "").replace("```", "")
        document = yaml.safe_load(document_raw)
        # print(document)

        flaw = Flaw(document)

        if debug:
            yellow("Imported issue ", end="")
            print(str(id), end="")
            yellow(" into a Flaw...")
            # gray(flaw)
        return flaw

    def import_issues_labels(self, label, isoption="open"):
        """
        Returns a list of issues

        :param label, tuple with labels, could be more than one
        :param is, status of the issues (could be "open", "closed" or "all")
        :return list[Issue]
        """
        issue_list = []
        issues_public = self.repo.get_issues(state=isoption)
        for issue in issues_public:
            all_labels = True  # indicates whether all labels are present
            if label:
                labels = [l.name for l in issue.labels]
                for l in label:
                    if l not in labels or "invalid" in labels:
                        all_labels = False
                        break
                if all_labels:
                    issue_list.append(issue)
            else:
                issue_list.append(issue)
        return issue_list

    def get_table(self, label, isoption="open"):
        """
        Returns a tabulate ready table

        :param label, tuple with labels, could be more than one
        :param is, status of the issues (could be "open", "closed" or "all")
        :return list[list]
        """
        table = []
        issues_public = self.repo.get_issues(state=isoption)
        for issue in issues_public:
            all_labels = True  # indicates whether all labels are present
            if label:
                labels = [l.name for l in issue.labels]
                for l in label:
                    if l not in labels or "invalid" in labels:
                        all_labels = False
                        break
                if all_labels:
                    table.append([issue.number, issue.title])
            else:
                table.append([issue.number, issue.title])
        return table

    def new_ticket(self, flaw, labels=None):
        """
        Make a new ticket/issue reporting a new flaw at RVD

        :return Issue
        """
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
        # Create the ticket
        return self.repo.create_issue(
            title=flaw.title, body=flaw.yml_markdown(), labels=labels
        )

    def update_ticket(self, issue, flaw):
        """Push updates to the 'issue' according to 'flaw'"""
        # # fetch past labels
        labels = [l.name for l in issue.labels]

        # if flaw.vendor:
        #     if flaw.vendor != "N/A":
        #         labels.append(flaw.vendor)

        yellow("Updating " + str(issue))
        # log title
        print("title: ", end="")
        gray(flaw.title)
        # log body
        print("body: ", end="")
        gray(flaw.yml_markdown())
        # log assignees
        print("assignees: ", end="")
        gray(issue.assignees)
        # log labels
        print("labels: ", end="")
        gray(labels)
        # Push updates
        issue.edit(
            title=flaw.title,
            body=flaw.yml_markdown(),
            assignees=issue.assignees,
            labels=labels,
        )

    def get_flaw(self, id):
        """
        Returns a flaw instance populated from the ticket with id number

        :param id, id number of the ticket
        :return Flaw
        """
        issue = self.repo.get_issue(int(id))
        labels = [l.name for l in issue.labels]
        cyan("Importing from RVD, issue: " + str(issue))
        document_raw = issue.body
        document_raw = document_raw.replace("```yaml", "").replace("```", "")
        try:
            document = yaml.safe_load(document_raw, Loader=yaml.FullLoader)
            flaw = Flaw(document)
            # print(flaw)
        except yaml.scanner.ScannerError:
            print("Not in yaml format please review")

        return flaw, labels
