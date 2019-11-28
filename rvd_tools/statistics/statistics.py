# -*- coding: utf-8 -*-
#
# Alias Robotics S.L.
# https://aliasrobotics.com

"""
Base statistics class

NOTE: Should be specialized by other subclasses that add functionality
"""

from ..database.base import Base
from ..utils import gray, red, green, cyan, yellow


class Statistics(Base):
    """
    Base statistics class
    """

    def __init__(self):
        super().__init__()
        # All
        self.issues = []  # stores the name of each one of the issues
        # Open
        self.issues_open = []  # stores the name of each one of the issues
        # Closed
        self.issues_closed = []  # stores the name of each one of the issues

        self.vulnerabilities = []
        self.bugs = []
        self.init_issues_and_labels()

    def init_issues_and_labels(self):
        """
        Inits the existing issues in the repo by adding their
        names into the class attribute self.issues

        Removes 'invalid' and 'duplicate' tickets
        """
        cyan("Statistics, initializing tickets...")
        # All
        issues = self.repo.get_issues(state="all")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues.append(issue)

            # Classify as a vunerability or as a bug
            # print(issue)  # debugging purposes
            flaw = self.import_issue(issue.number, issue=issue)
            if "vulnerability" in labels:
                self.vulnerabilities.append(issue)
            elif flaw.type == "vulnerability":
                yellow("Warning, 'type == vulnerability' but no corresponding label found, classifying as vuln")
                self.vulnerabilities.append(issue)
            else:
                self.bugs.append(issue)

        # Closed
        issues = self.repo.get_issues(state="closed")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues_closed.append(issue)

        # Open
        issues = self.repo.get_issues(state="open")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues_open.append(issue)

    def statistics_vulnerabilities_historic(self):
        """Produce statististics on the historic discovery and report
        of robot vulnerabilities"""
        cyan("Produce statististics on the historic discovery of flaws...")
        # Consider all tickets, open and close
        for issue in self.vulnerabilities:
            flaw = self.import_issue(issue.number, issue=issue, debug=False)
            print(flaw.date_reported)
            print(flaw.vendor)
