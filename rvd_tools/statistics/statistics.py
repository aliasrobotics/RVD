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
import sys
from tabulate import tabulate
import pprint
from plotly import graph_objs as go
import numpy


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

        self.vulnerabilities = []  # open and closed ones
        self.bugs = []  # open and closed ones
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

    def statistics_vulnerabilities_historic(self, label, isoption="all"):
        """Produce statististics on the historic discovery and report
        of robot vulnerabilities"""
        cyan("Produce statististics on the historic discovery of flaws...")
        table = None
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            # importer = Base()
            filtered = []
            if isoption == "all":
                issues = self.issues
            elif isoption == "open":
                issues = self.issues_open
            elif isoption == "closed":
                issues = self.issues_closed
            else:
                red("Error, not recognized isoption: " + str(isoption))
                sys.exit(1)

            # fetch the from attributes itself, see above
            # issues = importer.repo.get_issues(state=isoption)
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)

            table = self.historic(filtered)

        else:
            cyan("Using all vulnerabilities...")
            # Consider all tickets, open and close
            table = self.historic(self.vulnerabilities)

        if table:
            print(tabulate(table, headers=["ID", "Date reported",
                                           "vendor", "CVE", "CVSS", "RVSS"]))

    def historic(self, issues):
        """
        Compile a table with historic data.

        Items in the table (in this order):
        - ID
        - date reported
        - vendor
        - CVE
        - CVSS
        - RVSS

        :returns table [[]]
        """
        return_table = []
        for issue in issues:
            flaw = self.import_issue(issue.number, issue=issue, debug=False)
            return_table.append([flaw.id, flaw.date_reported, flaw.vendor,
                                 flaw.cve, flaw.cvss_score, flaw.rvss_score])
            # print(flaw.date_reported)
            # print(flaw.vendor)
        return return_table

    def summary(self, issues):
        """
        """
        pass

    def vendor_vulnerabilities(self, issues):
        """
        Barplot showing number of vulns by vendor

        return None
        """
        vulnerabilities_flaws = []  # flaw objects, simplify processing
        for vulnerability in self.vulnerabilities:
            vulnerabilities_flaws.append(
                self.import_issue(vulnerability.number,
                                  issue=vulnerability, debug=False))

        # Create a dict that organizes vulns by vendor
        dict_vulnerabilities = {}
        vulnerabilities_averaged = {}
        for vuln in vulnerabilities_flaws:
            score = vuln.cvss_score
            if score == 0:
                score = 10  # asign by default a max. score to those non triaged
                # score = 0  # asign by default a min score to those non triaged
            if score == "N/A":
                score = 10
                # score = 0

            if vuln.vendor.strip() in dict_vulnerabilities.keys():
                dict_vulnerabilities[vuln.vendor.strip()].append(score)
            else:
                dict_vulnerabilities[vuln.vendor.strip()] = [score]

        # pprint.pprint(dict_vulnerabilities)

        # Create the figure
        fig = go.Figure()
        # populate low_percentages
        x = []
        y_num_vulns = []
        for vendor in dict_vulnerabilities.keys():
            if vendor == "N/A":
                x.append("Others")
            else:
                x.append(vendor)
            y_num_vulns.append(len(dict_vulnerabilities[vendor]))
            print(vendor)
            print(len(dict_vulnerabilities[vendor]))

        # colors = ['yellow', 'orange', 'red', 'darkred']
        fig.add_trace(go.Bar(x=x, y=y_num_vulns,
                             name="Number of vulnerabilities"))

        fig.update_layout(barmode='stack',
                          xaxis={'categoryorder': 'category ascending'})
        fig.show()




    def cvss_score_distribution(self, label, isoption="all"):
        """
        Generates an averaged score distribution for all tickets,
        unless a label is provided (which would filter tickets)

        Produces a plot.

        :return None
        """
        vulnerabilities_flaws = []  # flaw objects, simplify processing
        for vulnerability in self.vulnerabilities:
            vulnerabilities_flaws.append(
                self.import_issue(vulnerability.number,
                                  issue=vulnerability, debug=False))

        # Create a dict that organizes vulns by vendor
        dict_vulnerabilities = {}
        vulnerabilities_averaged = {}
        for vuln in vulnerabilities_flaws:
            score = vuln.cvss_score
            if score == 0:
                score = 10  # asign by default a max. score to those non triaged
                # score = 0  # asign by default a min score to those non triaged
            if score == "N/A":
                score = 10
                # score = 0

            if vuln.vendor.strip() in dict_vulnerabilities.keys():
                dict_vulnerabilities[vuln.vendor.strip()].append(score)
            else:
                yellow("Creating new vendor group: " + str(vuln.vendor.strip()))
                dict_vulnerabilities[vuln.vendor.strip()] = [score]

        pprint.pprint(dict_vulnerabilities)

        # construct data for plotting
        for key in dict_vulnerabilities.keys():
            # lists to quantify how severe are tickets for each vendor
            low_scale = []  # 0 - 3.9
            medium_scale = []  # 4.0 - 6.9
            high_scale = []  # 7.0 - 8.9
            critical_scale = []  # 9.0 - 10.0

            for score in dict_vulnerabilities[key]:
                if score >= 0 and score < 4:
                    low_scale.append(score)
                elif score >= 4 and score < 7:
                    medium_scale.append(score)
                elif score >= 7 and score < 9:
                    high_scale.append(score)
                elif score >= 9 and score <= 10:
                    critical_scale.append(score)
                else:
                    red("Error, not accepted score: " + str(score))
                    sys.exit(1)

            total = len(dict_vulnerabilities[key])
            low_percentage = len(low_scale)/total
            medium_percentage = len(medium_scale)/total
            high_percentage = len(high_scale)/total
            critical_percentage = len(critical_scale)/total

            vulnerabilities_averaged[key] = [
                            low_percentage,
                            medium_percentage,
                            high_percentage,
                            critical_percentage
            ]

        # pprint.pprint(vulnerabilities_averaged)

        # x = list(dict_vulnerabilities.keys())
        fig = go.Figure()
        # populate low_percentages
        x = []
        y_low_percentage = []
        y_medium_percentage = []
        y_high_percentage = []
        y_critical_percentage = []
        for vendor in vulnerabilities_averaged.keys():
            if vendor == "N/A":
                x.append("Others")
            else:
                x.append(vendor)

            y_low_percentage.append(vulnerabilities_averaged[vendor][0])
            y_medium_percentage.append(vulnerabilities_averaged[vendor][1])
            y_high_percentage.append(vulnerabilities_averaged[vendor][2])
            y_critical_percentage.append(vulnerabilities_averaged[vendor][3])

        # colors = ['yellow', 'orange', 'red', 'darkred']
        fig.add_trace(go.Bar(x=x, y=y_low_percentage,
                             name="Low"))

        fig.add_trace(go.Bar(x=x, y=y_medium_percentage,
                             name="Medium"))

        fig.add_trace(go.Bar(x=x, y=y_high_percentage,
                             name="High"))

        fig.add_trace(go.Bar(x=x, y=y_critical_percentage,
                             name="Critical"))

        fig.update_layout(barmode='stack',
                          xaxis={'categoryorder': 'category ascending'})
        fig.show()
