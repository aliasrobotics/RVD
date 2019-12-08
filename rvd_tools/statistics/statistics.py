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
# import plotly.graph_objects as go
import numpy
import arrow


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

    def cvss_vs_rvss(self, label, isoption="all"):
        """Produce statististics on the scoring of vulns while comparing
        two mechanims, CVSS and RVSS"""
        cyan("Produce RVSS and CVSS comparisons...")
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

            print(table)
            table = self.historic(filtered)

        else:
            cyan("Using all vulnerabilities...")
            # Consider all tickets, open and close
            table = self.historic(self.vulnerabilities)

        if table:
            print(tabulate(table, headers=["ID", "Date reported",
                                           "vendor", "CVE", "CVSS", "RVSS"]))

    def zero_vs_mitigated(self, label, nolabel):
        """
        Plots 0-days vs mitigated flaws, among the filtered ones
        """
        # issues = self.vulnerabilities  # select all possible tickets
        # zero_days = []
        # mitigated = []
        # if label:  # account for only filtered tickets
        #     cyan("Using label: " + str(label))
        #     cyan("Using nolabel: " + str(nolabel))
        #     filtered = []
        #     # fetch the from attributes itself, see above
        #     for issue in issues:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in label:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         for l in nolabel:
        #             # id l in labels, we don't want it
        #             if l in labels:
        #                 all_labels = False
        #                 break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        # 
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     # vulnerability = self.import_issue(issue.number, issue=issue)
        #     print("Issue " + str(issue.number) + " state: " + str(issue.state))
        #     labels = [l.name for l in issue.labels]
        #     if issue.state == "open" and not "mitigated" in labels:
        #         zero_days.append(issue)
        #     else:
        #         mitigated.append(issue)
        # 
        # yellow("0-days: " + str(len(zero_days)))
        # yellow("Mitigated: " + str(len(mitigated)))
        # 
        # # Plot
        # # animals = ['ROS', 'ROS 2', 'Universal Robots']
        # animals = [str(label)]
        # 
        # fig = go.Figure(data=[
        #     go.Bar(name='0-days', x=animals, y=[len(zero_days)]),
        #     go.Bar(name='Mitigated', x=animals, y=[len(mitigated)])
        # ])
        # # Change the bar mode
        # fig.update_layout(barmode='group')
        # fig.show()

        issues_nonfiltered = self.vulnerabilities
        issues = self.vulnerabilities  # select all possible tickets
        # ROS
        zero_days_ROS = []
        mitigated_ROS = []
        labels_ROS = ["robot component: ROS"]
        nolabels_ROS = []
        if labels_ROS:  # account for only filtered tickets
            cyan("Using labels_ROS: " + str(labels_ROS))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ROS:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ROS:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ROS.append(issue)
            else:
                mitigated_ROS.append(issue)

        yellow("0-days: " + str(len(zero_days_ROS)))
        yellow("Mitigated: " + str(len(mitigated_ROS)))

        # ROS2
        zero_days_ROS2 = []
        mitigated_ROS2 = []
        labels_ROS2 = ["robot component: ROS2"]
        nolabels_ROS2 = []
        if labels_ROS2:  # account for only filtered tickets
            cyan("Using labels_ROS2: " + str(labels_ROS2))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ROS2:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ROS2:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ROS2.append(issue)
            else:
                mitigated_ROS2.append(issue)

        yellow("0-days: " + str(len(zero_days_ROS2)))
        yellow("Mitigated: " + str(len(mitigated_ROS2)))

        # UR
        zero_days_UR = []
        mitigated_UR = []
        labels_UR = ["vendor: Universal Robots"]
        nolabels_UR = []
        if labels_UR:  # account for only filtered tickets
            cyan("Using labels_UR: " + str(labels_UR))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_UR:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_UR:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_UR.append(issue)
            else:
                mitigated_UR.append(issue)

        yellow("0-days: " + str(len(zero_days_UR)))
        yellow("Mitigated: " + str(len(mitigated_UR)))

        # ABB
        zero_days_ABB = []
        mitigated_ABB = []
        labels_ABB = ["vendor: ABB"]
        nolabels_ABB = ["triage"]
        if labels_ABB:  # account for only filtered tickets
            cyan("Using labels_ABB: " + str(labels_ABB))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ABB:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ABB:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ABB.append(issue)
            else:
                mitigated_ABB.append(issue)

        yellow("0-days: " + str(len(zero_days_ABB)))
        yellow("Mitigated: " + str(len(mitigated_ABB)))

        ########
        # Plot
        ########
        animals = ['ROS', 'ROS 2', 'Universal Robots', "ABB"]
        # animals = [str(label)]

        fig = go.Figure(data=[
            go.Bar(name='0-days', x=animals, y=[
                len(zero_days_ROS),
                len(zero_days_ROS2),
                len(zero_days_UR),
                len(zero_days_ABB)
            ]),
            go.Bar(name='Mitigated', x=animals, y=[
                len(mitigated_ROS),
                len(mitigated_ROS2),
                len(mitigated_UR),
                len(mitigated_ABB)
            ])
        ])
        # Change the bar mode
        fig.update_layout(barmode='group')
        fig.show()

    def mitigation_timing(self, label, nolabel):
        """
        Creates a plot showing the time to mitigation for the selected tickets
        via label (labels).

        :param label tuple()
        :return None
        """
        cyan("Produce plot with time required to mitigate each flaw...")

        issues = self.vulnerabilities  # select all possible tickets
        time_difference = []  # in days
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            # importer = Base()
            filtered = []

            # fetch the from attributes itself, see above
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabel:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            vulnerability = self.import_issue(issue.number, issue=issue)
            # favour selection of earliest date (date_detected)
            if vulnerability.date_detected == "" or vulnerability.date_detected is None:
                if vulnerability.date_reported == "" or vulnerability.date_reported is None:
                    # report error in dates
                    red("Error, both date_detected and date_reported seem \
                    wrong in " + str(vulnerability))
                    sys.exit(1)
                else:
                    initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
            else:
                initial_date = arrow.get(vulnerability.date_detected, ['YYYY-MM-DD'])

            # select mitigation date
            if vulnerability.date_mitigation:
                mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
            else:
                mitigation_date = arrow.now()  # default to now for statistics

            yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
            print(str((mitigation_date - initial_date).days))
            time_difference.append(int((mitigation_date - initial_date).days))

        ############
        # Create plot
        ############

        # x_data = ['Carmelo Anthony']
        x_data = [str(label)]

        y0 = time_difference

        # y_data = [y0, y1, y2, y3, y4, y5]
        y_data = [y0]

        # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)',
        #           'rgba(207, 114, 255, 0.5)', 'rgba(127, 96, 0, 0.5)']
        colors = ['rgba(93, 164, 214, 0.5)']

        fig = go.Figure()

        for xd, yd, cls in zip(x_data, y_data, colors):
            fig.add_trace(go.Box(
                    y=yd,
                    name=xd,
                    boxpoints='all',
                    jitter=0.5,
                    whiskerwidth=0.2,
                    fillcolor=cls,
                    marker_size=2,
                    line_width=1)
                )

        fig.update_layout(
            title='Time to mitigation (in days), robot vulnerabilities',
            yaxis=dict(
                autorange=True,
                showgrid=False,
                zeroline=True,
                gridcolor='rgb(255, 255, 255)',
                gridwidth=1,
                zerolinecolor='rgb(255, 255, 255)',
                zerolinewidth=2,
            ),
            margin=dict(
                l=40,
                r=30,
                b=80,
                t=100,
            ),
            paper_bgcolor='rgb(243, 243, 243)',
            plot_bgcolor='rgb(243, 243, 243)',
            showlegend=False
        )
        fig.show()

        # issues_nonfiltered = self.vulnerabilities
        # issues = self.vulnerabilities  # select all possible tickets
        #
        # # ROS
        # time_difference_ROS = []  # in days
        # labels_ROS = ["robot component: ROS"]
        # if labels_ROS:  # account for only filtered tickets
        #     cyan("Using labels_ROS: " + str(labels_ROS))
        #     # importer = Base()
        #     filtered = []
        #
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ROS:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        # 
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(vulnerability.date_detected, ['YYYY-MM-DD'])
        # 
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        # 
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     # print(str((mitigation_date - initial_date).days))
        #     time_difference_ROS.append(int((mitigation_date - initial_date).days))
        # 
        # # ROS2
        # time_difference_ROS2 = []  # in days
        # labels_ROS2 = ["robot component: ROS2"]
        # if labels_ROS2:  # account for only filtered tickets
        #     cyan("Using labels_ROS2: " + str(labels_ROS2))
        #     # importer = Base()
        #     filtered = []
        # 
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ROS2:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        # 
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(vulnerability.date_detected, ['YYYY-MM-DD'])
        # 
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        # 
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     # print(str((mitigation_date - initial_date).days))
        #     time_difference_ROS2.append(int((mitigation_date - initial_date).days))
        # 
        # # UR
        # time_difference_UR = []  # in days
        # labels_UR = ["vendor: Universal Robots"]
        # if labels_UR:  # account for only filtered tickets
        #     cyan("Using labels_UR: " + str(labels_UR))
        #     # importer = Base()
        #     filtered = []
        # 
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_UR:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        # 
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(str(vulnerability.date_detected), ['YYYY-MM-DD'])
        # 
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        # 
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     print(str((mitigation_date - initial_date).days))
        #     time_difference_UR.append(int((mitigation_date - initial_date).days))
        # 
        # # ABB
        # time_difference_ABB = []  # in days
        # labels_ABB = ["vendor: ABB"]
        # if labels_ABB:  # account for only filtered tickets
        #     cyan("Using labels_ABB: " + str(labels_ABB))
        #     # importer = Base()
        #     filtered = []
        # 
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ABB:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         for l in nolabel:
        #             # id l in labels, we don't want it
        #             if l in labels:
        #                 all_labels = False
        #                 break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        # 
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(str(vulnerability.date_detected), ['YYYY-MM-DD'])
        # 
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        # 
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     print(str((mitigation_date - initial_date).days))
        #     # print(mitigation_date)
        #     # print(initial_date)
        #     time_difference_ABB.append(int((mitigation_date - initial_date).days))
        # 
        # ############
        # # Create plot
        # ############
        # 
        # # x_data = ['Carmelo Anthony']
        # x_data = ["ROS", "ROS2", "Universal Robots", "ABB"]
        # 
        # y0 = time_difference_ROS
        # y1 = time_difference_ROS2
        # y2 = time_difference_UR
        # y3 = time_difference_ABB
        # 
        # # y_data = [y0, y1, y2, y3, y4, y5]
        # y_data = [y0, y1, y2, y3]
        # 
        # # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        # #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)',
        # #           'rgba(207, 114, 255, 0.5)', 'rgba(127, 96, 0, 0.5)']
        # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)']
        # 
        # fig = go.Figure()
        # 
        # for xd, yd, cls in zip(x_data, y_data, colors):
        #     fig.add_trace(go.Box(
        #             y=yd,
        #             name=xd,
        #             boxpoints='all',
        #             jitter=0.5,
        #             whiskerwidth=0.2,
        #             fillcolor=cls,
        #             marker_size=5,
        #             line_width=1)
        #         )
        # 
        # # fig.add_shape(
        # #         # Line Horizontal
        # #         go.layout.Shape(
        # #             type="line",
        # #             y0=365,
        # #             # x0=0,
        # #             # x1=5,
        # #             y1=365,
        # #             line=dict(
        # #                 color="LightSeaGreen",
        # #                 width=3,
        # #                 dash="dashdot",
        # #             ),
        # #         )
        # # )
        # 
        # fig.update_layout(
        #     title='Time until mitigation (in days), robot vulnerabilities',
        #     yaxis=dict(
        #         autorange=True,
        #         showgrid=False,
        #         zeroline=True,
        #         gridcolor='rgb(255, 255, 255)',
        #         gridwidth=1,
        #         zerolinecolor='rgb(255, 255, 255)',
        #         zerolinewidth=2,
        #     ),
        #     margin=dict(
        #         l=40,
        #         r=30,
        #         b=80,
        #         t=100,
        #     ),
        #     # paper_bgcolor='rgb(243, 243, 243)',
        #     # plot_bgcolor='rgb(243, 243, 243)',
        #     showlegend=True
        # )
        # fig.show()

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
                # score = 10  # asign by default a max. score to those non triaged
                score = 0  # asign by default a min score to those non triaged
            if score == "N/A":
                # score = 10
                score = 0

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
