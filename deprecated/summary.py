"""
Alias Robotics SL 
https://aliasrobotics.com

Scripts that (re-)produces a summary of vulnerabilities and weaknesses
and dumps it optionally into README.md

Run:
    python3 summary.py
"""

from base.import_base import RVDImport
from github import Label
from time import gmtime, strftime


class Summary(RVDImport):
    def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__()
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username + "/" + self.repo_name)

        # All
        self.issues = []  # stores the name of each one of the issues in the corresponding repository
        self.labels = []  # labels for all issues
        # Open
        self.issues_open = []  # stores the name of each one of the issues in the corresponding repository
        self.labels_open = []  # labels for all issues
        # Closed
        self.issues_closed = []  # stores the name of each one of the issues in the corresponding repository
        self.labels_closed = []  # labels for all issues
        
        self.malformed = 0 # number of malformed tickets

        ###########################
        # Summary attributes
        ###########################
        self.ntotal = 0  # Total number of weaknesses + vulnerabilities in RVD
        self.open_issues_count = 0
        self.closed_issues_count = 0

        self.nweaknesses = 0
        self.nweaknesses_open = 0
        self.nweaknesses_closed = 0

        self.nvulnerabilities = 0
        self.nvulnerabilities_open = 0
        self.nvulnerabilities_closed = 0

        self.nothers = 0
        self.nothers_open = 0
        self.nothers_closed = 0

        self.vulns_critical = 0
        self.vulns_high = 0
        self.vulns_medium = 0
        self.vulns_low = 0

        # ROS 2 variables
        self.nweaknesses_ros2 = 0
        self.nweaknesses_open_ros2 = 0
        self.nweaknesses_closed_ros2 = 0

        self.nvulnerabilities_ros2 = 0
        self.nvulnerabilities_open_ros2 = 0
        self.nvulnerabilities_closed_ros2 = 0

        self.nothers_ros2 = 0
        self.nothers_open_ros2 = 0
        self.nothers_closed_ros2 = 0

        self.vulns_critical_ros2 = 0
        self.vulns_high_ros2 = 0
        self.vulns_medium_ros2 = 0
        self.vulns_low_ros2 = 0
                
        self.processed_packages = {} # dict containg "package_name" as keys and "number of issues" as content

        # MoveIt 2 variables
        self.nweaknesses_moveit2 = 0
        self.nweaknesses_open_moveit2 = 0
        self.nweaknesses_closed_moveit2 = 0

        self.nvulnerabilities_moveit2 = 0
        self.nvulnerabilities_open_moveit2 = 0
        self.nvulnerabilities_closed_moveit2 = 0

        self.nothers_moveit2 = 0
        self.nothers_open_moveit2 = 0
        self.nothers_closed_moveit2 = 0

        self.vulns_critical_moveit2 = 0
        self.vulns_high_moveit2 = 0
        self.vulns_medium_moveit2 = 0
        self.vulns_low_moveit2 = 0

        self.init_issue_names()
        self.summarize()

    def init_issue_names(self):
        """
        Inits the existing issues in the repo by adding their
        names into the class attribute self.issues
        """
        # All
        issues = self.repo.get_issues(state="all")
        for issue in issues:
            self.issues.append(issue)
            self.labels.append([l.name for l in issue.labels])
            # print([l.name for l in issue.labels])

        # # test finding labels
        # for lab in self.labels:
        #     if "severity: medium" in lab:
        #         print("found!")

        # Closed
        issues = self.repo.get_issues(state="closed")
        for issue in issues:
            self.issues_closed.append(issue)
            self.labels_closed.append([l.name for l in issue.labels])

        # Open
        issues = self.repo.get_issues(state="open")
        for issue in issues:
            self.issues_open.append(issue)
            self.labels_open.append([l.name for l in issue.labels])

    def summarize(self):
        """
        Calculate summary of vulns and weaknesses
        """
        # Calculate total number of flaws reported, including closed ones
        self.ntotal = len(self.issues)
        # Number of open issues
        self.open_issues_count = self.repo.open_issues_count  # or simply len(self.issues_open)
        self.closed_issues_count = len(self.issues_closed)
        
        #######################
        # Process general information
        #######################
        
        # Number of weaknesses
        for l_set in self.labels:
            if "invalid" in l_set:
                continue            
            if "weakness" in l_set:
                self.nweaknesses += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nweaknesses_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "weakness" in l_set:
                self.nweaknesses_open += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_open_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nweaknesses_open_moveit2 += 1

        for l_set in self.labels_closed:
            if "invalid" in l_set:
                continue            
            if "weakness" in l_set:
                self.nweaknesses_closed += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_closed_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nweaknesses_closed_moveit2 += 1

        # Number of vulnerabilities
        for l_set in self.labels:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                self.nvulnerabilities += 1
                if 'robot component: ROS2' in l_set:
                    self.nvulnerabilities_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nvulnerabilities_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                self.nvulnerabilities_open += 1
                if 'robot component: ROS2' in l_set:
                    self.nvulnerabilities_open_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nvulnerabilities_open_moveit2 += 1

        for l_set in self.labels_closed:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                self.nvulnerabilities_closed += 1
                if 'robot component: ROS2' in l_set:
                    self.nvulnerabilities_closed_ros2 += 1
                if 'robot component: moveit2' in l_set:
                    self.nvulnerabilities_closed_moveit2 += 1

        # Number of others (neither vulns nor weaknesses)
        for l_set in self.labels:
            if "invalid" in l_set:
                continue
            if "vulnerability" not in l_set:
                if "weakness" not in l_set:
                    self.nothers += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.nothers_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" not in l_set:
                if "weakness" not in l_set:
                    self.nothers_open += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_open_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.nothers_open_moveit2 += 1

        for l_set in self.labels_closed:
            if "invalid" in l_set:
                continue            
            if "vulnerability" not in l_set:
                if "weakness" not in l_set:
                    self.nothers_closed += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_closed_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.nothers_closed_moveit2 += 1

        # Number of vulnerabilities, by severity
        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                if "severity: critical" in l_set:
                    self.vulns_critical += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_critical_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.vulns_critical_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                if "severity: high" in l_set:
                    self.vulns_high += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_high_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.vulns_high_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                if "severity: medium" in l_set:
                    self.vulns_medium += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_medium_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.vulns_medium_moveit2 += 1

        for l_set in self.labels_open:
            if "invalid" in l_set:
                continue            
            if "vulnerability" in l_set:
                if "severity: low" in l_set:
                    self.vulns_low += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_low_ros2 += 1
                    if 'robot component: moveit2' in l_set:
                        self.vulns_low_moveit2 += 1

        #######################
        # ROS-specific packages
        #######################                          
        # Process per package issue
        # NOTE: only open issues are taken into account
        packages = []
        for l_set in self.labels_open:
            if 'invalid' in l_set:
                continue
            if 'robot component: ROS2' in l_set:
                filtered_package = [i for i in l_set if "package: " in i]
                if filtered_package != []:
                    package = filtered_package[0].replace("package: ","")
                    # print("package: "+package)
                    packages.append(package)
                else:
                    print("\tl_set that has ROS2 component includes NO package: "+str(l_set))

        # now process all the packages
        # self.processed_packages is a dict containg "package_name" as keys and "number of issues" as content        
        for p in packages:
            if p in self.processed_packages.keys():
                self.processed_packages[p] += 1
            else:
                self.processed_packages[p] = 1
        
        # Obtain the number of tickets with "malformed" label
        for l_set in self.labels_open:
            if 'malformed' in l_set:
                self.malformed += 1        

    def upper_shields(self):
        """
        Produces a first line of small shields providing quick information for
        RVD maintainers.
        
        :return markdown string
        """
        markdown = ""
        # add the shields
        markdown += "[![label: upper_shield_malformed][~upper_shield_malformed]](https://github.com/aliasrobotics/RVD/labels/malformed) "
        markdown += "[![](https://img.shields.io/badge/flaws-"+str(self.open_issues_count)+"-red.svg)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+)"  + "\n"        
        markdown += "\n"
        
        # add the source of the shields
        markdown += "[~upper_shield_malformed]: https://img.shields.io/badge/malformed-" + str(self.malformed) + "-440fa8.svg" + "\n"
        return markdown        
        
    def to_markdown_general(self):
        """
        Produces a markdown output for the general table
        
        Inspired by
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown = "### General summary" + "\n"
        markdown += "*Last updated " + str(strftime("%a, %d %b %Y %H:%M:%S", gmtime())) + " GMT*\n"
        markdown += "" + "\n"
        markdown += "|       | Open      | Closed  |    All |" + "\n"
        markdown += "|-------|---------|--------|-----------|" + "\n"
        markdown += "| Vulnerabilities | [![label: vulns_open][~vulns_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: vulns_closed][~vulns_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: vulns][~vulns]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) |" + "\n"

        markdown += "| Weaknesses | [![label: weaknesses_open][~weaknesses_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+)  | \
[![label: weaknesses_closed][~weaknesses_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Aweakness+-label%3A%22invalid%22) | \
[![label: weaknesses][~weaknesses]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) |" + "\n"

        markdown += "| Others |  [![label: others_open][~others_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: others_closed][~others_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | \
 [![label: others][~others]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+)|" + "\n"
        markdown += "\n"
        markdown += "\n"

        # Summary of vulnerabilities (only open issues considered)
        markdown += "|       |       |           |          |          |" + "\n"
        markdown += "|-------|---------|---------|----------|----------|" + "\n"
        markdown += "| Vulnerabilities (open) | [![label: vulns_critical][~vulns_critical]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+) | \
[![label: vulns_high][~vulns_high]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+) | \
[![label: vulns_medium][~vulns_medium]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+) | \
[![label: vulns_low][~vulns_low]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+) |" + "\n"

        markdown += "\n"
        markdown += "\n"
        markdown += "[~vulns]: https://img.shields.io/badge/vulnerabilities-" + str(
            self.nvulnerabilities) + "-7fe0bb.svg" + "\n"
        markdown += "[~vulns_open]: https://img.shields.io/badge/vulnerabilities-" + str(
            self.nvulnerabilities_open) + "-red.svg" + "\n"
        markdown += "[~vulns_closed]: https://img.shields.io/badge/vulnerabilities-" + str(
            self.nvulnerabilities_closed) + "-green.svg" + "\n"
        markdown += "[~weaknesses]: https://img.shields.io/badge/weaknesses-" + str(
            self.nweaknesses) + "-dbf9a2.svg" + "\n"
        markdown += "[~weaknesses_open]: https://img.shields.io/badge/weaknesses-" + str(
            self.nweaknesses_open) + "-red.svg" + "\n"
        markdown += "[~weaknesses_closed]: https://img.shields.io/badge/weaknesses-" + str(
            self.nweaknesses_closed) + "-green.svg" + "\n"
        markdown += "[~others]: https://img.shields.io/badge/others-" + str(self.nothers) + "-dbf9a2.svg" + "\n"
        markdown += "[~others_open]: https://img.shields.io/badge/others-" + str(self.nothers_open) + "-red.svg" + "\n"
        markdown += "[~others_closed]: https://img.shields.io/badge/others-" + str(
            self.nothers_closed) + "-green.svg" + "\n"
        markdown += "[~vulns_critical]: https://img.shields.io/badge/vuln.critical-" + str(
            self.vulns_critical) + "-ce5b50.svg" + "\n"
        markdown += "[~vulns_high]: https://img.shields.io/badge/vuln.high-" + str(
            self.vulns_high) + "-e99695.svg" + "\n"
        markdown += "[~vulns_medium]: https://img.shields.io/badge/vuln.medium-" + str(
            self.vulns_medium) + "-e9cd95.svg" + "\n"
        markdown += "[~vulns_low]: https://img.shields.io/badge/vuln.low-" + str(self.vulns_low) + "-e9e895.svg" + "\n"
        return markdown

    def to_markdown_ros2(self):
        """
        Produces a markdown output for ROS 2
        
        Inspired by
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown = ""
        markdown += "### ROS 2" + "\n"
        markdown += "*Last updated " + str(strftime("%a, %d %b %Y %H:%M:%S", gmtime())) + " GMT*\n"
        markdown += "" + "\n"
        markdown += "|       | Open      | Closed  |    All |" + "\n"
        markdown += "|-------|---------|--------|-----------|" + "\n"
        markdown += "| `ROS 2` Vulnerabilities | [![label: vulns_open_ros2][~vulns_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_closed_ros2][~vulns_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_ros2][~vulns_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"

        markdown += "| `ROS 2` Weaknesses | [![label: weaknesses_open_ros2][~weaknesses_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: weaknesses_closed_ros2][~weaknesses_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot+component%3A+ROS2%22+) | \
[![label: weaknesses_ros2][~weaknesses_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"

        markdown += "| `ROS 2` Others | [![label: others_open_ros2][~others_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: others_closed_ros2][~others_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+)  | \
[![label: others_ros2][~others_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"
        markdown += "\n"
        markdown += "\n"

        # Summary of vulnerabilities (only open issues considered)
        markdown += "|       |       |           |          |          |" + "\n"
        markdown += "|-------|---------|---------|----------|----------|" + "\n"
        markdown += "| `ROS 2` Vulnerabilities (open) | [![label: vulns_critical_ros2][~vulns_critical_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_high_ros2][~vulns_high_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_medium_ros2][~vulns_medium_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_low_ros2][~vulns_low_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"
        markdown += "\n"
        markdown += "\n"

        # ros 2 labels
        markdown += "[~vulns_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-" + str(
            self.nvulnerabilities_ros2) + "-7fe0bb.svg" + "\n"
        markdown += "[~vulns_open_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-" + str(
            self.nvulnerabilities_open_ros2) + "-red.svg" + "\n"
        markdown += "[~vulns_closed_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-" + str(
            self.nvulnerabilities_closed_ros2) + "-green.svg" + "\n"
        markdown += "[~weaknesses_ros2]: https://img.shields.io/badge/ros2_weaknesses-" + str(
            self.nweaknesses_ros2) + "-dbf9a2.svg" + "\n"
        markdown += "[~weaknesses_open_ros2]: https://img.shields.io/badge/ros2_weaknesses-" + str(
            self.nweaknesses_open_ros2) + "-red.svg" + "\n"
        markdown += "[~weaknesses_closed_ros2]: https://img.shields.io/badge/ros2_weaknesses-" + str(
            self.nweaknesses_closed_ros2) + "-green.svg" + "\n"
        markdown += "[~others_ros2]: https://img.shields.io/badge/ros2_others-" + str(
            self.nothers_ros2) + "-dbf9a2.svg" + "\n"
        markdown += "[~others_open_ros2]: https://img.shields.io/badge/ros2_others-" + str(
            self.nothers_open_ros2) + "-red.svg" + "\n"
        markdown += "[~others_closed_ros2]: https://img.shields.io/badge/ros2_others-" + str(
            self.nothers_closed_ros2) + "-green.svg" + "\n"
        markdown += "[~vulns_critical_ros2]: https://img.shields.io/badge/ros2_vuln.critical-" + str(
            self.vulns_critical_ros2) + "-ce5b50.svg" + "\n"
        markdown += "[~vulns_high_ros2]: https://img.shields.io/badge/ros2_vuln.high-" + str(
            self.vulns_high_ros2) + "-e99695.svg" + "\n"
        markdown += "[~vulns_medium_ros2]: https://img.shields.io/badge/ros2_vuln.medium-" + str(
            self.vulns_medium_ros2) + "-e9cd95.svg" + "\n"
        markdown += "[~vulns_low_ros2]: https://img.shields.io/badge/ros2_vuln.low-" + str(
            self.vulns_low_ros2) + "-e9e895.svg" + "\n"
        
        # get some space for readability
        markdown += "\n\n"
        
        markdown += "#### ROS 2 flaws by package (only `open` ones)" + "\n"
        for key in self.processed_packages.keys():        
            markdown += "[![label: ros2_package_"+str(key)+"][~ros2_package_"+str(key)+"]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+"+str(key)+"%22)"  + "\n"

        # get some space for readability
        markdown += "\n\n"
        
        # Now add the corresponding source code for the labels
        for key in self.processed_packages.keys():
            markdown += "[~ros2_package_"+str(key)+"]: https://img.shields.io/badge/"+str(key.replace("-","_"))+"-" + str(
                self.processed_packages[key]) + "-red.svg" + "\n"

        # get some space for readability
        markdown += "\n\n"        
        return markdown

    def to_markdown_moveit2(self):
        """
        Produces a markdown output for MoveIt 2
        
        Inspired by 
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown = ""
        markdown += "#### MoveIt 2" + "\n"
        markdown += "*Last updated " + str(strftime("%a, %d %b %Y %H:%M:%S", gmtime())) + " GMT*\n"
        markdown += "" + "\n"
        markdown += "|       | All      | Open  |    Closed |" + "\n"
        markdown += "|-------|---------|--------|-----------|" + "\n"
        markdown += "| `MoveIt 2` Vulnerabilities | [![label: vulns_moveit2][~vulns_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_open_moveit2][~vulns_open_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_closed_moveit2][~vulns_closed_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"

        markdown += "| `MoveIt 2` Weaknesses | [![label: weaknesses_moveit2][~weaknesses_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: weaknesses_open_moveit2][~weaknesses_open_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: weaknesses_closed_moveit2][~weaknesses_closed_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"

        markdown += "| `MoveIt 2` Others | [![label: others_moveit2][~others_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: others_open_moveit2][~others_open_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: others_closed_moveit2][~others_closed_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"
        markdown += "\n"
        markdown += "\n"

        # Summary of vulnerabilities (only open issues considered)
        markdown += "|       |       |           |          |          |" + "\n"
        markdown += "|-------|---------|---------|----------|----------|" + "\n"
        markdown += "| `MoveIt 2` Vulnerabilities (open) | [![label: vulns_critical_moveit2][~vulns_critical_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_high_moveit2][~vulns_high_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_medium_moveit2][~vulns_medium_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_low_moveit2][~vulns_low_moveit2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+) |" + "\n"
        markdown += "\n"
        markdown += "\n"

        # ros 2 labels
        markdown += "[~vulns_moveit2]: https://img.shields.io/badge/moveit2_vulnerabilities-" + str(
            self.nvulnerabilities_moveit2) + "-7fe0bb.svg" + "\n"
        markdown += "[~vulns_open_moveit2]: https://img.shields.io/badge/moveit2_vulnerabilities-" + str(
            self.nvulnerabilities_open_moveit2) + "-red.svg" + "\n"
        markdown += "[~vulns_closed_moveit2]: https://img.shields.io/badge/moveit2_vulnerabilities-" + str(
            self.nvulnerabilities_closed_moveit2) + "-green.svg" + "\n"
        markdown += "[~weaknesses_moveit2]: https://img.shields.io/badge/moveit2_weaknesses-" + str(
            self.nweaknesses_moveit2) + "-dbf9a2.svg" + "\n"
        markdown += "[~weaknesses_open_moveit2]: https://img.shields.io/badge/moveit2_weaknesses-" + str(
            self.nweaknesses_open_moveit2) + "-red.svg" + "\n"
        markdown += "[~weaknesses_closed_moveit2]: https://img.shields.io/badge/moveit2_weaknesses-" + str(
            self.nweaknesses_closed_moveit2) + "-green.svg" + "\n"
        markdown += "[~others_moveit2]: https://img.shields.io/badge/moveit2_others-" + str(
            self.nothers_moveit2) + "-dbf9a2.svg" + "\n"
        markdown += "[~others_open_moveit2]: https://img.shields.io/badge/moveit2_others-" + str(
            self.nothers_open_moveit2) + "-red.svg" + "\n"
        markdown += "[~others_closed_moveit2]: https://img.shields.io/badge/moveit2_others-" + str(
            self.nothers_closed_moveit2) + "-green.svg" + "\n"
        markdown += "[~vulns_critical_moveit2]: https://img.shields.io/badge/moveit2_vuln.critical-" + str(
            self.vulns_critical_moveit2) + "-ce5b50.svg" + "\n"
        markdown += "[~vulns_high_moveit2]: https://img.shields.io/badge/moveit2_vuln.high-" + str(
            self.vulns_high_moveit2) + "-e99695.svg" + "\n"
        markdown += "[~vulns_medium_moveit2]: https://img.shields.io/badge/moveit2_vuln.medium-" + str(
            self.vulns_medium_moveit2) + "-e9cd95.svg" + "\n"
        markdown += "[~vulns_low_moveit2]: https://img.shields.io/badge/moveit2_vuln.low-" + str(
            self.vulns_low_moveit2) + "-e9e895.svg" + "\n"
        return markdown

    @staticmethod
    def static_content_header():
        header = """\
# Robot Vulnerability Database (RVD)

<a href="http://www.aliasrobotics.com"><img src="https://pbs.twimg.com/profile_images/1138735160428548096/px2v9MeF.png" align="left" hspace="8" vspace="2" width="200"></a>

This repository contains Alias Robotics' Robot Vulnerability and Database (RVD), an attempt to register and record robot vulnerabilities and weaknesses. 

Vulnerabilities are rated according to the [Robot Vulnerability Scoring System (RVSS)](https://github.com/aliasrobotics/RVSS). For a discussion regarding terminology and the difference between robot vulnerabilities, robot weaknesses or robot bugs refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more).

**Alias Robotics supports hacker-powered robot security in close collaboration with original robot manufacturers. By no means we encourage or promote the unauthorized tampering with running robotic systems. This can cause serious human harm and material damages.**

## Concepts
"""
        return header

    def concepts_to_markdown(self):
        """
        Summarizes RVD concepts in a markdown output
                
        :return markdown string
        """
        markdown = "Each RVD issue (ticket) corresponds with a flaw that is labeled appropriately. The meaning of the most relevant labels or statuses is covered below. Refer to the appendices for definitions on the terminology used:"  + "\n"
        
        markdown += "- [![](https://img.shields.io/badge/open-green.svg?style=flat)](#): Flaw that remains active or under research."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/closed-red.svg?style=flat)](#): Flaw that is inactive. Reasons for inactivity relate to mitigations, duplicates, erroneous reports or similar."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/invalid-red.svg?style=flat)](#): Ticket discarded and removed for the overall count. This label flags invalid or failed reports including tests and related."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/duplicate-cfd3d7.svg?style=flat)](#): Duplicated flaw. Typically, a link to the original ticket is provided."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/malformed-440fa8.svg?style=flat)](https://github.com/aliasrobotics/RVD/labels/malformed): Flaw has a malformed syntax. Refer to the templates for basic guidelines on the right syntax."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/mitigated-aaf9a7.svg?style=flat)](#): Mitigated. A link to the corresponding mitigation is required."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/quality-ddb140.svg?style=flat)](#): Indicates that the bug is a quality one instead of a security flaw."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/exposure-ccfc2d.svg?style=flat)](#): Indicates that flaw is an exposure."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/weakness-dbf9a2.svg?style=flat)](#): Indicates that flaw is a weakness."  + "\n"
        markdown += "- [![](https://img.shields.io/badge/vulnerability-7fe0bb.svg?style=flat)](#): Indicates that flaw is a vulnerability."  + "\n"        
        markdown += "- [![](https://img.shields.io/badge/severity_critical-ce5b50.svg?style=flat)](#) [![](https://img.shields.io/badge/severity_high-e99695.svg?style=flat)](#) [![](https://img.shields.io/badge/severity_medium-e9cd95.svg?style=flat)](#): Indicates the severity of the vunerability according to RVSS."  + "\n"                
        return markdown    

    @staticmethod
    def static_content_header2():
        header = """\

## ToC

- [Robot vulnerabilities (and weaknesses)](#robot-vulnerabilities-and-weaknesses)
	- [Concepts](#concepts)
    - [Table of contents](#toc)
    - [General summary](#general-summary)
	- [ROS 2](#ros-2)
		- [ROS 2 flaws by package (only `open` ones)](#ros-2-flaws-by-package-only-open-ones)
- [Disclosure policy](#disclosure-policy)
	- [Methodology](#methodology)
	- [FAQ](#faq)
- [Contributing, reporting a vulnerability](#contributing-reporting-a-vulnerability)
- [Contact us or send feedback](#contact-us-or-send-feedback)
	- [Automatic pings for manufacturers](#automatic-pings-for-manufacturers)
- [Appendices](#appendices)
	- [Appendix A: Vulnerabilities, weaknesses, bugs and more](#appendix-a-vulnerabilities-weaknesses-bugs-and-more)
		- [Discussion](#discussion)

## Robot vulnerabilities (and weaknesses)

"""
        return header

    @staticmethod
    def static_content_header3():
        header2 = """\

<details><summary><b>Robot vulnerabilities by robot component</b></summary>

By robot components, we consider both software and hardware robot components.

- Community robot components
  - [ROS](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS%22+-label%3A%22invalid%22+)
  - [ROS 2.0](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS2%22+-label%3A%22invalid%22+)
  - [navigation2](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+navigation2%22)
  - [moveit2](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+moveit2%22)

- Vendor-specific robot components
  - [ABB's Service Box](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ABB%27s+Service+Box%22+-label%3A%22invalid%22)
  - [Alpha 1S android application](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A%20Alpha%201S%20android%20application%22+-label%3A%22invalid%22)
  - [FastRTPS](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+FastRTPS%22)
  - [IRB140's flex pendant](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=label%3A"robot+component%3A%20IRB140%27s%20flex%20pendant"+-label%3A"invalid")
  - [IRB140's main computer](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A%20IRB140%27s%20main%20computer%22+-label%3A%22invalid%22)
  - [OP2 Firmware](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20OP2%20Firmware"+-label%3A"invalid")
  - [Sawyer Task Editor](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20Sawyer%20Task%20Editor"+-label%3A"invalid")
  - [Universal Robots Controller](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20Universal%20Robots%20Controller"+-label%3A"invalid")
  - [V-Sido OS](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20V-Sido%20OS"+-label%3A"invalid")

</details>

<details><summary><b>Robot vulnerabilities by robot</b></summary>

- [MARA](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A%20MARA%22+-label%3A%22invalid%22)
- [Pepper](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Pepper%22+-label%3A%22invalid%22+)
- [Nao](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+NAO%22++-label%3A%22invalid%22+)
- [Baxter](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Baxter%22++-label%3A%22invalid%22+)
- [Sawyer](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Sawyer%22+-label%3A%22invalid%22)
- [UR3](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR3%22+-label%3A%22invalid%22+)
- [UR5](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR5%22+-label%3A%22invalid%22+)
- [UR10](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR10%22+-label%3A%22invalid%22+)
- [REEM-C](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+REEM-C%22+-label%3A%22invalid%22+)
- [Alpha 1S](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot%3A+Alpha+1S%22+-label%3A%22invalid%22+)
</details>

<details><summary><b>Robot vulnerabilities by vendor</b></summary>

- [Acutronic Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A%20Acutronic%20Robotics"+-label%3A"invalid")
- [ABB](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A%20ABB"+-label%3A"invalid")
- [eProsima](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+eProsima"+-label%3A"invalid")
- [PAL Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+PAL+Robotics"+-label%3A"invalid")
- [Rethink Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Rethink+Robotics"+-label%3A"invalid")
- [Softbank Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Softbank+Robotics"+-label%3A"invalid")
- [UBTech Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+UBTech+Robotics"+-label%3A"invalid")
- [Universal Robots](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Universal+Robots"+-label%3A"invalid")
- [Vecna](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Vecna"+-label%3A"invalid")

</details>

For more, visit the [complete list](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+-label%3A%22invalid%22+) of reported robot vulnerabilities.

"""
        return header2

    @staticmethod
    def static_content_footer():
        footer = """\

## Disclosure policy

*Our disclosure policy is highly inspired by [Google's Project Zero](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-faq.html). TL;DR, we apply a 90-day disclosure deadline for new vulnerabilities*.

*This policy is strongly in line with our desire to improve the robotics industry response times to security bugs, but also results in softer landings for bugs marginally over deadline. According to [our research](https://arxiv.org/pdf/1806.06681.pdf), most vendors are ignoring security flaws completely. We call on all researchers to adopt disclosure deadlines in some form, and feel free to use our policy verbatim (we've actually done so, from [Google's](https://www.google.com/about/appsecurity/)) if you find our record and reasoning compelling. Creating pressure towards more reasonably-timed fixes will result in smaller windows of opportunity for blackhats to abuse vulnerabilities. Given the direct physical connection with the world that robots have,  in our opinion, vulnerability disclosure policies such as ours result in greater security in robotics and an overall improved safety. A security-first approach is a must to ensure safe robotic operations.*

Alias Robotics believes that vulnerability disclosure is a two-way street where both vendors and researchers, must act responsibly.  We adhere to a **90-day disclosure deadline for new vulnerabilities** while other flaws such as simple bugs or weaknesses could be filed at any point in time (refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more) for the difference between vulnerabilities, weaknesses and bugs). We notify vendors of vulnerabilities immediately, with **details shared in public with the defensive community after 90 days**, or sooner if the vendor releases a fix.

Similar to Google's policy, we want to acknowledge that the deadline can vary in the following ways:

- If a deadline is due to expire on a weekend or public holiday, the deadline will be moved to the next normal work day.
  
- Before the 90-day deadline has expired, if a vendor lets us know that a patch is scheduled for release on a specific day that will fall within 14 days following the deadline, we will delay the public disclosure until the availability of the patch.

- When we observe a previously unknown and unpatched vulnerability in software under active exploitation (a “0day”), we believe that more urgent action—within 7 days—is appropriate. The reason for this special designation is that each day an actively exploited vulnerability remains undisclosed to the public and unpatched, more devices or accounts will be compromised. Seven days is an aggressive timeline and may be too short for some vendors to update their products, but it should be enough time to publish advice about possible mitigations, such as temporarily disabling a service, restricting access, or contacting the vendor for more information. As a result, after 7 days have elapsed without a patch or advisory, we will support researchers making details available so that users can take steps to protect themselves.

Alias Robotics reserves the right to bring deadlines forwards or backwards based on extreme circumstances. We remain committed to treating all vendors strictly equally and we expect to be held to the same standard.

## CI/CD setup
In an attempt to lower the overall effort to maintain the Robot Vulnerability Database, RVD attempts to make active use of Continuous Integration (CI) and Continuous Deployment (CD) techniques through Github Actions. See our [configurations here](.github/workflows). Contributions and new ideas to this section are welcome. Please submit a Pull Request with your proposal or enhancement.

Below we list some of the existing capabilities and some tentative ones:
- [x] Comparison of stack trace before flaw submission to avoid duplicates (perfomed upstream) [refer to import_ros2.py](https://github.com/aliasrobotics/RVD/blob/master/scripts/import_ros2.py#L221)
- [x] Markdown parser that conforms with [RVD templates](.github/ISSUE_TEMPLATE/) [refer to parser.py](https://github.com/aliasrobotics/RVD/blob/master/scripts/parser/parser.py)
- [x] Automatic flaw-syntax evaluation (based on parser), tags tickets as `malformed` when applicable [refer to malformed.py#L104-L188](https://github.com/aliasrobotics/RVD/blob/master/scripts/malformed.py#L104-L188)
- [x] Automatic feedback on flaw-syntax, introduced in tickets directly as a comment [refer to malformed.py#L190-L252](https://github.com/aliasrobotics/RVD/blob/master/scripts/malformed.py#L190-L252)
- [ ] Automatic review and cross-reference of duplicated flaws, based on ticket body content and comments
- [ ] Automatic and periodic review of security advisories "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of NVD "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of CVE List "in search" for robot-related vulnerabilities
- [ ] CWE ID parser and validation method to conform with official CWE guidelines
- [ ] Automatic CWE ID validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.
- [ ] RVSS parser and validation to conform with RVSSv1.0 spec.
- [ ] Automatic RVSS validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.
- [ ] schema
    - [ ] enforce `subsystem` policy
    - [ ] enforce `id` policy
    - [ ] `architectural-location` get consistency between `platform code` and `platform-code`. Same for `application-specific`. Also, remove `ROS-specific`.
    - [ ] `specificity`, enfoce policy and allowed keywords

## Contributing, reporting a vulnerability

Vulnerabilities are community-contributed. If you believe you have discovered a vulnerability in a robot or robot component (either software or hardware), obtain public acknowledgement by submitting a vulnerability while providing prove of it. Reports can be submitted in the form of [an issue](https://github.com/aliasrobotics/RVDP/issues/new?template=vulnerability-template.md).

If you wish to contribute to the RVD repository's content, please note that this document (`README.md`) is generated automatically. Submit the corresponding PRs by looking at the `scripts/` folder. If you need some inspiration or ideas to contribute, refer to [CI/CD setup](#ci/cd-setup).


## Contact us or send feedback

Feel free to contact us if you have any requests of feedaback at **contact[at]aliasrobotics[dot]com**

### Automatic pings for manufacturers
By default, new vulnerabilities are reported to manufacturers and/or open source projects however other flaws aren't. Alias Robotics can inform manufacturers directly when weaknesses are reported. If you're interested in this service, contact **contact[at]aliasrobotics[dot]com**.

## Appendices

### Appendix A: Vulnerabilities, weaknesses, bugs and more
#### Research on terminology
[Commonly](https://en.wikipedia.org/wiki/Software_bug):
- A **software `bug`** is an error, flaw, failure or fault in a computer program or system that causes it to produce an incorrect or unexpected result, or to behave in unintended ways.

According to [CWE](https://cwe.mitre.org/about/faq.html#A.2):
- **software `weaknesses`** are errors (bugs) that can lead to software vulnerabilities.
- **software `vulnerability`** is a mistake in software that can be directly used by a hacker to gain access to a system or network.

Moreover, according to [CVE page](https://cve.mitre.org/about/faqs.html#what_is_vulnerability):
- A `vulnerability` is a `weakness` in the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that, when exploited, results in a negative impact to confidentiality, integrity or availability (more [here](https://cve.mitre.org/about/terminology.html)).
- An `exposure` is a system configuration issue or a mistake in software that allows access to information or capabilities that can be used by a hacker as a stepping-stone into a system or network.

[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) defines only vulnerability:
- **(robot) vulnerability**: weakness of an asset or control that can be exploited by one or more threats

#### Discussion and interpretation 

From the definitions above, it seems reasonable to associate use interchangeably `bugs` and `flaws` when referring to security issues. In addition, the word `weakness` seems applicable to any flaw that might turn into a `vulnerability` however it must be noted that (from the text above) a `vulnerability` "must be exploited"). Based on this a clear difference can be established classifiying flaws with potential to be exploitable as `weaknesses` and flaws exploitable as `vulnerabilities`. Ortogonal to this appear `exposures` which refer to misconfigurations that allows attackers to establish an attack vector in a system.

Based in all of the above, we interpret and make the following assumptions for RVD:
- unless specified, all `flaws` are "security flaws" (an alternative could be a quality bug)
- `flaw` and `bug` refer to the same thing and can be used interchangeably
- `weakness` is a flaw with potential to be exploited (but unconfirmed its exploitability)
- `vulnerability` is a weakness that is exploitable.
- `exposure` is a configuration error or mistake in software that *without leading to exploitation*, leaks relevant information that empowers an attacker.

### Appendix B: How does RVD relate to CVE, the CVE List and the NVD?

Some definitions:
- `Robot Vulnerability Database (RVD)` is a database for robot vulnerabilities and weaknesses that aims to record and categorize flaws that apply to robot and robot components. RVD was created as a community-contributed and open archive of robot security flaws. It was originally created and sponsored by Alias Robotics.
- `Common Vulnerabilities and Exposures (CVE)` List CVE® is an archive (dictionary according to the official source) of entries—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities. CVE contains vulnerabilities and exposures and is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA). It is **not** a database (see [official information](https://cve.mitre.org/about/faqs.html)). CVE List *feeds* vulnerability databases (such as the National Vulnerability Database (NVD)) with its entries and also acts as an aggregator of vulnerabilities and exposures reported at NVD.
- `U.S. National Vulnerability Database (NVD)` is the U.S. government repository of standards based vulnerability management data. It presents an archive with vulnerabilities, each with their corresponding CVE identifiers. NVD gets fed by the CVE List and then builds upon the information included in CVE Entries to provide enhanced information for each entry such as fix information, severity scores, and impact ratings. 

RVD does **not** aim to replace CVE but to <ins>complement it for the domain of robotics</ins>. RVD aims to become CVE-compatible (see [official guidelines for compatibility](https://cve.mitre.org/compatible/guidelines.html)) by tackling aspects such scope and impact of the flaws (through a proper severity scoring mechanism for robots), information for facilitating mitigation, detailed technical information, etc. For a more detailed discussion, see [this ROS Discourse thread](https://discourse.ros.org/t/introducing-the-robot-vulnerability-database/11105/7?u=vmayoral). 

When compared to other vulnerability databases, RVD aims to differenciate itself by focusing on the following:
- **robot specific**: RVD aims to focus and capture robot-specific flaws. If a flaw does not end-up applying to a robot or a robot component then it should not be recorded here.
- **community-oriented**: while RVD is originally sponsored by Alias Robotics, it aims to become community-managed and contributed.
- **facilitates reproducing robot flaws**: Working with robots is very time consuming. Mitigating a vulnerability or a weakness requires one to first reproduce the flaw. This can be extremely time consuming. Not so much providing the fix itself but ensuring that your environment is appropriate. At RVD, each flaw entry should aim to include a row named as `Module URL`. This should correspond with the link to a Docker image that should allow anyone reproduce the flaw easily.
- **robot-specific severity scoring**: opposed to CVSS which has strong limitations when applied to robotics, RVD uses RVSS, a robot-specific scoring mechanism.

As part of RVD, we encourage security researchers to file CVE Entries and use official CVE identifiers for their reports and discussions at RVD.


***
<!--
    ROSIN acknowledgement from the ROSIN press kit
    @ https://github.com/rosin-project/press_kit
-->

<a href="http://rosin-project.eu">
  <img src="http://rosin-project.eu/wp-content/uploads/rosin_ack_logo_wide.png"
       alt="rosin_logo" height="60" >
</a></br>

Supported by ROSIN - ROS-Industrial Quality-Assured Robot Software Components.
More information: <a href="http://rosin-project.eu">rosin-project.eu</a>

<img src="http://rosin-project.eu/wp-content/uploads/rosin_eu_flag.jpg"
     alt="eu_flag" height="45" align="left" >

This repository was partly funded by ROSIN RedROS2-I FTP which received funding from the European Union’s Horizon 2020
research and innovation programme under the project ROSIN with the grant agreement No 732287.

"""
        return footer

    def generate_readme(self):
        """
        Generates the content of the README processing the issues of the repository
        and adding default, static content.
        
        Refer to static_content_header() and static_content_footer().
        
        :return string
        """
        readme = ""
        # Quick information and input for RVD maintainers
        readme += self.upper_shields()
        # Introduction and disclaimer
        readme += self.static_content_header()
        # Concepts
        readme += self.concepts_to_markdown()        
        # ToC
        readme += self.static_content_header2()
        # general flaw numbers
        readme += self.to_markdown_general()
        readme += self.static_content_header3()
        # ROS 2 flaw numbers
        readme += self.to_markdown_ros2()
        readme += self.static_content_footer()
        return readme

    def replace_readme(self):
        """
        Replaces README.md with new content generated by
        calling generate_README
        
        :return None
        """
        readme_content = self.generate_readme()
        readme_file = open("../README.md", "w")  # NOTE, path for README.md hardcoded
        readme_file.write(readme_content)
        readme_file.close()


summary = Summary()
# print(summary.to_markdown())
# print(summary.generate_readme())
summary.replace_readme()
