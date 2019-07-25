"""
Scripts that produces a summary of vulnerabilities and weaknesses
"""

from import_base import RVDImport
from github import Label
from time import gmtime, strftime

class Summary(RVDImport):    
    def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__()
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username+"/"+self.repo_name)
        
        # All
        self.issues = [] # stores the name of each one of the issues in the corresponding repository
        self.labels = [] # labels for all issues        
        # Open
        self.issues_open = [] # stores the name of each one of the issues in the corresponding repository
        self.labels_open = [] # labels for all issues        
        # Closed
        self.issues_closed = [] # stores the name of each one of the issues in the corresponding repository
        self.labels_closed = [] # labels for all issues
        
        ### Summary attributes
        self.ntotal = 0 # Total number of weaknesses + vulnerabilities in RVD
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
        
        ### Vulnerability by severity
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
        
        ### Vulnerability by severity
        self.vulns_critical_ros2 = 0
        self.vulns_high_ros2 = 0
        self.vulns_medium_ros2 = 0
        self.vulns_low_ros2 = 0
        
        
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
        self.open_issues_count = self.repo.open_issues_count # or simply len(self.issues_open)        
        self.closed_issues_count = len(self.issues_closed)
        # Number of weaknesses
        for l_set in self.labels:
            if "weakness" in l_set:
                self.nweaknesses += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_ros2 += 1
                    
        for l_set in self.labels_open:
            if "weakness" in l_set:
                self.nweaknesses_open += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_open_ros2 += 1

        for l_set in self.labels_closed:
            if "weakness" in l_set:
                self.nweaknesses_closed += 1
                if 'robot component: ROS2' in l_set:
                    self.nweaknesses_closed_ros2 += 1
                    
        
        # Number of vulnerabilities
        for l_set in self.labels:
            if "vulnerability" in l_set:
                self.nvulnerabilities += 1
                if 'robot component: ROS2' in l_set:
                        self.nvulnerabilities_ros2 += 1

        for l_set in self.labels_open:
            if "vulnerability" in l_set:
                self.nvulnerabilities_open += 1
                if 'robot component: ROS2' in l_set:
                        self.nvulnerabilities_open_ros2 += 1

        for l_set in self.labels_closed:
            if "vulnerability" in l_set:
                self.nvulnerabilities_closed += 1
                if 'robot component: ROS2' in l_set:
                        self.nvulnerabilities_closed_ros2 += 1
        
        # Number of others (neither vulns nor weaknesses)
        for l_set in self.labels:
            if not "vulnerability" in l_set:
                if not "weakness" in l_set:
                    self.nothers += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_ros2 += 1

        for l_set in self.labels_open:
            if not "vulnerability" in l_set:
                if not "weakness" in l_set:
                    self.nothers_open += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_open_ros2 += 1

        for l_set in self.labels_closed:
            if not "vulnerability" in l_set:
                if not "weakness" in l_set:
                    self.nothers_closed += 1
                    if 'robot component: ROS2' in l_set:
                        self.nothers_closed_ros2 += 1
        
        # Number of vulnerabilities, by severity
        for l_set in self.labels_open:
            if "vulnerability" in l_set:
                if "severity: critical" in l_set:
                    self.vulns_critical += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_critical_ros2 += 1

        for l_set in self.labels_open:
            if "vulnerability" in l_set:
                if "severity: high" in l_set:
                    self.vulns_high += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_high_ros2 += 1

        for l_set in self.labels_open:
            if "vulnerability" in l_set:
                if "severity: medium" in l_set:
                    self.vulns_medium += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_medium_ros2 += 1

        for l_set in self.labels_open:
            if "vulnerability" in l_set:
                if "severity: low" in l_set:
                    self.vulns_low += 1
                    if 'robot component: ROS2' in l_set:
                        self.vulns_low_ros2 += 1



    def to_markdown_general(self):
        """
        Produces a markdown output for the general table
        
        Inspired by 
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown="### General summary"+"\n"
        markdown+="*Last updated "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))+"*\n"
        markdown+=""+"\n"
        markdown+="|       | All      | Open  |    Closed |"+"\n"
        markdown+="|-------|---------|--------|-----------|"+"\n"
        markdown+="| Vulnerabilities | [![label: vulns][~vulns]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: vulns_open][~vulns_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: vulns_closed][~vulns_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) |"+"\n"
        
        markdown+="| Weaknesses | [![label: weaknesses][~weaknesses]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) | \
[![label: weaknesses_open][~weaknesses_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) | \
[![label: weaknesses_closed][~weaknesses_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) |"+"\n"

        markdown+="| Others | [![label: others][~others]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: others_open][~others_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | \
[![label: others_closed][~others_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) |"+"\n"
        markdown+="\n"
        markdown+="\n"

        # Summary of vulnerabilities (only open issues considered)
        markdown+="|       |       |           |          |          |"+"\n"
        markdown+="|-------|---------|---------|----------|----------|"+"\n"
        markdown+="| Vulnerabilities (open) | [![label: vulns_critical][~vulns_critical]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+) | \
[![label: vulns_high][~vulns_high]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+) | \
[![label: vulns_medium][~vulns_medium]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+) | \
[![label: vulns_low][~vulns_low]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+) |"+"\n"                

        markdown+="\n"
        markdown+="\n"
        markdown+="[~vulns]: https://img.shields.io/badge/vulnerabilities-"+str(self.nvulnerabilities)+"-7fe0bb.svg"+"\n"
        markdown+="[~vulns_open]: https://img.shields.io/badge/vulnerabilities-"+str(self.nvulnerabilities_open)+"-red.svg"+"\n"
        markdown+="[~vulns_closed]: https://img.shields.io/badge/vulnerabilities-"+str(self.nvulnerabilities_closed)+"-green.svg"+"\n"
        markdown+="[~weaknesses]: https://img.shields.io/badge/weaknesses-"+str(self.nweaknesses)+"-dbf9a2.svg"+"\n"
        markdown+="[~weaknesses_open]: https://img.shields.io/badge/weaknesses-"+str(self.nweaknesses_open)+"-red.svg"+"\n"
        markdown+="[~weaknesses_closed]: https://img.shields.io/badge/weaknesses-"+str(self.nweaknesses_closed)+"-green.svg"+"\n"
        markdown+="[~others]: https://img.shields.io/badge/others-"+str(self.nothers)+"-dbf9a2.svg"+"\n"
        markdown+="[~others_open]: https://img.shields.io/badge/others-"+str(self.nothers_open)+"-red.svg"+"\n"
        markdown+="[~others_closed]: https://img.shields.io/badge/others-"+str(self.nothers_closed)+"-green.svg"+"\n"
        markdown+="[~vulns_critical]: https://img.shields.io/badge/vuln.critical-"+str(self.vulns_critical)+"-ce5b50.svg"+"\n"
        markdown+="[~vulns_high]: https://img.shields.io/badge/vuln.high-"+str(self.vulns_high)+"-e99695.svg"+"\n"
        markdown+="[~vulns_medium]: https://img.shields.io/badge/vuln.medium-"+str(self.vulns_medium)+"-e9cd95.svg"+"\n"
        markdown+="[~vulns_low]: https://img.shields.io/badge/vuln.low-"+str(self.vulns_low)+"-e9e895.svg"+"\n"
        return markdown

    def to_markdown_ros2(self):
        """
        Produces a markdown output for ROS 2
        
        Inspired by 
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown=""
        markdown+="#### ROS 2"+"\n"
        markdown+="*Last updated "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))+"*\n"
        markdown+=""+"\n"
        markdown+="|       | All      | Open  |    Closed |"+"\n"
        markdown+="|-------|---------|--------|-----------|"+"\n"
        markdown+="| `ROS 2` Vulnerabilities | [![label: vulns_ros2][~vulns_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_open_ros2][~vulns_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_closed_ros2][~vulns_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |"+"\n"
        
        markdown+="| `ROS 2` Weaknesses | [![label: weaknesses_ros2][~weaknesses_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: weaknesses_open_ros2][~weaknesses_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: weaknesses_closed_ros2][~weaknesses_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |"+"\n"

        markdown+="| `ROS 2` Others | [![label: others_ros2][~others_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: others_open_ros2][~others_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: others_closed_ros2][~others_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |"+"\n"
        markdown+="\n"
        markdown+="\n"

        # Summary of vulnerabilities (only open issues considered)
        markdown+="|       |       |           |          |          |"+"\n"
        markdown+="|-------|---------|---------|----------|----------|"+"\n"
        markdown+="| `ROS 2` Vulnerabilities (open) | [![label: vulns_critical_ros2][~vulns_critical_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_high_ros2][~vulns_high_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_medium_ros2][~vulns_medium_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+) | \
[![label: vulns_low_ros2][~vulns_low_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+) |"+"\n"
        markdown+="\n"
        markdown+="\n"

        # ros 2 labels
        markdown+="[~vulns_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-"+str(self.nvulnerabilities_ros2)+"-7fe0bb.svg"+"\n"
        markdown+="[~vulns_open_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-"+str(self.nvulnerabilities_open_ros2)+"-red.svg"+"\n"
        markdown+="[~vulns_closed_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-"+str(self.nvulnerabilities_closed_ros2)+"-green.svg"+"\n"
        markdown+="[~weaknesses_ros2]: https://img.shields.io/badge/ros2_weaknesses-"+str(self.nweaknesses_ros2)+"-dbf9a2.svg"+"\n"
        markdown+="[~weaknesses_open_ros2]: https://img.shields.io/badge/ros2_weaknesses-"+str(self.nweaknesses_open_ros2)+"-red.svg"+"\n"
        markdown+="[~weaknesses_closed_ros2]: https://img.shields.io/badge/ros2_weaknesses-"+str(self.nweaknesses_closed_ros2)+"-green.svg"+"\n"
        markdown+="[~others_ros2]: https://img.shields.io/badge/ros2_others-"+str(self.nothers_ros2)+"-dbf9a2.svg"+"\n"
        markdown+="[~others_open_ros2]: https://img.shields.io/badge/ros2_others-"+str(self.nothers_open_ros2)+"-red.svg"+"\n"
        markdown+="[~others_closed_ros2]: https://img.shields.io/badge/ros2_others-"+str(self.nothers_closed_ros2)+"-green.svg"+"\n"
        markdown+="[~vulns_critical_ros2]: https://img.shields.io/badge/ros2_vuln.critical-"+str(self.vulns_critical_ros2)+"-ce5b50.svg"+"\n"
        markdown+="[~vulns_high_ros2]: https://img.shields.io/badge/ros2_vuln.high-"+str(self.vulns_high_ros2)+"-e99695.svg"+"\n"
        markdown+="[~vulns_medium_ros2]: https://img.shields.io/badge/ros2_vuln.medium-"+str(self.vulns_medium_ros2)+"-e9cd95.svg"+"\n"
        markdown+="[~vulns_low_ros2]: https://img.shields.io/badge/ros2_vuln.low-"+str(self.vulns_low_ros2)+"-e9e895.svg"+"\n"
        return markdown

    def to_markdown(self):
        """
        Produces a markdown output
        
        Inspired by 
        - https://github.com/isaacs/github/issues/305 and
        - https://shields.io/
        
        :return markdown string
        """
        markdown =""
        markdown += self.to_markdown_general()
        markdown += self.to_markdown_ros2()
        
        return markdown
        

summary = Summary()
print(summary.to_markdown())