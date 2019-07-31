import json
import requests
import csv
import sys
import os
from import_base import RVDImport
from time import gmtime, strftime
from sys import argv

class RVDImport_ASan(RVDImport):
    
    def __init__(self, username="vmayoral", repo="test"):
    # def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__()
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username+"/"+self.repo_name)
        self.issues = [] # stores the name of each one of the issues in the corresponding repository
        self.csv_elements = None
        
    def list_repos(self):
        # Then play with your Github objects:
        for repo in self.g.get_user().get_repos():
            print(repo.name)

    def init_issue_names(self):
        """
        Inits the existing issues in the repo by adding their 
        names into the class attribute self.issues
        """
        issues = self.repo.get_issues(state="all")
        for issue in issues:
            self.issues.append(issue)        

    def parse_csv(self, file="issues.csv"):
        """
        Parse csv file and return a list filled with dictionaries corresponding 
        to each one of the elements
        
        :param file: file to parse, relative path
        :return list[dict] of csv elements
        """
        parsed_list = []
        with open(file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # typically ASan dumps the following elements: 
                #   package,error_name,stack_trace_key,count,sample_stack_trace
                # let's make a dict out of it
                elem = {
                    'package':row['package'],
                    'error_name':row['error_name'],
                    'stack_trace_key':row['stack_trace_key'],
                    'count':row['count'],
                    'sample_stack_trace':row['sample_stack_trace'],
                }
                parsed_list.append(elem)
        self.csv_elements = parsed_list        
        
    def make_issue(self, title="This is a new issue", body="This is the body", labels=None):
        """
        Make a new issue
        
        If label/s doesn't exist, it creates them automatically.
        """
        self.repo.create_issue(title=title, body=body, labels=labels)
        
    def make_issue(self, dict_elem, 
                        robot_component="ROS 2",
                        reporter = "vmayoral"):
        """
        Make a new issue
                
        If label/s doesn't exist, it creates them automatically.
        
        :param dict_elem: dictionary element corresponding to one of the 
            entries of the csv 
        :param robot_component: additional information for the construction of 
            the issue related to the robot component
        :param reporter: username of the person reporting the issues
        """
        title = self.make_issue_title_asan(dict_elem)
        body = self.make_issue_body_asan(dict_elem, robot_component)
        labels = ["weakness", "components software"]
        if robot_component == "ROS 2":
            labels.append("robot component: ROS2")
        elif robot_component == "moveit2":
            labels.append("robot component: ROS2")
            labels.append("robot component: moveit2")
        print("\tMaking issue with title '"+title+"'")
        self.repo.create_issue(title=title, body=body, labels=labels)        

    def make_issue_title_asan(self, dict_elem):
        """
        Make and return the title of an ASan-related weakness using markdown
        :param dict_elem: dictionary element corresponding to one of the 
            entries of the csv
        :return string
        """
        # Each dict_elem should have the following keys: 
        #       package,error_name,stack_trace_key,count,sample_stack_trace
        # Let's compose the body of the issue based on that assumption with a
        # structure as follows:
        #       rcl: detected memory leaks, __default_zero_allocate
        title = ""
        title += str(dict_elem["package"])
        title +=": "
        title += str(dict_elem["error_name"])
        title +=", "
        title += str(dict_elem["stack_trace_key"]).split("/")[0]
        if len(title) > 60:
            return title[:60]+"..."
        else:
            return title


    def make_issue_body_asan(self, dict_elem, robot_component="ROS 2", reporter = "vmayoral"):
        """
        Make and return the body of an ASan-related weakness using markdown
        :param dict_elem: dictionary element corresponding to one of the 
            entries of the csv
        :return string
        """
        # Each dict_elem should have the following keys: 
        #       package,error_name,stack_trace_key,count,sample_stack_trace
        # Let's compose the body of the issue based on that assumption
        body=""
        body+="| Input      | Value  |"+"\n"
        body+="|---------|--------|"+"\n"
        body+="| Robot component | "+robot_component+" |"+"\n"
        body+="| Vendor  | N/A |"+"\n"
        body+="| CVE ID  | N/A  |"+"\n"
        body+="| CWE ID  | "+ self.find_cwe(dict_elem) +" |"+"\n"
        body+="| RVSS Score  |  N/A |"+"\n"
        body+="| RVSS Vector | N/A |"+"\n"
        body+="| GitHub Account | "+reporter+" |"+"\n"
        body+="| Date Reported  | "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())) +" |"+"\n"
        body+="| Date Updated   | "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())) +" |"+"\n"
        body+="| Exploitation vector | Internal network, robotics framework |"+"\n"
        body+="\n"
        body+="\n"
        body+="### Description"+"\n"
        body+="Issue detected while running Address Sanitizer (ASan)."+"\n"
        body+="\n"
        body+="### Stack trace"+"\n"
        body+="```"+"\n"
        body+= str(dict_elem["sample_stack_trace"])+"\n"
        body+="```"+"\n"
        return body

    def find_cwe(self, dict_elem):
        """
        Find out CWE id from "error_name" in the element
        :param dict_elem: dictionary element corresponding to one of the 
            entries of the csv
        :return string
        """
        if dict_elem["error_name"] == "detected memory leaks":
            # See https://cwe.mitre.org/data/definitions/401.html
            return "[CWE-401: Missing Release of Memory after Effective Lifetime](https://cwe.mitre.org/data/definitions/401.html)"
        elif dict_elem["error_name"] == "alloc-dealloc-mismatch":
            # See https://cwe.mitre.org/data/definitions/400.html
            return "[CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)"
        else:
            return "N/A"
        

    def add_new_issues(self, file="issues.csv", robot_component="ROS 2", reporter = "vmayoral"):
        """
        Retrieves information from csv, determines which ones already
        exist in the RVD and produces the corresponding new issues.        
        """
        self.parse_csv(file)
        if self.csv_elements == None:
            print("ERROR: No elements parsed correctly")
            sys.exit(0)
        # Fetch all issue titles, including closed ones
        self.init_issue_names()
        # Discard already existing ones to avoid duplicates
        self.discard_existing()
        # Add the remaining as issues to the repo
        for elem in self.csv_elements:
            self.make_issue(elem, robot_component=robot_component, reporter=reporter)

    def discard_existing(self):
        """
        Parse elements coming from CSV against existing issues.
        Remote duplicates according to title
        """                
        # auxiliary list of dicts with no duplicates when compared to existing issues
        no_duplicates = []
        for elem in self.csv_elements:
            title = self.make_issue_title_asan(elem)
            # print("*******")
            # print(title)
            # print(len(no_duplicates))
            # print("*******")
            duplicate = False
            for issue in self.issues:
                # print(issue.title)
                # print("////////////////")
                # print(issue.title)
                # print(title)
                # print("****************")
                if issue.title == title:
                    print("REJECTED: issue with title '"+title+"' already existing")
                    duplicate = True
                    break
            if not duplicate:                    
                no_duplicates.append(elem)        
        # print("length no_duplicates: "+str(len(no_duplicates)))
        # print("length self.csv_elements: "+str(len(self.csv_elements)))
        self.csv_elements = no_duplicates
                            

# Instance to import results
# importer = RVDImport_ASan(username="vmayoral", repo="test")
if len(argv) < 3:
    print("ERROR: No file provided")
    sys.exit(0)    
else:
    file = argv[1]
    robot_component = argv[2]
    
importer = RVDImport_ASan(username="aliasrobotics", repo="RVD")
importer.add_new_issues(file, robot_component=robot_component)