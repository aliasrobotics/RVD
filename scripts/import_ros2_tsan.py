"""
A script to import the output of TSan sanitizer over ROS 2 into issues
Usage:
    python3 import_ros2_tsan.py '/opt/ros2_ws/sanitizer_report.csv'  'ROS 2'
"""

from import_ros2_asan import RVDImport_ASan
from sys import argv

class RVDImport_TSan(RVDImport_ASan):
    """
    Deal with TSan reports and file them as issues in RVD
    """
    def __init__(self, username="vmayoral", repo="test"):
    # def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__() 

    def make_issue_body(self, dict_elem, robot_component="ROS 2", reporter = "vmayoral"):
        """
        Make and return the body of an TSan-related weakness using markdown
        :param robot_component:
        :param reporter:
        :param dict_elem: dictionary element corresponding to one of the
            entries of the csv
        :return string
        """
        # Each dict_elem should have the following keys: 
        #       package,error_name,stack_trace_key,count,sample_stack_trace
        # Let's compose the body of the issue based on that assumption
        body = ""
        body += "| Input      | Value  |"+"\n"
        body += "|---------|--------|"+"\n"
        body += "| Robot component | "+robot_component+" |"+"\n"
        body += "| Vendor  | N/A |"+"\n"
        body += "| CVE ID  | N/A  |"+"\n"
        body += "| CWE ID  | " + self.find_cwe(dict_elem) + " |"+"\n"
        body += "| RVSS Score  |  N/A |"+"\n"
        body += "| RVSS Vector | N/A |"+"\n"
        body += "| GitHub Account | "+reporter+" |"+"\n"
        body += "| Date Reported  | "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())) + " |"+"\n"
        body += "| Date Updated   | "+str(strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())) + " |"+"\n"
        body += "| Exploitation vector | Internal network, robotics framework |"+"\n"
        body += "\n"
        body += "\n"
        body += "### Description"+"\n"
        body += "Issue detected while running Thread Sanitizer (TSan)."+"\n"
        body += "\n"
        body += "### Stack trace"+"\n"
        body += "```"+"\n"
        body += str(dict_elem["sample_stack_trace"])+"\n"
        body += "```"+"\n"
        return body
        
# Instance to import results
# importer = RVDImport_ASan(username="vmayoral", repo="test")
if len(argv) < 3:
    print("ERROR: No file provided")
    sys.exit(0)    
else:
    file = argv[1]
    robot_component = argv[2]
    
importer = RVDImport_TSan(username="aliasrobotics", repo="RVD")
importer.add_new_issues(file, robot_component=robot_component)
