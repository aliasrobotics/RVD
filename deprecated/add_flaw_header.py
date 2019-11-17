"""
Alias Robotics SL 
https://aliasrobotics.com

Adds a header ("# Weakness report") to all open issues that have a "weakness" label and are malformed.

Run:
    python3 add_flaw_header.py
"""

from github import Github
import os
from parser.parser import RVDParser

try:
    token = os.environ['GITHUB_TOKEN'] 
except KeyError:
    print("Make sure that you've GITHUB_TOKEN exported")
    exit(1)

parser = RVDParser()

# First create a Github instance:
# or using an access token
g = Github(os.environ['GITHUB_TOKEN'])
repo = g.get_repo("aliasrobotics/RVD")

labels = None # keep the labels variable for later use

# Get all issues and include malformed ones in a list
issues_malformed = [] # list of issues that are malformed


issues = repo.get_issues(state="open")
# issues = [repo.get_issue(number=167), repo.get_issue(number=166), repo.get_issue(number=164)] # ONLY FOR TESTING

for issue in issues:
    labels = [l.name for l in issue.labels]
    if "malformed" in labels:
        issues_malformed.append(issue)
        
# Iterate over them, check if title is present and
#  if not, add it and untag them as malformed
for malformed in issues_malformed:
    print("Analyzing: "+str(malformed))
    labels = [l.name for l in malformed.labels]
    parser.parse(malformed.body)
    flaw_type = parser.get_flaw_type()

    if flaw_type is None:
        print("\t- No header detected...")
        header = ""
        header += "# "
        # No flaw identified from parser, see if labels indicate 
        # something to construct the header
        if "weakness" in labels:
            # assume it's a weakness
            header += "Weakness report"
        elif "vulnerability" in labels:
            header += "Vulnerability report"
        elif "exposure" in labels:
            header += "Exposure report"
        else:
            # default to weakness
            header += "Weakness report"
        header +="\n"        
        content = malformed.body
        reviewed_body = header+content # get the new body adding the header
        
        print("\t- Editing, adding header and removing malformed label...")
        labels.remove("malformed") # remove that label
        malformed.edit(title=malformed.title, body=reviewed_body, assignees=malformed.assignees, labels=labels)
        print("\t- Done!")
        # issue.remove_from_labels("malformed")
        
