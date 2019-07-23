"""
Scripts that produces a summary of vulnerabilities and weaknesses
"""

class Summary(RVDImport):    
    def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__()
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username+"/"+self.repo_name)
        self.issues = [] # stores the name of each one of the issues in the corresponding repository        

    def init_issue_names(self):
        """
        Inits the existing issues in the repo by adding their 
        names into the class attribute self.issues
        """
        issues = self.repo.get_issues(state="all")
        for issue in issues:
            self.issues.append(issue)        

    def to_markdown(self):
        """
        Produces a markdown output        
        """


summary = Summary()
print(summary.to_markdown())