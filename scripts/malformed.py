"""
Script that parses all tickets in RVD and detects malformed ones.

In case of a malformed ticket, the script acts as follows:
- tags the corresponding issue as malformed
- provides tips on how to fix malformed content via a comment in the corresponding
issue

Run:
    python3 malformed.py
"""

from import_base import RVDImport
from parser.parser import RVDParser

# mandatory for compliance
VULNERABILITY = [
        "robot_or_component", 
        "cwe_id", 
        "rvss_score", 
        "rvss_vector",
        "attack_vector",
        "description"
                ]
WEAKNESS_EXPOSURES = [
        "robot_or_component", 
        "cwe_id", 
        "attack_vector",
        "description"
                ]
# EXPOSURE = [
#         "robot_or_component", 
#         "cwe_id", 
#         "attack_vector",
#         "description"
#                 ]

class Malformed(RVDImport):
    def __init__(self, username="aliasrobotics", repo="RVD"):
        super().__init__()
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username + "/" + self.repo_name)
        self.parser = RVDParser()
    
    def validate_robot_or_component(self, robot_or_component):
        """
        Validate the robot_or_component element
        
        :return bool
        """
        # TODO: validate this value
        return True

    def validate_cwe_id(self, cwe_id):
        """
        Validate the cwe_id element
        
        :return bool
        """
        # TODO: validate this value
        return True

    def validate_attack_vector(self, attack_vector):
        """
        Validate the attack_vector element
        
        :return bool
        """
        # TODO: validate this value
        return True

    def validate_description(self, description):
        """
        Validate the description element
        
        :return bool
        """
        # TODO: validate this value
        return True
        
    def validate(self, issue, flaw_type, tab):
        """
        Method that receives and issue and returns a data structure
        validating whether the required fields are valid or not.
        
        :param issue: Issue to analyze
        :param flaw_type (string): 'weakness', 'exposure' or `vulnerability`
        :param tab, string to introduce before each print in stdout, formatting purposes
        :return [dict]
        """
        validation = None
        if flaw_type:
            validation = {}
            if flaw_type == "weakness" or flaw_type == "exposure":
                
                # TODO: review
                # This should change if weakness and exposure stop sharing the same values
                for elem in WEAKNESS_EXPOSURES:
                    validation[elem] = False # set to False by default all elements

                # robot_or_component
                robot_or_component = self.parser.get_robot_or_component()
                if robot_or_component:
                    validation["robot_or_component"] = self.validate_robot_or_component(robot_or_component)                    
                
                # cwe_id
                cwe_id = self.parser.get_cwe_id()
                if cwe_id:
                    validation["cwe_id"] = self.validate_cwe_id(cwe_id)
                    
                # attack_vector
                attack_vector = self.parser.get_attack_vector()
                if attack_vector:
                    validation["attack_vector"] = self.validate_attack_vector(attack_vector)
                
                # description
                description = self.parser.get_description()
                if description:
                    validation["description"] = self.validate_description(description)
                                
            elif flaw_type == "vulnerability":
                for elem in VULNERABILITY:
                    validation[elem] = False # set to False by default all elements
                
                # robot_or_component
                robot_or_component = self.parser.get_robot_or_component()
                if robot_or_component:
                    validation["robot_or_component"] = self.validate_robot_or_component(robot_or_component)
                
                # cwe_id
                cwe_id = self.parser.get_cwe_id()
                if cwe_id:
                    validation["cwe_id"] = self.validate_cwe_id(cwe_id)
                    
                # rvss_score
                rvss_score = self.parser.get_rvss_score()
                if rvss_score:
                    validation["rvss_score"] = self.validate_rvss_score(rvss_score)
                
                # rvss_vector
                rvss_vector = self.parser.get_rvss_vector()
                if rvss_vector:
                    validation["rvss_vector"] = self.validate_rvss_vector(rvss_vector)                    

                # attack_vector
                attack_vector = self.parser.get_attack_vector()
                if attack_vector:
                    validation["attack_vector"] = self.validate_attack_vector(attack_vector)
                
                # description
                description = self.parser.get_description()
                if description:
                    validation["description"] = self.validate_description(description)
            else:
                raise Exception("Something went wrong, flaw_type: "+str(flaw_type))
            
            for key,value in validation.items():            
                if value:
                    print(tab+key+": OK")
                else:
                    print(tab+key+": x")
            # return the validation performed
            return validation
        else:            
            return validation
    
    def add_malformed_feedback(self, issue, validation, tab):
        """
        Method that adds feedback on a few regarding why it's malformed.
        Such feedback is added as a new comment.

        :param issue: Issue to analyze
        :param validation, dict with validation elements as keys and boolean results of validation as values
        :param tab, string to introduce before each print in stdout, formatting purposes
        :return
        """
        feedback = ""
        feedback += "#### Feedback (automatically generated):" + "\n"
        
        print(tab+"sending feedback to the issue")
        for key,value in validation.items():
            if not(value):
                # robot_or_component
                if key == "robot_or_component":
                    feedback += "- <ins>FIXME</ins>: `Robot` or `Robot component` **not** present in summary table or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `Robot` or `Robot component` **not** present in summary table")
                    
                    
                # cwe_id
                if key == "cwe_id":
                    feedback += "- <ins>FIXME</ins>: `CWD ID` **not** present in summary table or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `CWD ID` **not** present in summary table or **invalid**")
                
                # rvss_score 
                if key == "rvss_score":
                    feedback += "- <ins>FIXME</ins>: `RVSS score` **not** present in summary table or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `RVSS score` **not** present in summary table or **invalid**")
                
                # rvss_vector
                if key == "rvss_vector":
                    feedback += "- <ins>FIXME</ins>: `RVSS vector` **not** present in summary table or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `RVSS vector` **not** present in summary table or **invalid**")
                
                # attack_vector
                if key == "attack_vector":
                    feedback += "- <ins>FIXME</ins>: `Attack vector` **not** present in summary table or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `Attack vector` **not** present in summary table or **invalid**")
                
                # description
                if key == "description":
                    feedback += "- <ins>FIXME</ins>: `### Description` **not** present or **invalid**, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets and get inspiration" + "\n"
                    print(tab+"\t- `### Description` **not** present or **invalid**")
        
        
        feedback += "\n"
        feedback += "Please review the feedback above. Once addressed, either request the removal of the `malformed` label to trigger another automatic review." + "\n"
        issue.create_comment(feedback)
        
        # TODO: check first is malformed label 
    def validate_issues(self):
        """
        Method that goes through all RVD flaws (issues) and validates them. For each, it does:
        - check if malformed label is present, in case it's not:
            - check whether issue conforms with templates through the Parser class
            - add malformed label
            - add feedback to flaw as a comment
        
        This method prints in in stdout a summary of the tickets malformed.
        
        :return None
        """
        # list of malformed flaws
        malformed_list = []

        # # fetch open issues
        issues = self.repo.get_issues(state="open")        
        for issue in issues:        
            print("Validating ticket: "+str(issue.number))
            labels = issue.labels
            skip = False # skip if `malformed` label already in the issue
            for l in labels:
                if l.name == "malformed":
                    skip = True

            if skip:    
                print("\t- Ticket already malformed, skipping")
                malformed_list.append(issue)
            else:
                print("\t- parsing body...")
                self.parser.parse(issue.body)
                flaw_type = self.parser.get_flaw_type()
                
                # validate issue
                print("\t- validating...")
                validation = self.validate(issue, flaw_type, tab="\t\t* ")  
                if validation:
                    # process validation and ensure all values are valid
                    validation_result = True
                    for key,value in validation.items():
                        validation_result &= value                                                

                    if validation_result:
                        print("\t- valid")
                    else:
                        print("\t- invalid")
                        # Tagging as malformed
                        print("\t\t* tagging as `malformed`")
                        # # This other approach, didn't work, required a different data structure
                        # labels = issue.get_labels()
                        # labels_list = [str(l.name) for l in labels]
                        # labels_list.append("malformed")
                        # issue.set_labels(labels_list)
                        issue.add_to_labels("malformed")
                        
                        # Adding it to the list of malformed
                        malformed_list.append(issue)
                        
                        # Report malformed feedback as a comment                    
                        self.add_malformed_feedback(issue, validation, tab="\t\t* ")
                else:
                    # No flaw identified in issue, act appropriate
                    
                    # Tagging as malformed
                    print("\t\t* tagging as `malformed`")
                    issue.add_to_labels("malformed")
                    
                    # Report feedback that flaw wasn't identified and send as comment
                    feedback = "#### Feedback (automatically generated):" + "\n"
                    feedback += "- <ins>FIXME</ins>: Flaw **not** identified as a vulnerability, weakness or exposure. \
                                    Have you included `# Vulnerability (or Weakness or Exposure) report` at the top of the ticket?, see \
                                    ![Vulnerability report template](https://github.com/aliasrobotics/RVD/blob/master/.github/ISSUE_TEMPLATE/vulnerability-template.md)\
                                    for more information or review other tickets to get inspiration" + "\n"
                    print("\t\t* Flaw **not** identified as a vulnerability, weakness or exposure")
                    feedback += "\n"
                    feedback += "Please review the feedback above. Once addressed, either request the removal of the `malformed` label to trigger another automatic review." + "\n"
                    issue.create_comment(feedback)
                
        print("\n")
        print("Malformed statistics")
        print("--------------------")
        print("\t- number of malformed flaws: "+str(len(malformed_list))+"/"+str(self.repo.open_issues))
        if len(malformed_list) > 0:
            print("\t- malformed flaws:")
            for flaw in malformed_list:
                print("\t\t* "+str(flaw.number)+" - "+str(flaw.title))
        
        # # get comments and process them
        # comments = issue.get_comments()
        # for comment in comments:
        #     print(comment.body)

m = Malformed()
m.validate_issues()