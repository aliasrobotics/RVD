# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Markdown importer class, provides primitives to parse and import text in the
flaws based on the old markdown templates

Inspired slightly by https://github.com/lepture/mistune
"""

import re
from ..database.base import Base


class MarkdownImporter(Base):
    def __init__(self, username="aliasrobotics", repo="RVD"):
        """
        Import markdown syntax

        Reflects the previous syntax used in RVD (prior to YAML)
        """
        super().__init__(username, repo)
        self.headers = None
        self.links = None
        self.h1_headers = None
        self.table_rows = None
        self.code_blocks = None
        self.description = None

        # Markdown regular expressions
        self.MARKDOWN_LINK = r'\[([^\[]+)\]\(([^\)]+)\)'
        self.MARKDOWN_HEADERS = r'^(#+)(.*)'
        self.MARKDOWN_H1_HEADERS = r'^# (.*)'
        self.MARKDOWN_REPORT_TABLE_ROW = r'^\| *(.*) *\| *(.*) *\|'
        self.MARKDOWN_CODE = r'```([a-z]*\n[\s\S]*?\n)```'

        ## RVD specific expresions
        self.RVD_DESCRIPTION = r'Description\:*.*\n*(.*[\s\S]*)'

    def __str__(self):
        """
        str() method for the class which allows to debug
        values quickly

        :return string
        """
        return_str = ""

        # headers
        if self.headers:
            return_str += "Headers (#*):" + "\n"
            for x in self.headers:
                return_str += "\t"+str(x) + "\n"
        # h1_headers
        if self.h1_headers:
            return_str += "H1 headers (# .*):" + "\n"
            for x in self.h1_headers:
                return_str += "\t"+str(x) + "\n"
        # links
        if self.links:
            return_str += "Links ([]()):" + "\n"
            for x in self.links:
                return_str += "\t"+str(x) + "\n"
        # table_rows
        if self.table_rows:
            return_str += "Table rows (|bla| bla|):" + "\n"
            for x in self.table_rows:
                return_str += "\t"+str(x) + "\n"
        # code_blocks
        if self.code_blocks:
            return_str += "Code blocks (``` bla ```):" + "\n"
            for x in self.code_blocks:
                return_str += "\t"+str(x) + "\n"

        # description
        if self.description:
            return_str += "Description:" + "\n"
            return_str += "\t"+str(self.description) + "\n"

        return return_str

    def parse(self, content):
        """
        Parse content and fill up internal data structures

        :return: None
        """
        # Parse general markdown content
        self.headers = re.findall(self.MARKDOWN_HEADERS, content,
                                  re.MULTILINE)
        self.h1_headers = re.findall(self.MARKDOWN_H1_HEADERS,
                                     content,  re.MULTILINE)
        self.links = re.findall(self.MARKDOWN_LINK, content, re.MULTILINE)
        self.table_rows = re.findall(self.MARKDOWN_REPORT_TABLE_ROW,
                                     content,  re.MULTILINE)
        self.code_blocks = re.findall(self.MARKDOWN_CODE,
                                      content,  re.MULTILINE)

        # parse RVD-specific content
        self.description = re.findall(self.RVD_DESCRIPTION,
                                      content,  re.MULTILINE)

        # # Example fetching a markdown link
        # result = re.search(self.MARKDOWN_LINK, content)
        # print(result.group(0)) # print the entire match
        # print(result.group(1)) # print text
        # print(result.group(2)) # print link
        # print(re.findall(self.MARKDOWN_LINK, content))

        # # Example showing how to use re.search and re.findall
        # # m = re.search((r'trial'), 'trial and error 1, trial and error 2')
        # m = re.findall(r'trial', 'trial and error 1, trial and error 2')
        # print(m)

    def get_flaw_type(self):
        """
        This method parses self.h1_headers and determines based on that
        whether the flaw parsed is a:
        - vulnerability
        - weakness
        - exposure

        return :string
        """
        if len(self.h1_headers) < 1:
            return None

        if len(self.h1_headers) > 1:
            print("Warning, more than one top level headers.")

        # Checks only in the first element
        if "weakness" in self.h1_headers[0].lower():
            return "weakness"
        elif "exposure" in self.h1_headers[0].lower():
            return "exposure"
        elif "vulnerability" in self.h1_headers[0].lower():
            return "vulnerability"
        else:
            return None

    def get_vendor(self):
        """
        Return the vendor, if exists

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if "vendor" in row[0].lower():
                    return row[1].strip()
            return None
        return None

    def get_robot_or_component(self):
        """
        Return the name of the robot or robot component introduced.

        Syntax follows from the templates of vulnerability,
        weakness or exposure.

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if "robot" in row[0].lower():
                    return row[1].strip()
                elif "component" in row[0].lower():
                    return row[1].strip()
            return None
        return None

    def get_attack_vector(self):
        """
        Return the attack vector or None

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if ("attack vector" in row[0].lower()) or ("exploitation vector" in row[0].lower()):
                    return row[1].strip()
            return None
        return None

    def get_cwe_id(self):
        """
        Return the CWE ID or None

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if "cwe id" in row[0].lower():
                    # if self.parse_cwe_id(row[1].strip()): # TODO re-enable
                    return row[1].strip()
            return None
        return None

    def get_rvss_score(self):
        """
        Return the RVSS score or None

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if "rvss score" in row[0].lower():
                    return row[1].strip()
            return None
        return None

    def get_rvss_vector(self):
        """
        Return the RVSS vector or None

        :return string or None
        """
        if self.table_rows:
            for row in self.table_rows:
                if "rvss vector" in row[0].lower():
                    # if self.parse_rvss_vector(row[1].strip()):
                    return row[1].strip()
            return None
        return None

    def get_description(self):
        """
        Return the description content

        :return string
        """
        if self.description:
            if self.description[0] != '':
                return self.description[0].split('Stack trace')[0]

        return None

    def get_stack_trace(self):
        """
        Return the stack trace or None

        :return string or None
        """
        if self.description:
            if self.description[0] != '':
                stack = ''
                stack = self.description[0].split('Stack trace\r\n```\r\n')
                if len(stack) > 1:
                    stack = stack[1]
                    stack = stack.replace('```', '')
                    return stack
                else:
                    return None
        return None
