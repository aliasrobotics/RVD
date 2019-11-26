# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Gitlab importer class, fetches tickets/flaws from Gitlab's
private repositories.

Requires ones to have the right configuration file at
    $HOME/.python-gitlab.cfg
"""

import re
from ..database.base import Base
import gitlab
import os
from ..utils import red


class GitlabImporter(Base):
    def __init__(self, username="aliasrobotics", repo="RVD"):
        """
        Imports tickets from Gitlab's private repos
        """
        super().__init__(username, repo)

        try:
            self.token = os.environ['GITLAB_TOKEN']
        except KeyError:
            red("ERROR, make sure that you've GITHUB_TOKEN exported")
            exit(1)

        # Initialize Gitlab's object
        self.repo = gitlab.Gitlab('https://gitlab.com', private_token=self.token)

    def get_table(self, label):
        """
        Returns a tabulate ready table

        NOTE: Only open issues are considered for this source of information.

        :param label, tuple with labels, could be more than one
        :param is, status of the issues (could be "open", "closed" or "all")
        :return list[list]
        """
        table = []
        project = self.repo.projects.get(15400852)
        issues = project.issues.list()
        for issue in issues:
            if 'flaw' in issue.attributes['labels']:
                # print(issue.attributes['title'])
                # print(issue.attributes.keys())
                if label:
                    if label in issue.attributes['labels']:
                        row = [0, issue.attributes['title']]
                        table.append(row)
                else:
                    row = [0, issue.attributes['title']]
                    table.append(row)

        return table
