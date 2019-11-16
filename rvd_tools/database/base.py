# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Base class for importing stuff
"""

from github import Github
import os
from ..utils import red


class Base:
    """ Base class for importing stuff in RVD

        Used both by importers of content as well as by
        other RVD utilities to fetch data from the database
    """

    def token(self):
        """Fetch token from GITHUB_TOKEN env. variable"""
        # Authentication for user filing issue (must have read/write access to
        # repository to add issues to)
        try:
            self.token = os.environ['GITHUB_TOKEN']
        except KeyError:
            red("ERROR, make sure that you've GITHUB_TOKEN exported")
            exit(1)
        # First create a Github instance:
        # or using an access token
        self.g = Github(self.token)

    def __init__(self, username="aliasrobotics", repo="RVD"):
        """Init with other repo as target"""
        # Fetch the Github token
        self.token()

        # No username/repo provided thereby, default to RVD ones
        self.username = username
        self.repo_name = repo
        self.repo = self.g.get_repo(self.username+"/"+self.repo_name)
