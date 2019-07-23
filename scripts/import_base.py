"""
Base class for importing stuff
"""

from github import Github
import os

class RVDImport:

    def __init__(self):
        # Authentication for user filing issue (must have read/write access to
        # repository to add issue to)
        self.token = os.environ['GITHUB_TOKEN'] #ffb0d091869e647e3db4baa4d71dcb5c3c6a17d7
        # First create a Github instance:
        # or using an access token
        self.g = Github(self.token)

    # def __init__(self, user, password):
    #     # TODO
    #     username = os.environ['GITHUB_USER']
    #     password = os.environ['GITHUB_USER']
