# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Class to abstract the vulners database
"""

from ..utils import gray, red, green, cyan, yellow
import os
import vulners
import pprint
from .defaults import *
from .flaw import *
from .base import *
from .edit import *
import ast


class Vulners:
    """
    Vulners database abstraction class https://vulners.com/

    Using https://github.com/vulnersCom/api#functions-and-methods
    """

    def token(self):
        """Fetch token from VULNERS_TOKEN env. variable"""
        # Authentication for user filing issue (must have read/write access to
        # repository to add issues to)
        try:
            self.token = os.environ['VULNERS_TOKEN']
        except KeyError:
            red("ERROR, make sure that you've VULNERS_TOKEN exported")
            exit(1)

    def __init__(self, username="aliasrobotics", repo="RVD"):
        """Init with other repo as target"""
        # Fetch the Github token
        self.token()
        # Init the API
        self.api = vulners.Vulners(api_key=self.token)

    def search(self, query, push, limit=100):
        """
        Make a search with vulners' API
        """
        # augment the query
        augmented_query = query + " order:published"
        pprint.pprint(self.api.search(augmented_query, limit))
        if push:
            yellow("Push does nothing in here!")

    def cve(self, query, push, limit=100):
        """
        Make a search with vulners' API filtering by entries with a valid
        CVE and ordering by most recent
        """
        # augment the query
        augmented_query = query + " type:cve order:published"
        results = self.api.search(augmented_query, limit)
        pprint.pprint(results)

        for element in results:
            document = default_document()  # get the default document
            # Add relevant elements to the document
            document['title'] = element['description'][:65]
            document['type'] = "vulnerability"
            document['description'] = element['description']
            document['cve'] = element['id']
            document['severity']['cvss-vector'] = "CVSS:3.0/" + str(element['cvss']['vector'])
            document['severity']['cvss-score'] = element['cvss']['score']
            document['links'] = element['vhref']
            document['flaw']['date-reported'] = arrow.get(element['lastseen']).format('YYYY-MM-DD')
            document['flaw']['date-detected'] = arrow.get(element['published']).format('YYYY-MM-DD')
            document['flaw']['detected-by-relationship'] = "security researcher"

            # Create a flaw out of the document
            flaw = Flaw(document)
            new_flaw = edit_function(0, False, None, flaw=flaw)
            # new_flaw = flaw

            if new_flaw:
                print(new_flaw)
            else:
                continue

            # Push to RVD
            if push:
                pusher = Base()  # instantiate the class to push changes
                # Get some labels for the ticket
                labels = ['vulnerability']

                # vendor_label = "vendor: " + str(query)
                # labels.append(vendor_label)

                try:
                    new_keywords = ast.literal_eval(new_flaw.keywords)
                    for l in new_keywords:
                        labels.append(l)

                except SyntaxError:
                    red("Error while parsing keywords")
                    yellow("Continuing...")

                # Push ticket
                issue = pusher.new_ticket(new_flaw, labels)
                # Update id
                new_flaw.id = issue.number

                # Update issue and links
                if isinstance(new_flaw.links, list):
                    links = new_flaw.links
                else:
                    links = []
                    if new_flaw.links.strip() != "":
                        links.append(new_flaw.links.strip())
                links.append(issue.html_url)
                new_flaw.links = links
                new_flaw.issue = issue.html_url
                if flaw.title[:4] != "RVD#":  # already has the syntax
                    new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                    flaw.title = new_title
                pusher.update_ticket(issue, flaw)
