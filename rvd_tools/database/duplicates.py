# -*- coding: utf-8 -*-
#
# Alias Robotics S.L.
# https://aliasrobotics.com

"""
Class that manages de-duplication of RVD flaws
"""

import dedupe
from .base import *
from ..utils import gray, red, green, cyan, yellow
import sys
import os
import yaml
from .flaw import *
import pprint

class Duplicates(Base):
    """
    Makes use of dedupe to manage flaw de-duplication
    """

    def __init__(self):
        super().__init__()
        # If a settings file already exists, we'll just load that and skip training
        # NOTE: settings file should be re-generated using the training() method
        self.settings_file = 'training/csv_example_learned_settings'
        self.training_file = 'training/csv_example_training.json'

        # Define the fields dedupe will pay attention to
        self.fields = [
            # {'field': 'title', 'type': 'String', 'crf': True},
            # {'field': 'title', 'type': 'String'},
            {'field': 'type', 'type': 'String'},
            # {'field': 'cwe', 'type': 'String'},
            {'field': 'description', 'type': 'String', 'has missing': True},
            # {'field': 'flaw_trace', 'type': 'String', 'has missing': True},
            # {'field': 'cve', 'type': 'String'},
            # {'field': 'cwe', 'type': 'String', 'crf': True},
            # {'field': 'system', 'type': 'String'},
            # {'field': 'vendor', 'type': 'String'},
            # {'field': 'flaw_date-detected', 'type': 'String'},
            # {'field': 'flaw_date-reported', 'type': 'DateTime'},
        ]

    def train(self, data_d):
        """
        Train classifiers using logistic regression over the the RVD flaws
        """
        cyan("Duplicates, training the classifiers using dedupe...")

        # Create a new deduper object and pass our data model to it.
        deduper = dedupe.Dedupe(self.fields)

        # If we have training data saved from a previous run of dedupe,
        # look for it and load it in.
        # __Note:__ if you want to train from scratch, delete the training_file
        if os.path.exists(self.training_file):
            gray('Reading labeled examples from ', self.training_file)
            with open(self.training_file, 'rb') as f:
                deduper.prepare_training(data_d, f)
        else:
            deduper.prepare_training(data_d)

        # ## Active learning
        # Dedupe will find the next pair of records
        # it is least certain about and ask you to label them as duplicates
        # or not.
        # use 'y', 'n' and 'u' keys to flag duplicates
        # press 'f' when you are finished
        gray('Starting active labeling...')
        dedupe.consoleLabel(deduper)

        # Using the examples we just labeled, train the deduper and learn
        # blocking predicates
        gray('Training...')
        deduper.train()

        # When finished, save our training to disk
        gray('Saving results to training file...')
        with open(self.training_file, 'w+') as tf:
            deduper.writeTraining(tf)

        # Save our weights and predicates to disk.  If the settings file
        # exists, we will skip all the training and learning next time we run
        # this file.
        gray('Saving weights and predicates to settings file...')
        with open(self.settings_file, 'wb+') as sf:
            deduper.writeSettings(sf)

        return deduper

    def read_data(self, label, invalid=True):
        """
        Read data from RVD and return in the corresponding dedupe format,
        dictionary of records, where the key is a unique record ID and
        each value is dict.

        :return {}
        """
        data_d = {}
        gray("Processing tickets from RVD...")
        if invalid:
            issues_all = self.repo.get_issues(state="all")  # using all tickets, including invalid ones for training
        else:
            issues_all = self.get_issues_filtered(state="all")

        for issue in issues_all:
            print("Scanning..." + str(issue))

            # check for PRs and skip them, should be labeled with "contribution"
            labels = [l.name for l in issue.labels]
            if "contribution" in labels:
                gray("Found a PR, skipping it")
                continue

            # # This can't be enabled because if it was to be, training and
            # # evaluation will not match
            # if "duplicate" in labels:
            #     gray("Found duplicate, skipping it")
            #     continue

            # review labels
            all_labels = True  # indicates whether all labels are present
            if label:
                for l in label:
                    if l not in labels or "invalid" in labels:
                        all_labels = False

            if all_labels:
                # NOTE: partially re-implementing Base.import_issue()
                # to avoid calling again the Github API
                try:
                    document_raw = issue.body
                    document_raw = document_raw.replace('```yaml','').replace('```', '')
                    document = yaml.load(document_raw)

                    try:
                        flaw = Flaw(document)

                        # print(document)
                        # print(flaw)

                        # yellow("Imported issue ", end="")
                        # print(str(issue.id), end="")
                        # yellow(" into a Flaw...")
                        # data_d[int(issue.number)] = flaw.document_duplicates()
                        data_d[int(issue.number)] = flaw.document_duplicates()
                    except TypeError:
                        # likely the document wasn't properly formed, report about it and continue
                        yellow("Warning: issue " + str(issue.number) + " not processed due to an error")
                        continue

                except yaml.parser.ParserError:
                    print(f"{issue.number} is not has no correct yaml format")
                    continue
        return data_d

    def find_duplicates(self, train, push, label):
        """
        Find duplicates and print them via stdout
        """
        # data_d = self.read_data()
        data_d = self.read_data(label, invalid=False)
        # pprint.pprint(data_d)

        if train:
            deduper = self.train(data_d)
        else:
            if os.path.exists(self.settings_file):
                print('reading from', self.settings_file)
                with open(self.settings_file, 'rb') as f:
                    deduper = dedupe.StaticDedupe(f)
            else:
                red("Error: settings file does not exist, stoping")
                sys.exit(1)

        cyan("Finding the threshold for data...")
        threshold = deduper.threshold(data_d, recall_weight=1)

        cyan('Clustering...')
        clustered_dupes = deduper.match(data_d, threshold)

        cyan('Number of duplicate sets: ' + str(len(clustered_dupes)))
        for set in clustered_dupes:
            yellow("Found a duplicated pair...")
            ids, values = set
            primary_issue = None  # reflects the primary ticket in a set of
                                  # duplicates all the duplicates should point
                                  # to this one
            for id in ids:
                # print(id)
                issue = self.repo.get_issue(int(id))

                # if duplicate in issue, do nothing
                labels = [l.name for l in issue.labels]
                if "duplicate" in labels:
                    gray(str(id) + " already duplicate, skipping it")
                    continue

                # print(issue)
                if primary_issue is None:
                    primary_issue = issue
                else:
                    # Indicate that this issue is duplicated
                    yellow("Marking " + str(id) + " as duplicate, referencing to: " + str(primary_issue))
                    if push:
                        duplicate_text = "- <ins>DUPLICATE</ins>: Tagging this ticket as duplicate. Referencing to  #" + str(primary_issue.number) + "\n"
                        issue.create_comment(duplicate_text)
                        # labeling
                        issue.add_to_labels("duplicate")
                        issue.add_to_labels("triage")

    def is_duplicate(self, flaw):
        """
        Checks whether the flaw passes as parameter is a duplicate or not
        Uses training information already available in training data folder.

        NOTE: should be called from the RVD respository directory.

        :param flaw, Flaw
        :return bool
        """
        data_d = self.read_data(None, invalid=False)  # data dict
        # pprint.pprint(data_d)

        # Append the flaw to the data dictonary with the ID 0
        data_d[0] = flaw.document_duplicates()
        # pprint.pprint(data_d)

        if os.path.exists(self.settings_file):
            print('reading from', self.settings_file)
            with open(self.settings_file, 'rb') as f:
                deduper = dedupe.StaticDedupe(f)
        else:
            red("Error: settings file does not exist, stoping")
            sys.exit(1)

        cyan("Finding the threshold for data...")
        threshold = deduper.threshold(data_d, recall_weight=1)

        cyan('Clustering...')
        clustered_dupes = deduper.match(data_d, threshold)
        pprint.pprint(clustered_dupes)  # debug purposes

        # If ID 0 (corresponds with flaw passed as arg) is in there, is_duplicate
        for set in clustered_dupes:
            ids, values = set
            for id in ids:
                # print(id)
                if int(id) == 0:
                    return True
        return False
