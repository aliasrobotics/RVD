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
            {'field': 'title', 'type': 'String'},
            {'field': 'type', 'type': 'String'},
            {'field': 'cwe', 'type': 'String'},
            {'field': 'description', 'type': 'String', 'has missing': True},
            {'field': 'cve', 'type': 'String'},
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

    def read_data(self, invalid=True):
        """
        Read data from RVD and return in the corresponding dedupe format,
        dictionary of records, where the key is a unique record ID and
        each value is dict.

        :return {}
        """
        data_d = {}
        gray("Processing tickets from RVD...")
        if invalid:
            issues_all = self.repo.get_issues(state="open")  # using all tickets, including invalid ones for training
        else:
            issues_all = self.get_issues_filtered()
        for issue in issues_all:
            # NOTE: partially re-implementing Base.import_issue()
            # to avoid calling again the Github API
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
        return data_d

    def find_duplicates(self, train):
        """
        Find duplicates and print them via stdout
        """
        # data_d = self.read_data()
        data_d = self.read_data(invalid=False)

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
            for id in ids:
                # print(id)
                print(self.repo.get_issue(int(id)))
