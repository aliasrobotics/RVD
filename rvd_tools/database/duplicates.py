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
# import pprint


class Duplicates(Base):
    """
    Makes use of dedupe to manage flaw de-duplication
    """

    def __init__(self):
        super().__init__()
        # If a settings file already exists, we'll just load that and skip training
        # NOTE: settings file should be re-generated using the training() method
        self.settings_file = "training/csv_example_learned_settings"
        self.training_file = "training/csv_example_training.json"

        # Define the fields dedupe will pay attention to
        self.fields = [
            # {'field': 'title', 'type': 'String', 'crf': True},
            # {'field': 'title', 'type': 'String'},
            {"field": "type", "type": "String"},
            # {'field': 'cwe', 'type': 'String'},
            {"field": "description", "type": "String", "has missing": True},
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
            gray("Reading labeled examples from ", self.training_file)
            with open(self.training_file, "rb") as f:
                deduper.prepare_training(data_d, f)
        else:
            deduper.prepare_training(data_d)

        # ## Active learning
        # Dedupe will find the next pair of records
        # it is least certain about and ask you to label them as duplicates
        # or not.
        # use 'y', 'n' and 'u' keys to flag duplicates
        # press 'f' when you are finished
        gray("Starting active labeling...")
        dedupe.consoleLabel(deduper)

        # Using the examples we just labeled, train the deduper and learn
        # blocking predicates
        gray("Training...")
        deduper.train()

        # When finished, save our training to disk
        gray("Saving results to training file...")
        with open(self.training_file, "w+") as tf:
            deduper.writeTraining(tf)

        # Save our weights and predicates to disk.  If the settings file
        # exists, we will skip all the training and learning next time we run
        # this file.
        gray("Saving weights and predicates to settings file...")
        with open(self.settings_file, "wb+") as sf:
            deduper.writeSettings(sf)

        return deduper

    def dump_issues_local(self, issues, label, update=False):
        """
        Dump all tickets into a local directory, mimicing
        the 'rvd export local' functionality.

        TODO: document params
        """
        local_directory_path = ".rvd/"
        if not os.path.exists(local_directory_path):
            cyan("Creating directory .rvd/ whereto dump tickets...")
            os.makedirs(local_directory_path)
            update = True
        else:
            if update:
                cyan("Updating all tickets, re-downloading...")
                os.system("rm -r " + local_directory_path)
                os.makedirs(".rvd")
            else:
                yellow("Directory already exists, skipping")

        if update:
            importer = Base()
            # Fetch all issues, exluding the ones with the invalid label
            # NOTE: includes the ones with the duplicate label
            issues = importer.get_issues_filtered(state="all")
            # flaws = []  # a list whereto store all flaws, from the issues

            for issue in issues:
                # Filter by label, to further align with code below

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
                        document_raw = document_raw.replace("```yaml", "").replace(
                            "```", ""
                        )
                        document = yaml.load(document_raw)

                        try:
                            flaw = Flaw(document)
                            # flaws.append(flaw)  # append to list
                            # Dump into local storage
                            with open(
                                local_directory_path + str(flaw.id) + ".yml", "w+"
                            ) as file:
                                yellow("Creating file " + str(flaw.id) + ".yml")
                                # dump contents in file
                                result = yaml.dump(
                                    document,
                                    file,
                                    default_flow_style=False,
                                    sort_keys=False,
                                )

                        except TypeError:
                            # likely the document wasn't properly formed,
                            # report about it and continue
                            yellow(
                                "Warning: issue "
                                + str(issue.number)
                                + " \
not processed due to an error"
                            )
                            continue

                    except yaml.parser.ParserError:
                        red(f"{issue.number} is not has no correct yaml format")
                        continue

    def read_data(self, label, invalid=True):
        """
        Read data from RVD and return in the corresponding dedupe format,
        dictionary of records, where the key is a unique record ID and
        each value is dict.

        :return {}
        """
        data_d = {}
        gray("Processing tickets from RVD...")
        gray("Trying first to fetch them from the local dump...")

        local_directory_path = ".rvd/"
        if os.path.exists(local_directory_path):
            cyan("Found .rvd/ folder, fetching tickets...")
            flaws = []
            # need to fetch all tickets into flaws list
            for root, subdirs, files in os.walk(local_directory_path):
                for file in files:
                    relative_path = local_directory_path + file
                    with open(relative_path, "r") as file_doc:
                        document = yaml.load(file_doc, Loader=yaml.FullLoader)
                        # yellow(document)
                        try:
                            flaw = Flaw(document)
                            try:
                                # sanitize first some leftovers from yaml
                                int_id = int(str(flaw.id).replace(",", ""))
                                # add to the dict now
                                data_d[int_id] = flaw.document_duplicates()
                                # yellow("Fetched local " + relative_path + " ticket")
                            except TypeError:
                                # likely the document wasn't properly formed,
                                # report about it and continue
                                yellow(
                                    "Warning: issue "
                                    + str(flaw.id)
                                    + " \
not processed due to an error"
                                )
                                continue
                        except yaml.parser.ParserError:
                            red(f"{flaw.number} is not has no correct yaml format")
                            continue
        else:
            yellow("No local folder found, fetching from cloud")
            # Not found locally, import them manually
            if invalid:
                issues_all = self.repo.get_issues(state="all")  # using all
                # tickets, including invalid ones for training
            else:
                issues_all = self.get_issues_filtered(state="all")

            # Dump all tickets locally so that we don't need to re-download them
            # next time
            self.dump_issues_local(issues_all, label, update=False)  # set to false so
            # that only once
            # is downloaded
            for issue in issues_all:
                # print("Scanning..." + str(issue))

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
                        document_raw = document_raw.replace("```yaml", "").replace(
                            "```", ""
                        )
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
                            yellow(
                                "Warning: issue "
                                + str(issue.number)
                                + " not processed due to an error"
                            )
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
                print("reading from", self.settings_file)
                with open(self.settings_file, "rb") as f:
                    deduper = dedupe.StaticDedupe(f)
            else:
                red("Error: settings file does not exist, stoping")
                sys.exit(1)

        cyan("Finding the threshold for data...")
        threshold = deduper.threshold(data_d, recall_weight=1)

        cyan("Clustering...")
        clustered_dupes = deduper.match(data_d, threshold)

        cyan("Number of duplicate sets: " + str(len(clustered_dupes)))
        for aset in clustered_dupes:
            yellow("Found a duplicated pair...")
            ids, values = aset
            primary_issue = None  # reflects the primary ticket in a aset of
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
                    yellow(
                        "Marking "
                        + str(id)
                        + " as duplicate, referencing to: "
                        + str(primary_issue)
                    )
                    if push:
                        duplicate_text = (
                            "- <ins>DUPLICATE</ins>: Tagging this ticket as duplicate. Referencing to  #"
                            + str(primary_issue.number)
                            + "\n"
                        )
                        issue.create_comment(duplicate_text)
                        # labeling
                        issue.add_to_labels("duplicate")
                        issue.add_to_labels("triage")

    def is_duplicate(self, flaw):
        """
        Checks whether the flaw passed as parameter is a duplicate or not
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
            print("reading from", self.settings_file)
            with open(self.settings_file, "rb") as f:
                deduper = dedupe.StaticDedupe(f)
        else:
            red("Error: settings file does not exist, stoping")
            sys.exit(1)

        cyan("Finding the threshold for data...")
        threshold = deduper.threshold(data_d, recall_weight=1)

        cyan("Clustering...")
        clustered_dupes = deduper.match(data_d, threshold)
        # pprint.pprint(clustered_dupes)  # debug purposes

        #  If ID 0 (corresponds with flaw passed as arg) is in there, is_duplicate
        for set in clustered_dupes:
            ids, values = set
            for id in ids:
                # print(id)
                if int(id) == 0:
                    return True
        return False

    def get_duplicate(self, flaw):
        """
        Returns duplicates for a given flaw passed as parameter.

        Uses training information already available in training data folder.
        NOTE: should be called from the RVD respository directory.

        :param flaw, Flaw
        :return list
        """
        data_d = self.read_data(None, invalid=False)  # data dict
        # pprint.pprint(data_d)

        # Append the flaw to the data dictonary with the ID 0
        data_d[0] = flaw.document_duplicates()
        # pprint.pprint(data_d)

        if os.path.exists(self.settings_file):
            print("reading from", self.settings_file)
            with open(self.settings_file, "rb") as f:
                deduper = dedupe.StaticDedupe(f)
        else:
            red("Error: settings file does not exist, stoping")
            sys.exit(1)

        cyan("Finding the threshold for data...")
        threshold = deduper.threshold(data_d, recall_weight=1)

        cyan("Clustering...")
        clustered_dupes = deduper.match(data_d, threshold)
        # pprint.pprint(clustered_dupes)  # debug purposes

        #  If ID 0 (corresponds with flaw passed as arg) is in there, is_duplicate
        for set in clustered_dupes:
            ids, values = set
            if 0 in ids:
                return list(ids)
        return []
