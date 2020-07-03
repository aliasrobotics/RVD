# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Entry point for the rvd CLI tool.
"""

import click
import yaml
from cerberus import Validator
from .utils import red, cyan, green, yellow, inline_magenta, inline_gray, inline_green
from .database.schema import *
from .database.defaults import *
from .database.flaw import *
from .database.summary import *
from .database.duplicates import *
from .database.vulners import *
from .database.edit import *

# from .database.coercer import *
from .importer.robust import *
from .importer.markdown import *
from .importer.gitlab import *
from .cve.cve import *
from .statistics.statistics import *
from .reports.reports import *
import sys
import json
import os
import subprocess
import pprint
from datetime import datetime
import arrow
from arrow.parser import ParserError
from tabulate import tabulate
import qprompt
import ast

#  ┌┬┐┌─┐┬┌┐┌
#  │││├─┤││││
#  ┴ ┴┴ ┴┴┘└┘
# http://patorjk.com/software/taag/#p=display&c=bash&f=Calvin%20S&t=main
@click.group()
def main():
    """Robot Vulnerability Database (RVD) command line tooling"""
    cyan(
        "Starting rvd, the CLI tool for managing the Robot \
Vulnerability Database..."
    )


#  ┬  ┬┌─┐┌┬┐
#  │  │└─┐ │
#  ┴─┘┴└─┘ ┴
@main.command("list")
@click.argument("id", required=False)
@click.option(
    "--dump/--no-dump", help="Print the tickets.", default=False,
)
@click.option(
    "--private/--no-private", help="Print private RVD tickets.", default=False,
)
@click.option(
    "--onlyprivate/--no-onlyprivate",
    help="Print only private RVD tickets.",
    default=False,
)
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--isoption", help="Filter flaws by status (open, closed, all).", default="open"
)
@click.option(
    "--markdown/--no-markdown",
    help="Only valid for individual \
ticket. Print ticket in Markdown format.",
    default=False,
)
@click.option(
    "--fromdate",
    help="Filter flaws by date, until today.\
Use YYYY-MM-DD format.",
    multiple=False,
)
def listar(id, dump, private, onlyprivate, label, isoption, markdown, fromdate):
    """List current flaw tickets"""
    importer = Base()

    if id:  # which is the same as the issue number
        if private:
            importer_private = GitlabImporter()
            flaw, labels = importer_private.get_flaw(id)
            print(flaw)
            # cyan("Importing from RVD private, issue: " + str(flaw))
        else:
            # Get the issue
            # TODO: abstract this piece of code and return a flaw directly
            issue = importer.repo.get_issue(int(id))
            cyan("Importing from RVD, issue: " + str(issue))
            document_raw = issue.body
            document_raw = document_raw.replace("```yaml", "").replace("```", "")
            try:
                document = yaml.load(document_raw, Loader=yaml.FullLoader)
                # print(document)
                flaw = Flaw(document)
                if markdown:
                    print(flaw.markdown())
                else:
                    print(flaw)
            except yaml.scanner.ScannerError as e:
                print("Not in yaml format please review")
                print(e)

    else:
        # table = [[issue.number, issue.title] for issue in issues_public]
        # table = importer.get_table(label, isoption)

        # Refer to https://python-gitlab.readthedocs.io/en/stable/cli.html
        #  for configuration of the python-gitlab API. RVD assumes that the
        #  file ~/.python-gitlab.cfg exists
        if onlyprivate:
            cyan("Listing private flaws in ", end="")
            yellow("yellow", end="")
            cyan("...")
            importer_private = GitlabImporter()
            table_private = importer_private.get_table(label)
            yellow(tabulate(table_private))
        elif private:
            cyan("Listing all open flaws from RVD...")
            cyan("Listing private flaws in ", end="")
            yellow("yellow", end="")
            cyan("...")
            importer_private = GitlabImporter()
            table_private = importer_private.get_table(label)
            table = importer.get_table(label, isoption)
            print(tabulate(table, headers=["ID", "Title"]))
            yellow(tabulate(table_private))
        elif fromdate:
            # Get the data from where to filter
            # raw_date, = fromdate  # get the first element of the tuple
            date_filter = arrow.get(fromdate)

            issues_all = importer.get_issues_filtered()
            flaws_date_filtered = []  # filtered flaws by date
            for issue in issues_all:
                #  Filter now by label/s
                all_labels = True  # indicates whether all labels are present
                if label:
                    labels_issue = [l.name for l in issue.labels]
                    for l in label:
                        if l not in labels_issue or "invalid" in labels_issue:
                            all_labels = False
                            break
                    if not all_labels:
                        continue  # jump issue

                # Build flaw
                document_raw = issue.body
                document_raw = document_raw.replace("```yaml", "").replace("```", "")
                document = yaml.load(document_raw, Loader=yaml.FullLoader)
                flaw = Flaw(document)

                date_formats = [
                    "ddd, DD MMM YYYY HH:mm:ss Z",
                    "YYYY-MM-DD",
                    "YYY-MM-DD (HH:mm)",
                ]
                try:
                    date_flaw_detected = None
                    if flaw.date_detected:
                        date_flaw_detected = arrow.get(flaw.date_detected, date_formats)
                except ParserError as e:
                    red("Error while parsing date-detected of flaw " + str(flaw.id))
                    print(e)
                    date_flaw_detected = None

                # if date_flaw_detected:
                #     print(str(flaw.date_detected) + " -> " + date_flaw_detected.format())  # Debug

                try:
                    date_flaw_reported = None
                    if flaw.date_reported:
                        date_flaw_reported = arrow.get(flaw.date_reported, date_formats)
                except ParserError as e:
                    red("Error while parsing date-reported of flaw " + str(flaw.id))
                    print(e)
                    date_flaw_reported = None

                # if date_flaw_reported:
                #     print(str(flaw.date_reported) + " -> " + date_flaw_reported.format())  # Debug

                # # Debug
                # print("ID: " + str(flaw.id) + ", comparing:")
                # if date_filter and date_flaw_reported:
                #     print("\t - (date_flaw_reported) " + \
                #         date_filter.format() + "(" + date_filter.humanize() + \
                #         ") with " + date_flaw_reported.format() + \
                #         "(" + date_flaw_reported.humanize() + "): " + \
                #         inline_green(date_flaw_reported >= date_filter) if date_flaw_reported >= date_filter
                #             else inline_magenta(date_flaw_reported >= date_filter)
                #         )
                #
                # if date_filter and date_flaw_detected:
                #     print("\t - (date_flaw_detected) " + \
                #         date_filter.format() + "(" + date_filter.humanize() + \
                #         ") with " + date_flaw_detected.format() + \
                #         "(" + date_flaw_detected.humanize() + "): " + \
                #         inline_green(date_flaw_detected >= date_filter) if date_flaw_detected >= date_filter
                #             else inline_magenta(date_flaw_detected >= date_filter)
                #         )

                # Compare flaw date with date_filter
                if not (date_flaw_reported or date_flaw_detected):
                    yellow(
                        "Neither date-reported nor date-detected have been understood, skipping flaw "
                        + str(flaw.id)
                    )
                    continue

                if date_flaw_reported:
                    if date_flaw_reported >= date_filter:
                        flaws_date_filtered.append(flaw)
                        continue
                if date_flaw_detected:
                    if date_flaw_detected >= date_filter:
                        flaws_date_filtered.append(flaw)

            # print(flaws_date_filtered)  # Debug

            # Build a mardown table and dump it in stdout
            markdown_table = ""
            markdown_table += "| ID | Type | Title |" + "\n"
            markdown_table += "|----|------|-------|" + "\n"
            for flaw in flaws_date_filtered:
                markdown_table += (
                    "| [RVD#"
                    + str(flaw.id)
                    + "]("
                    + str(flaw.issue)
                    + ") | "
                    + str(flaw.type)
                    + " | "
                    + str(flaw.title)
                    + "|"
                    + "\n"
                )

            print(markdown_table)

        else:
            cyan("Listing all open flaws from RVD...")
            table = importer.get_table(label, isoption)
            print(tabulate(table, headers=["ID", "Title"]))

        if dump:
            issues = importer.import_issues_labels(label, isoption)
            for issue in issues:
                cyan("Importing from RVD, issue: " + str(issue))
                document_raw = issue.body
                document_raw = document_raw.replace("```yaml", "").replace("```", "")
                document = yaml.load(document_raw, Loader=yaml.FullLoader)
                flaw = Flaw(document)
                print(flaw)


#  ┬─┐┌─┐┌─┐┌─┐┬─┐┌┬┐
#  ├┬┘├┤ ├─┘│ │├┬┘ │
#  ┴└─└─┘┴  └─┘┴└─ ┴
@main.command("report")
@click.argument("id", required=True, nargs=-1)
@click.option(
    "--deadline", help="Deadline in days. Single number, e.g. 30.", multiple=False
)
@click.option(
    "--disclose/--no-disclose",
    help="Disclose exploitation \
and mitigation information.",
    default=False,
)
def report(id, deadline, disclose):
    """
    Generates a PDF report for the given ID under /tmp/rvd/reports/
    """
    for i in id:
        cyan("Generating a PDF report for ID: ", end="")
        print(i, end="")
        cyan(" ...")
        report = Report()
        report.from_gitlab(i, deadline, disclose)
    # TODO make the reports and pack them together for delivery
    # consider something like:
    #  for d in ./* ; do ( cd "$d" && make); done


#  ┌─┐┌┬┐┌─┐┌┬┐┬┌─┐┌┬┐┬┌─┐┌─┐
#  └─┐ │ ├─┤ │ │└─┐ │ ││  └─┐
#  └─┘ ┴ ┴ ┴ ┴ ┴└─┘ ┴ ┴└─┘└─┘
@main.group("statistics")
def statistics():
    """
    Produce some statistics and plots from RVD
    """
    cyan("Generating statistics...")


@statistics.command("general")
@click.option("--label", help="Filter flaws by label.", multiple=True)
def statistics_general(label):
    """
    Creates a table with some general information per flaw
    """
    statistics = Statistics()
    statistics.statistics_vulnerabilities_historic(label)


#  UNFINISHED
@statistics.command("scoring_comparison")
@click.option("--label", help="Filter flaws by label.", multiple=True)
def statistics_scoring(label):
    """
    Compares CVSS and RVSS for selected tickets
    """
    statistics = Statistics()
    statistics.cvss_vs_rvss(label)


#  UNFINISHED
@statistics.command("public_private")
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--nolabel",
    help="Filter flaws by those who which do not\
 include label.",
    multiple=True,
)
def statistics_public_private(label, nolabel):
    """
    Plots public vs private flaws given a set of filters through labels
    """
    statistics = Statistics()
    statistics.public_private(label, nolabel)


@statistics.command("zero")
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--nolabel",
    help="Filter flaws by those who which do not\
 include label.",
    multiple=True,
)
def statistics_zero_vs_mitigated(label, nolabel):
    """
    Plots 0-days vs mitigated flaws, among the filtered ones
    """
    statistics = Statistics()
    statistics.zero_vs_mitigated(label, nolabel)


@statistics.command("cwe")
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--nolabel",
    help="Filter flaws by those who which do not\
 include label.",
    multiple=True,
)
def statistics_cwe(label, nolabel):
    """
    Plots flaw CWEs grouped by value among the filtered ones
    """
    statistics = Statistics()
    statistics.cwe(label, nolabel)


@statistics.command("mitigation_timing")
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--nolabel",
    help="Filter flaws by those who which do not\
 include label.",
    multiple=True,
)
def statistics_mitigation_timing(label, nolabel):
    """
    Creates a plot showing the time to mitigation for the selected tickets.

    If no mitigation date is provided (or if it's ""), it's assumed it's not
    mitigated just yet.
    """
    statistics = Statistics()
    statistics.mitigation_timing(label, nolabel)


@statistics.command("distribution")
@click.option("--label", help="Filter flaws by label.", multiple=True)
def statistics_distribution(label):
    """ An averaged scoring distribution per vendor"""
    statistics = Statistics()
    statistics.cvss_score_distribution(label)


@statistics.command("vendor_vulnerabilities")
@click.option("--label", help="Filter flaws by label.", multiple=True)
def statistics_vendor_vulnerabilities(label):
    """ # Vulnerabilities per vendor"""
    statistics = Statistics()
    statistics.vendor_vulnerabilities(label)


#  ┌─┐┌┬┐┬┌┬┐
#  ├┤  │││ │
#  └─┘─┴┘┴ ┴
@main.command("edit")
@click.argument("id", required=False)
@click.option(
    "--subsequent/--no-subsequent", help="Continue editing subsequently.", default=True,
)
@click.option("--label", help="Filter flaws by label.", multiple=True)
def edit(id, subsequent, label):
    """
    Edits selected (and iteratively all subsequent) tickets within the database
    """
    edit_function(id, subsequent, label)


#  ┌┬┐┬ ┬┌─┐┬  ┬┌─┐┌─┐┌┬┐┌─┐┌─┐
#   │││ │├─┘│  ││  ├─┤ │ ├┤ └─┐
#  ─┴┘└─┘┴  ┴─┘┴└─┘┴ ┴ ┴ └─┘└─┘
@main.command("duplicates")
@click.option(
    "--train/--no-train", help="Train the classifiers.", default=False,
)
@click.option(
    "--push/--no-push", help="Push feedback.", default=False,
)
@click.option("--label", help="Filter flaws by label.", multiple=True)
@click.option(
    "--test/--no-test", help="Test that validation works.", default=False,
)
def duplicates(train, push, label, test):
    """
    Searches and tags appropriately duplicates in the database
    Make use of dedupe library for it.

    NOTE: operates only over "open" issues.
    """
    cyan("Searching for duplicates...")
    duplicates = Duplicates()
    if test:
        # Fetch a given ticket and check for duplicates in the db
        importer = Base()
        issue = importer.repo.get_issue(int(999))  #  use existing flaw
        document_raw = issue.body
        document_raw = document_raw.replace("```yaml", "").replace("```", "")
        document = yaml.load(document_raw, Loader=yaml.FullLoader)
        # document = default_document()  # get the default document
        flaw = Flaw(document)
        print(duplicates.is_duplicate(flaw))
    else:
        duplicates.find_duplicates(train, push, label)


#  ┬  ┬┬ ┬┬  ┌┐┌┌─┐┬─┐┌─┐
#  └┐┌┘│ ││  │││├┤ ├┬┘└─┐
#   └┘ └─┘┴─┘┘└┘└─┘┴└─└─┘
# @main.command("vulners")
@main.group("vulners")
def vulners():
    """
    Makes use of Vulners' database.

    See https://github.com/vulnersCom/api#functions-and-methods
    for more.
    """
    cyan("Using vulners database...")


@vulners.command("cve")
@click.argument("query", required=True)
@click.option(
    "--push/--no-push", help="Push feedback.", default=False,
)
def cve_vulners(query, push):
    vulners = Vulners()
    vulners.cve(query, push)


@vulners.command("search")
@click.argument("query", required=True)
@click.option(
    "--push/--no-push", help="Push feedback.", default=False,
)
def search_vulners(query, push):
    vulners = Vulners()
    vulners.search(query, push)


#  ┌─┐┬  ┬┌─┐
#  │  └┐┌┘├┤
#  └─┘ └┘ └─┘
# @main.group()
@main.group("cve")
def cve():
    """
    Makes use of Vulners' database.

    See https://github.com/vulnersCom/api#functions-and-methods
    for more.
    """
    cyan("Using CVE tools...")


@click.argument("number", required=True)
@click.option("--version", default=4, help="Version of CVE JSON.")
@click.option("--mode", default="public", help="Mode for the disclosure of CVE JSON.")
@click.option(
    "--private/--no-private",
    default=False,
    help="Private RVD or public RVD, defaults to False which implies public.",
)
@click.option(
    "--dump/--no-dump", default=False, help="Print resulting file.",
)
@click.option(
    "--push/--no-push", default=False, help="Push to a branch.",
)
@click.option(
    "--useexisting/--no-useexisting",
    default=False,
    help="Use existing CVE in ticket, instead of assigning new one.",
)
@cve.command("export")
def cve_export(number, version, mode, private, dump, push, useexisting):
    """
    Export an RVD ticket to CVE JSON
    """
    cyan("Exporting an RVD ticket into CVE JSON format...")
    cve_export_file(number, version, mode, private, dump, push, useexisting)


@click.option("--version", default=4, help="Version of CVE JSON.")
@click.option("--file", help="JSON file to validate.")
@cve.command("validate")
def cve_validate(version, file):
    """
    Validate a CVE JSON file

    Examples:
        cve validate --file /Users/alias/Downloads/CVE-2020-10264.json
    """
    cyan("Validating a CVE JSON file...")
    if file:
        cve_jsonvalidation(file, version)
    else:
        red("Error, file required")
        sys.exit(1)


@click.option(
    "--all/--no-all",
    default=False,
    help="Automatically import all flaws for a given vendor.",
)
@click.option("--vendor", default=None, help="Vendor to research.")
@click.option("--product", default=None, help="Product to research.")
@click.option("--push/--no-push", default=False, help="Push to RVD in a new ticket.")
@cve.command("search")
def cve_search(all, vendor, product, push):
    """
    Search CVEs and CPEs from cve-search enabled DB, import them.

    Search in CVE (Common Vulnerabilities and Exposures) and
    CPE (Common Platform Enumeration)and import them to RVD.

    Makes use of the following:
    - https://github.com/cve-search/PyCVESearch
    - (indirectly) https://github.com/cve-search/cve-search
    """
    # cve = CVESearch()
    cyan("Searching for CVEs and CPEs with cve-search ...")
    from pycvesearch import CVESearch

    if all:
        if vendor:
            cve = CVESearch()
            vendor_flaws = cve.browse(vendor)
            products = vendor_flaws["product"]
            for product in products:
                results = cve.search(vendor + "/" + product)
                # Start producing flaws in here
                for result in results["results"]:
                    # pprint.pprint(result)
                    document = default_document()  # get the default document
                    # Add relevant elements to the document
                    document["title"] = result["summary"][:65]
                    document["type"] = "vulnerability"
                    document["description"] = result["summary"]
                    document["cve"] = result["id"]
                    document["cwe"] = result["cwe"]
                    document["severity"]["cvss-vector"] = "CVSS:3.0/" + str(
                        result["cvss-vector"]
                    )
                    document["severity"]["cvss-score"] = result["cvss"]
                    document["links"] = result["references"]
                    document["flaw"]["reported-by"] = result["assigner"]
                    document["flaw"]["date-reported"] = arrow.get(
                        result["Published"]
                    ).format("YYYY-MM-DD")

                    # Create a flaw out of the document
                    flaw = Flaw(document)
                    # new_flaw = edit_function(0, subsequent=False, flaw=flaw)
                    new_flaw = flaw

                    if new_flaw:
                        print(new_flaw)
                    else:
                        continue

                    if push:
                        pusher = Base()  # instantiate the class to push changes
                        labels = ["vulnerability"]
                        vendor_label = "vendor: " + str(vendor)
                        labels.append(vendor_label)
                        # new_keywords = ast.literal_eval(new_flaw.keywords)
                        # for l in new_keywords:
                        #     labels.append(l)

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
                        pusher.update_ticket(issue, new_flaw)

        else:
            red("Error, vendor is required with --all")
            sys.exit(1)
        return

    if vendor and product:
        cve = CVESearch()
        cyan("Searching for vendor/product: ", end="")
        print(vendor + "/" + product)
        results = cve.search(vendor + "/" + product)
        # Start producing flaws in here
        for result in results["results"]:
            # pprint.pprint(result)
            document = default_document()  # get the default document
            # Add relevant elements to the document
            document["title"] = result["summary"][:65]
            document["description"] = result["summary"]
            document["cve"] = result["id"]
            document["cwe"] = result["cwe"]
            document["severity"]["cvss-vector"] = "CVSS:3.0/" + str(
                result["cvss-vector"]
            )
            document["severity"]["cvss-score"] = result["cvss"]
            document["links"] = result["references"]
            document["flaw"]["reported-by"] = result["assigner"]
            document["flaw"]["date-reported"] = arrow.get(result["Published"]).format(
                "YYYY-MM-DD"
            )

            # Create a flaw out of the document
            flaw = Flaw(document)
            new_flaw = edit_function(0, subsequent=False, label=None, flaw=flaw)

            if new_flaw:
                print(new_flaw)
            else:
                continue

            if push:
                pusher = Base()  # instantiate the class to push changes
                labels = ["vulnerability"]
                new_keywords = ast.literal_eval(new_flaw.keywords)
                for l in new_keywords:
                    labels.append(l)

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
                pusher.update_ticket(issue, new_flaw)

    elif vendor:
        cve = CVESearch()
        cyan("Browsing for vendor: ", end="")
        print(vendor)
        pprint.pprint(cve.browse(vendor))
    elif product:
        red("Error, vendor is required")
        sys.exit(1)
    else:
        red("Error, vendor or vendor and product required")
        sys.exit(1)


# @cve.command("browse")
# @click.argument('vendor')
# def browse(vendor):
#     from pycvesearch import CVESearch
#     cve = CVESearch()
#     cyan("Browsing for vendor: ", end="")
#     print(vendor)
#     pprint.pprint(cve.browse(vendor))
#
#
# @cve.command("search")
# @click.argument('vendor')
# @click.argument('product')
# def search(vendor, product):
#     from pycvesearch import CVESearch
#     cve = CVESearch()
#     cyan("Searching for vendor/product: ", end="")
#     print(vendor+"/"+product)
#     pprint.pprint(cve.search(vendor+"/"+product))


#  ┬  ┬┌─┐┬  ┬┌┬┐┌─┐┌┬┐┌─┐
#  └┐┌┘├─┤│  │ ││├─┤ │ ├┤
#   └┘ ┴ ┴┴─┘┴─┴┘┴ ┴ ┴ └─┘
@main.command("validate")
@click.argument("filename", type=click.Path(exists=True))
@click.option(
    "--dump/--no-dump", help="Print resulting document at the end.", default=False,
)
def validation(filename, dump):
    """Validate the file provided its path"""
    validate_file(filename, dump)


def validate_file(filename, dump=False):
    """
    Auxiliary function, validate file

    :return dict representing the YAML document. NOTE that the
    returned dict hasn't removed any 'additional' key from the original
    file.
    """
    validated = False  # reflect whether the overall process suceeded
    cyan("Validating " + str(filename) + "...")
    doc = None
    try:
        with open(click.format_filename(filename), "r") as stream:
            try:
                doc = yaml.load(stream, Loader=yaml.FullLoader)
            except yaml.YAMLError as exception:
                raise exception
    except FileNotFoundError:
        red("File " + str(filename) + " not found")

    v = Validator(SCHEMA, allow_unknown=True)  # allow unknown values
    if doc:
        # print(MyNormalizer().normalized(doc, SCHEMA))
        if not v.validate(doc, SCHEMA):
            # print(v.errors)
            for key in v.errors.keys():
                print("\t" + str(key) + ": ", end="")
                red("not valid", end="")
                print(": " + str(v.errors[key]))
        else:
            # print(v.validated(doc))
            # valid_documents = [x for x in v.validated(doc)]
            # for document in valid_documents:
            #     print("\t" + str(document) + ": ", end='')
            #     green("valid")
            green("Validated successfully!")
            validated = True
    # else:
    #     red("file to validate not processed correctly!")

    if dump:
        # print(json.dumps(v.document, indent=4, default=default))
        # print(yaml.dump(v.document))  # reorder
        print(
            yaml.dump(v.document(), default_flow_style=False, sort_keys=False)
        )  # maintain order

        # flaw = Flaw(v.document)
        # print the final document after validations and normalizations
        # print(flaw)
        # print(flaw.yml())
    return validated, v.document


#  ┌─┐┬ ┬┌┬┐┌┬┐┌─┐┬─┐┬ ┬
#  └─┐│ │││││││├─┤├┬┘└┬┘
#  └─┘└─┘┴ ┴┴ ┴┴ ┴┴└─ ┴
@main.command("summary")
@click.option(
    "--update/--no-update", help="Update the repo's README'nd file.", default=False,
)
def summary(update):
    """Produce a Markdown summary output of RVD"""
    cyan("Summarizing RVD's content...")
    summary = Summary()
    print(summary.generate_readme())  # only debug
    if update:
        summary.replace_readme()


#  ┌─┐┌┬┐┬ ┬┌─┐┬─┐
#  │ │ │ ├─┤├┤ ├┬┘
#  └─┘ ┴ ┴ ┴└─┘┴└─
@main.command("other")
@click.option(
    "--title/--no-title",
    help="Update each ticket's title and ensure it starts with \
              RVD#number",
    default=False,
)
def other(title):
    """Manage 'other' topics. See options for more."""
    cyan("Other actions for RVD...")
    importer = Base()
    if title:
        # Fetch all tickets, iterate over them and update each with a
        #  title that includes RVD#<ticket-number>
        issues_all = importer.get_issues_filtered()
        for issue in issues_all:
            # Get the flaw that corresponds with the issue
            flaw = importer.import_issue(0, issue, debug=False)
            if flaw.title[:4] != "RVD#":  # already has the syntax
                new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                flaw.title = new_title
                if flaw.title[:4] != "RVD#":  # already has the syntax
                    new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                    flaw.title = new_title
                importer.update_ticket(issue, flaw)  # labels fetched from issue


#  ┌─┐─┐ ┬┌─┐┌─┐┬─┐┌┬┐
#  ├┤ ┌┴┬┘├─┘│ │├┬┘ │
#  └─┘┴ └─┴  └─┘┴└─ ┴
@main.group("export")
def exportar():
    """Export flaws from RVD to a variety of sources"""
    cyan("Exporting...")


@exportar.command("local")
@click.option(
    "--update/--no-update",
    help='Force the download of all tickets again".',
    default=False,
)
def exportar_local(update):
    """Export all tickets to the local export directory"""

    local_directory_path = ".rvd/"
    cyan("Creating folder for the export process...")
    flag_fetch = False  # a flag to determine whether all tickets need to
    # be fetched again
    if not os.path.exists(local_directory_path):
        os.makedirs(local_directory_path)
        flag_fetch = True
    else:
        if update:
            cyan("Updating all tickets, re-downloading...")
            os.system("rm -r " + local_directory_path)
            os.makedirs(".rvd")
            flag_fetch = True
        else:
            red("Directory already exists, skipping")

    if flag_fetch:
        importer = Base()
        # Fetch all issues, exluding the ones with the invalid label
        # NOTE: includes the ones with the duplicate label
        issues = importer.get_issues_filtered(state="all")
        flaws = []  # a list whereto store all flaws, from the issues

        for issue in issues:
            # NOTE: partially re-implementing Base.import_issue()
            # to avoid calling again the Github API
            try:
                document_raw = issue.body
                document_raw = document_raw.replace("```yaml", "").replace("```", "")
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
                        # result = yaml.dump(document, file)
                        result = yaml.dump(
                            document, file, default_flow_style=False, sort_keys=False
                        )

                except TypeError:
                    # likely the document wasn't properly formed, report about it and continue
                    yellow(
                        "Warning: issue "
                        + str(issue.number)
                        + " not processed due to an error"
                    )
                    continue

            except yaml.parser.ParserError:
                red(f"{issue.number} is not has no correct yaml format")
                continue


#  ┬┌┬┐┌─┐┌─┐┬─┐┌┬┐
#  ││││├─┘│ │├┬┘ │
#  ┴┴ ┴┴  └─┘┴└─ ┴
@main.group("import")
def fetch():
    """Import flaws to RVD from a variety of sources"""
    cyan("Importing...")
    # if not uri:
    #     red("A URI is needed when calling import")
    #     sys.exit(1)
    # else:
    cyan("Creating the default folder for the import process...")
    os.system("mkdir -p /tmp/rvd")


@fetch.command("local")
@click.argument("id", required=True)
def fetch_local(id):
    """Import a given ticket id from the local export directory
    and dump its contents in stdout"""

    local_directory_path = ".rvd/"
    cyan("Trying to import " + id + " from local export directory...")
    for root, subdirs, files in os.walk(local_directory_path):
        for file in files:
            file_name = id + ".yml"
            if file_name == file:
                relative_path = local_directory_path + file
                with open(relative_path, "r") as file_doc:
                    document = yaml.load(file_doc, Loader=yaml.FullLoader)
                    # yellow(document)
                    print(Flaw(document))


@fetch.command("gitlab")
@click.argument("id", required=True)
@click.option(
    "--push/--no-push", help="Push imported flaws to RVD.", default=False,
)
@click.option(
    "--all/--no-all",
    help='Import all issues from repository. USED in "overwrite_issue".',
    default=False,
)
@click.option(
    "--dump/--no-dump", help="Print in stdout results.", default=False,
)
@click.option(
    "--disclose/--no-disclose",
    help='Disclose sensitive aspects of the ticket".',
    default=False,
)
@click.option(
    "--update", help='Update previously (fully) undisclosed ticket".',
)
def fetch_gitlab(id, push, all, dump, disclose, update):
    """
    Import ticket from private gitlab feed
    """
    if all:
        # simply push all the tickets that have the "ready" label
        # importer_private = GitlabImporter()
        # importer_private.get_ready_flaws(labels)  # TODO, add labels argument
        raise NotImplementedError
    else:
        cyan("Importing from private gitlab feed...")
        importer_private = GitlabImporter()
        flaw, labels = importer_private.get_flaw(id, True)

        # Define disclosure date
        flaw.date_reported = arrow.utcnow().format("YYYY-MM-DD")

        if not disclose:
            # Remove sensitive information from the ticket
            flaw.trace = "Not disclosed"
            flaw.reproduction = "Not disclosed"
            flaw.reproduction_image = "Not disclosed"
            flaw.description_exploitation = "Not disclosed"
            flaw.exploitation_image = "Not disclosed"
            flaw.exploitation_vector = "Not disclosed"
            flaw.description_mitigation = "Not disclosed"
            flaw.pull_request = "Not disclosed"

        print(flaw)
        # print(labels)

        if push:
            cyan("Pushing results to RVD...")
            pusher = Base()
            issue = pusher.new_ticket(flaw, labels)
            # Update id
            flaw.id = issue.number
            # Update issue and links
            if isinstance(flaw.links, list):
                links = flaw.links
            else:
                links = []
                if flaw.links.strip() != "":
                    links.append(flaw.links.strip())
            links.append(issue.html_url)
            flaw.links = links
            flaw.issue = issue.html_url
            if flaw.title[:4] != "RVD#":  # already has the syntax
                new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                flaw.title = new_title
            pusher.update_ticket(issue, flaw)

        if update:
            importer = Base()
            issue = importer.repo.get_issue(int(update))
            flaw.issue = issue.html_url  # this bit is not in the gitlab ticket
            flaw.id = issue.number  # Update id
            if flaw.title[:4] != "RVD#":  # already has the syntax
                new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                flaw.title = new_title
            importer.update_ticket(issue, flaw)  # labels fetched from issue


@fetch.command("robust")
@click.argument("filename", required=False)
@click.option(
    "--push/--no-push", help="Push imported flaws to RVD.", default=False,
)
@click.option(
    "--all/--no-all",
    help='Import all issues from repository. USED in "overwrite_issue".',
    default=False,
)
@click.option(
    "--dump/--no-dump", help="Print in stdout results.", default=False,
)
def fetch_robust(filename, push, all, dump):
    """
    Import tickets from robust project
    """
    importer = RobustImporter()
    cyan("Cloning robust project...")
    os.system(
        "cd /tmp/rvd && git clone\
               https://github.com/robust-rosin/robust"
    )
    # os.system("du -a /tmp/rvd/robust | grep\
    #           '\.bug$' | awk '{print $2}'")
    stdoutdata = subprocess.getoutput(
        "\
        du -a /tmp/rvd/robust | grep '\.bug$' | awk '{print $2}'"
    )
    bugfiles = stdoutdata.split("\n")
    for bug in bugfiles:
        # normalize and validate the content of the bug
        validation, document_validated = validate_file(bug)

        # drop 'bugzoo' key
        if "bugzoo" in document_validated.keys():
            yellow("Dropping bugzoo key")
            document_validated.pop("bugzoo")
        # drop 'time-machine' key
        if "time-machine" in document_validated.keys():
            yellow("Dropping time-machine key")
            document_validated.pop("time-machine")

        # Make some adjustments, manually
        document_validated["flaw"]["date-reported"] = str(
            document_validated["flaw"]["time-reported"]
        )
        document_validated["cwe"] = document_validated["classification"]

        flaw = Flaw(document_validated)
        # add relevant keys to flaw using add_field method
        for key in document_validated["mitigation"].keys():
            yellow(
                "Adding to flaw ['mitigation']['"
                + str(key)
                + "'] = "
                + str(document_validated["mitigation"][key])
            )
            flaw.add_field(
                value=document_validated["mitigation"][key], key="mitigation", key2=key
            )

        if dump:
            print(flaw)
            # print(flaw.yml())

        cyan("Validate again after processing...")
        # validate the resulting document
        flaw.validate()

        if push:
            cyan("Pushing results to RVD...")
            pusher = Base()
            labels = ["quality"]
            if flaw.vendor:
                if flaw.vendor != "N/A":
                    labels.append(flaw.vendor)
            labels.append(flaw.type)
            if flaw.system == "universal_robot":
                flaw.vendor = "Universal Robots"
                labels.append("vendor: Universal Robots")
            else:
                labels.append(flaw.system)
            labels.append("mitigated")
            labels.append("robust")
            issue = pusher.new_ticket(flaw, labels)
            # Update id
            flaw.id = issue.number

            # Update issue and links
            if isinstance(flaw.links, list):
                links = flaw.links
            else:
                links = []
                if flaw.links.strip() != "":
                    links.append(flaw.links.strip())
            links.append(issue.html_url)
            flaw.links = links
            flaw.issue = issue.html_url
            if flaw.title[:4] != "RVD#":  # already has the syntax
                new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                flaw.title = new_title
            pusher.update_ticket(issue, flaw)


# @fetch.command("issue")
# @click.argument('filename', required=False)
# @click.option('--push/--no-push',
#               help='Push imported flaws to RVD.', default=False,)
# @click.option('--all/--no-all',
#               help='Import all issues from repository. USED in "overwrite_issue".',
#               default=False,)
# @click.option('--dump/--no-dump',
#               help='Print in stdout results.', default=False,)
# def fetch_issue(filename, push, all, dump):
#     """
#     Import from
#     """
#     url = filename
#     if not url:
#         red("URL not provided")
#         sys.exit(1)
#     else:
#         processed_url = url.split("/")
#
#         repo = processed_url[-3]
#         user = processed_url[-4]
#         issue_number = int(processed_url[-1])
#
#         # Get the issue
#         importer = Base(username=user, repo=repo)
#         flaw = importer.import_issue(issue_number)
#         raise NotImplementedError


@fetch.command("overwrite")
@click.argument("filename", required=False)
@click.option(
    "--push/--no-push", help="Push imported flaws to RVD.", default=False,
)
@click.option(
    "--all/--no-all",
    help='Import all issues from repository. USED in "overwrite_issue".',
    default=False,
)
@click.option(
    "--dump/--no-dump", help="Print in stdout results.", default=False,
)
def fetch_overwrite(filename, push, all, dump):
    """
    Overwrite a series of Github tickets with new content.

    rvd import overwrite <URL>: imports from RVD's OLD format issues
    and overwrite them with the new format. If --all flag is used, applies
    changes to all the tickets.

    """
    # use filename as URL
    url = filename
    if not url:
        red("URL not provided")
        sys.exit(1)
    else:
        processed_url = url.split("/")

        repo = processed_url[-3]
        user = processed_url[-4]
        importer = MarkdownImporter(user, repo)

        issues = None  # put together the issues we should go through
        if all:
            issues = importer.repo.get_issues(state="open")
        else:
            issue_number = int(processed_url[-1])
            issues = [importer.repo.get_issue(issue_number)]

        for issue in issues:
            cyan("Importing from RVD, issue: " + str(issue))
            # parse issue's body
            importer.parse(issue.body)
            document = default_document()

            # Define key elements for document
            # set up id
            document["id"] = issue.number
            # set up title
            document["title"] = issue.title
            # set up description
            if importer.get_description():
                description_raw = (
                    importer.get_description().replace("```", "").replace("###", "")
                )
                description_raw = description_raw.replace("\r\n\r\n", "")
                # description_printed = "{}".format(description_raw)
                # description_printed = "%s" % description_raw
                # description_printed = description_raw.replace("\r\n", "\\n")
            else:
                description_raw = ""
            document["description"] = description_raw

            # set up type of flaw
            document["type"] = importer.get_flaw_type()
            # set up vendor
            document["vendor"] = importer.get_vendor()
            # set up system
            document["system"] = importer.get_robot_or_component()
            # set up CWE
            if importer.get_cwe_id():
                document["cwe"] = (
                    "None"
                    if importer.get_cwe_id() == "N/A"
                    else "CWE-" + str(importer.get_cwe_id())
                )
            else:
                document["cwe"] = "None"
            # set up RVSS score
            try:
                if importer.get_rvss_score():
                    document["severity"]["rvss-score"] = (
                        "None"
                        if importer.get_cwe_id() == "N/A"
                        else int(importer.get_rvss_score())
                    )
                else:
                    document["severity"]["rvss-score"] = "None"
            except ValueError:
                document["severity"]["rvss-score"] = "None"
            except:
                document["severity"]["rvss-score"] = "None"
            # set up rvss-vector
            if importer.get_rvss_vector():
                document["severity"]["rvss-vector"] = importer.get_rvss_vector()
            else:
                document["severity"]["rvss-vector"] = "N/A"
            # set up trace
            document["flaw"]["trace"] = importer.get_stack_trace()

            # set up some general information
            table = importer.table_rows
            labels = [l.name for l in issue.labels]
            document["flaw"]["issue"] = issue.html_url
            document["links"] = [issue.html_url]
            document["keywords"] = labels

            # Process importer.table_rows, e.g.:
            #    [('Input      ', 'Value  '),
            #    ('---------', '--------'),
            #    ('Robot component ', 'ros2 '),
            #    ('Package ', 'tf2_ros '),
            #    ('Commit ', '[30baee82ea95c176b4b0d7ced1d3921820362d9d](https://github.com/ros2/ros2/tree/30baee82ea95c176b4b0d7ced1d3921820362d9d) '),
            #    ('Vendor  ', 'N/A '), ('CVE ID  ', 'N/A  '),
            #    ('CWE ID  ', 'N/A '), ('RVSS Score  ', 'N/A '),
            #    ('RVSS Vector ', 'N/A '),
            #    ('GitHub Account ', '@vmayoral '),
            #    ('Date Reported  ', 'Mon, 21 Oct 2019 17:38:55 +0000 '),
            #    ('Date Updated   ', 'Mon, 21 Oct 2019 17:38:55 +0000 '),
            #    ('Module URL ', 'registry.gitlab.com/aliasrobotics/offensive/alurity/ros2/ros2:build-tsan2-commit-b2dca472a35109cece17d3e61b18af5cb9be5772 '),
            #    ('Attack vector ', 'Internal network, robotics framework ')]
            for key, value in table:
                if "Robot" in key:
                    document["system"] = value.strip()
                    if value.strip() == "ros2":
                        document["flaw"]["phase"] = "testing"
                        document["flaw"]["subsystem"] = "cognition:ros2"
                        document["flaw"]["reported-by-relationship"] = "automatic"
                        document["flaw"]["detected-by-method"] = "testing dynamic"
                        document["flaw"]["specificity"] = "ROS-specific"
                        document["flaw"]["architectural-location"] = "platform code"
                        document["flaw"][
                            "reported-by"
                        ] = "Alias Robotics (http://aliasrobotics.com)"
                if "Package" in key:
                    document["flaw"]["package"] = value.strip()
                if "Date Reported" in key:
                    document["flaw"]["date-detected"] = value.strip()
                    document["flaw"]["date-reported"] = value.strip()
                if "Module URL" in key:
                    document["flaw"]["reproduction-image"] = value.strip()
                    if value.strip() != "" and value.strip() != "None":
                        document["flaw"]["reproducibility"] = "always"
                        document["flaw"][
                            "reproduction"
                        ] = "Find a\
pre-compiled environment in the Docker image below. Reproducing it implies\
source the workspace, finding the appropriate test and executing it."

            flaw = Flaw(document)
            if dump:
                # print(document)
                print(flaw)
                # print(flaw.yml())

            # validate the resulting document
            flaw.validate()

            # print(document_final)
            if push:
                cyan("Pushing results to RVD...")
                pusher = Base()
                if flaw.title[:4] != "RVD#":  # already has the syntax
                    new_title = "RVD#" + str(issue.number) + ": " + flaw.title
                    flaw.title = new_title
                pusher.update_ticket(issue, flaw)


@fetch.command("yml")
@click.argument("filename", required=False)
@click.option(
    "--push/--no-push", help="Push imported flaws to RVD.", default=False,
)
@click.option(
    "--all/--no-all",
    help='Import all issues from repository. USED in "overwrite_issue".',
    default=False,
)
@click.option(
    "--dump/--no-dump", help="Print in stdout results.", default=False,
)
def fetch_yml(filename, push, all, dump):
    """
   rvd import yml <filepath> imports from a yml file in the filepath
   provided, validates the file yml content against the database schema and
   then attempts to push it to RVD as a ticket if the right flags are used
    """
    if not filename:
        red("Filename not provided")
        sys.exit(1)
    else:
        cyan("Importing from yaml file: " + str(filename))
        validation, document_validated = validate(filename)
        if validation:
            # pprint.pprint(document_validated)
            cyan("Final result:")
            flaw = Flaw(document)

            if dump:
                print(flaw)
                # print(flaw.yml())

            # validate the resulting document
            flaw.validate()

            if push:
                cyan("Pushing results to RVD...")
                pusher = Base()
                pusher.new_ticket(flaw, [])


def start():
    main(obj={})


if __name__ == "__main__":
    start()
