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
from .utils import red, cyan, green, yellow
from .database.schema import *
from .database.defaults import *
from .database.flaw import *
# from .database.coercer import *
from .importer.robust import *
from .importer.markdown import *
import sys
import json
import os
import subprocess
import pprint
from datetime import datetime
import arrow
from tabulate import tabulate

#  ┌┬┐┌─┐┬┌┐┌
#  │││├─┤││││
#  ┴ ┴┴ ┴┴┘└┘
@click.group()
def main():
    """Robot Vulnerability Database (RVD) command line tooling"""
    cyan("Starting rvd, the CLI tool for managing the Robot \
Vulnerability Database...")

#  ┬  ┬┌─┐┌┬┐
#  │  │└─┐ │ 
#  ┴─┘┴└─┘ ┴ 
@main.command("list")
@click.argument('id', required=False)
@click.option('--dump/--no-dump',
              help='Print the tickets.', default=False,)
def list(id, dump):
    """List current flaw tickets"""
    importer = Base()

    if id:  # which is the same as the issue number
        # Get the issue
        issue = importer.repo.get_issue(int(id))
        cyan("Importing from RVD, issue: " + str(issue))
        document_raw = issue.body
        document_raw = document_raw.replace('```yaml','').replace('```', '')
        document = yaml.load(document_raw)
        # print(document)

        flaw = Flaw(document)
        print(flaw)
    else:
        cyan("Listing all open issues from RVD...")
        issues = importer.repo.get_issues(state="open")
        table = [[issue.number, issue.title] for issue in issues]
        print(tabulate(table, headers=["ID", "Title"]))
        if dump:
            for issue in issues:
                cyan("Importing from RVD, issue: " + str(issue))
                document_raw = issue.body
                document_raw = document_raw.replace('```yaml','').replace('```', '')
                document = yaml.load(document_raw)
                flaw = Flaw(document)
                # print(flaw)

#  ┬  ┬┌─┐┬  ┬┌┬┐┌─┐┌┬┐┌─┐
#  └┐┌┘├─┤│  │ ││├─┤ │ ├┤ 
#   └┘ ┴ ┴┴─┘┴─┴┘┴ ┴ ┴ └─┘
@main.command("validate")
@click.argument('filename', type=click.Path(exists=True))
@click.option('--dump/--no-dump',
              help='Print resulting document at the end.', default=False,)
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
        with open(click.format_filename(filename), 'r') as stream:
            try:
                doc = yaml.load(stream)
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
                print("\t" + str(key) + ": ", end='')
                red("not valid", end='')
                print(': ' + str(v.errors[key]))
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
        print(json.dumps(v.document, indent=4,
                         default=default))
        # flaw = Flaw(v.document)
        # print the final document after validations and normalizations
        # print(flaw)
        # print(flaw.yml())
    return validated, v.document

#  ┬┌┬┐┌─┐┌─┐┬─┐┌┬┐
#  ││││├─┘│ │├┬┘ │ 
#  ┴┴ ┴┴  └─┘┴└─ ┴ 
@main.command("import")
# @click.option('--url', default=None, help='Base URL\
#               from where to import flaws.')
@click.argument('uri')
@click.argument('filename', required=False)
@click.option('--push/--no-push',
              help='Push imported flaws to RVD.', default=False,)
@click.option('--all/--no-all',
              help='Import all issues from repository. USED in "overwrite_issue".',
              default=False,)
@click.option('--dump/--no-dump',
              help='Print in stdout results.', default=False,)
def fetch(uri, filename, push, all, dump):
    """Import flaws to RVD from a variety of sources

       rvd import yml <filepath>: imports from a yml file in the filepath
       provided, validates the file yml content against the database schema and
       then attempts to push it to RVD as a ticket.

       rvd import robust: imports from ROSin's robust project tickets

       rvd import issue <URL>: imports from RVD's Github issues

       rvd import overwrite_issue <URL>: imports from RVD's OLD format issues
       and overwrite them with the new format. If --all flag is used, applies
       changes to all the tickets.
    """
    cyan("Importing...")
    if not uri:
        red("A URL is needed when calling import")
        sys.exit(1)
    else:
        cyan("Creating folder for the import process...")
        os.system("mkdir -p /tmp/rvd")

        # Check URIs, only selected ones should be accepted
        
        # robust
        #########
        if (uri == "https://github.com/robust-rosin/robust") or (uri == "robust"):
            importer = RobustImporter()
            cyan("Cloning robust project...")
            os.system("cd /tmp/rvd && git clone\
                       https://github.com/robust-rosin/robust")
            # os.system("du -a /tmp/rvd/robust | grep\
            #           '\.bug$' | awk '{print $2}'")
            stdoutdata = subprocess.getoutput("\
                du -a /tmp/rvd/robust | grep '\.bug$' | awk '{print $2}'")
            bugfiles = stdoutdata.split('\n')
            for bug in bugfiles:
                # normalize and validate the content of the bug
                validation, document_validated = validate_file(bug)

                # drop 'bugzoo' key
                if 'bugzoo' in document_validated.keys():
                    yellow("Dropping bugzoo key")
                    document_validated.pop('bugzoo')
                # drop 'time-machine' key
                if 'time-machine' in document_validated.keys():
                    yellow("Dropping time-machine key")
                    document_validated.pop('time-machine')

                flaw = Flaw(document_validated)
                # add relevant keys to flaw using add_field method
                for key in document_validated['mitigation'].keys():
                    yellow("Adding to flaw ['mitigation']['" + str(key) + "'] = " + str(document_validated['mitigation'][key]))
                    flaw.add_field(value=document_validated['mitigation'][key],
                                   key="mitigation",
                                   key2=key)
                if dump:
                    print(flaw)
                    # print(flaw.yml())

                cyan("Validate again after processing...")
                # validate the resulting document
                flaw.validate()

                if push:
                    cyan("Pushing results to RVD...")
                    pusher = Base()
                    labels = ['quality']
                    if flaw.vendor:
                        if flaw.vendor != "N/A":
                            labels.append(flaw.vendor)
                    labels.append(flaw.type)
                    labels.append(flaw.system)
                    labels.append('mitigated')
                    pusher.new_ticket(flaw, labels)

        # issue
        #########
        #  Github issue/ticket, URL
        #  dump machine-readable content in a local flaw file
        elif uri == "issue":
            # use filename as URL
            url = filename
            if not url:
                red("URL not provided")
                sys.exit(1)
            else:
                processed_url = url.split("/")

                repo = processed_url[-3]
                user = processed_url[-4]
                issue_number = int(processed_url[-1])

                # Get the issue
                importer = Base()
                issue = importer.repo.get_issue(issue_number)
                cyan("Importing from RVD, issue: " + str(issue))

                # TODO: dump issue.body into a file
                raise NotImplementedError

        # overwrite_issue
        #########
        #  Github OLD issue/ticket, URL
        #  mean to be used from sources like old RVD tickets
        #  assummes syntax defined in MarkdownImporter class
        elif uri == "overwrite_issue":
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
                    document['id'] = issue.number
                    # set up title
                    document['title'] = issue.title
                    # set up description
                    if importer.get_description():
                        description_raw = importer.get_description().replace('```', '').replace('###', '')
                        description_raw = description_raw.replace('\r\n\r\n', '')
                        # description_printed = "{}".format(description_raw)
                        # description_printed = "%s" % description_raw
                        # description_printed = description_raw.replace("\r\n", "\\n")
                    else:
                        description_raw = ""
                    document['description'] = description_raw

                    # set up type of flaw
                    document['type'] = importer.get_flaw_type()
                    # set up vendor
                    document['vendor'] = importer.get_vendor()
                    # set up system
                    document['system'] = importer.get_robot_or_component()
                    # set up CWE
                    if importer.get_cwe_id():
                        document['cwe'] = "None" if importer.get_cwe_id() == "N/A" else "CWE-" + str(importer.get_cwe_id())
                    else:
                        document['cwe'] = "None"
                    # set up RVSS score
                    try:
                        if importer.get_rvss_score():
                            document['severity']['rvss-score'] = "None" if importer.get_cwe_id() == "N/A" else int(importer.get_rvss_score())
                        else:
                            document['severity']['rvss-score'] = "None"
                    except ValueError:
                        document['severity']['rvss-score'] = "None"
                    except:
                        document['severity']['rvss-score'] = "None"
                    # set up rvss-vector
                    if importer.get_rvss_vector():
                        document['severity']['rvss-vector'] = importer.get_rvss_vector()
                    else:
                        document['severity']['rvss-vector'] = "N/A"
                    # set up trace
                    document['flaw']['trace'] = importer.get_stack_trace()

                    # set up some general information
                    table = importer.table_rows
                    labels = [l.name for l in issue.labels]
                    document['flaw']['issue']= issue.html_url
                    document['links'] = [issue.html_url]
                    document['keywords'] = labels

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
                            document['system'] = value.strip()
                            if value.strip() == "ros2":
                                document['flaw']['phase'] = "testing"
                                document['flaw']['subsystem'] = "cognition:ros2"
                                document['flaw']['reported-by-relationship'] = "automatic"
                                document['flaw']['detected-by-method'] = "testing dynamic"
                                document['flaw']['specificity'] = "ROS-specific"
                                document['flaw']['architectural-location'] = "platform code"
                                document['flaw']['reported-by'] = "Alias Robotics (http://aliasrobotics.com)"
                        if "Package" in key:
                            document['flaw']['package'] = value.strip()
                        if "Date Reported" in key:
                            document['flaw']['date-detected'] = value.strip()
                            document['flaw']['date-reported'] = value.strip()
                        if "Module URL" in key:
                            document['flaw']['reproduction-image'] = value.strip()
                            if value.strip() != '' and value.strip() != 'None':
                                document['flaw']['reproducibility'] = "always"
                                document['flaw']['reproduction'] = "Find a\
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
                        pusher.update_ticket(issue, flaw)

        # yml
        #########
        elif uri == "yml":
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

        # Default
        #########
        else:
            red("URI: " + str(uri) + " not among the accepted ones")
            red("try with: yml, robust, issue, overwrite_issue")
            sys.exit(1)


def start():
    main(obj={})


if __name__ == '__main__':
    start()
