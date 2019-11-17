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
def list():
    """List current flaw tickets"""
    importer = Base()
    cyan("Fetching all open issues from RVD...")
    issues = importer.repo.get_issues(state="open")
    table = [[issue.number, issue.title] for issue in issues]
    print(tabulate(table, headers=["ID", "Title"]))


#  ┬  ┬┌─┐┬  ┬┌┬┐┌─┐┌┬┐┌─┐
#  └┐┌┘├─┤│  │ ││├─┤ │ ├┤ 
#   └┘ ┴ ┴┴─┘┴─┴┘┴ ┴ ┴ └─┘
@main.command("validate")
@click.argument('filename', type=click.Path(exists=True))
@click.option('--dump/--no-dump',
              help='Print resulting document at the end.', default=False,)
def validation(filename, dump):
    """Validate the file provided its path"""
    validate(filename, dump)


def validate(filename, dump=False):
    """Auxiliary function to reuse code"""
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
        # print the final document after validations and normalizations
        print(json.dumps(v.document, indent=4))
    return validated, v.document


def default(obj):
    """
    Auxiliary function to import

    captures those cases where datetime is recognized from the yaml
    file and translates it using arrow
    """
    if isinstance(obj, datetime):
        # return { '_isoformat': obj.isoformat() }
        arrow_date = arrow.get(obj)
        return arrow_date.format('YYYY-MM-DD (HH:mm)')
        # return str(obj)  # return str instead
    # return super().default(obj)  # removed since it was causing issues

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
def fetch(uri, filename, push):
    """Import flaws to RVD from a variety of sources

       rvd import yml <filepath>: imports from a yml file in the filepath
       provided, validates the file yml content against the database schema and
       then attempts to push it to RVD as a ticket.

       rvd import robust: imports from ROSin's robust project tickets

       rvd import issue <URL>: imports from Github's issue
    """
    cyan("Importing...")
    if not uri:
        red("A URL is needed when calling import")
        sys.exit(1)
    else:
        cyan("Creating folder for the import process...")
        os.system("mkdir -p /tmp/rvd")

        # Check URIs, only selected ones should be accepted
        # Robust
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
                validation, document_validated = validate(bug)
                # document_validated['bugzoo'] = None
                if 'bugzoo' in document_validated.keys():
                    yellow("Dropping bugzoo key")
                    document_validated.pop('bugzoo')

                # Deal with datetime issues
                document_final = json.dumps(document_validated, indent=4,
                                            default=default)

                # # print resulting document
                # print(document_final)

                # if validation:
                #     print(json.dumps(document_validated, indent=4,
                #           default=default))

                if push:
                    cyan("Pushing results to RVD...")
                    importer = Base()
                    # TODO, implement this one
                    raise NotImplementedError

        # Github issue/ticket, URL
        #  mean to be used from sources like RVD to import tickets
        #  assummes syntax defined in MarkdownImporter class
        #########
        elif uri == "issue":
            # use filename as URL
            url = filename
            if not url:
                red("URL not provided")
                sys.exit(1)
            else:
                processed_url = url.split("/")
                issue_number = int(processed_url[-1])
                repo = processed_url[-3]
                user = processed_url[-4]

                importer = MarkdownImporter(user, repo)
                issue = importer.repo.get_issue(issue_number)
                # parse issue's body
                importer.parse(issue.body)
                document = default_document()

                # Define key elements for document
                # set up id
                document['id'] = issue.number
                # set up title
                document['title'] = issue.title
                # set up description
                description_raw = importer.get_description().replace('```', '').replace('###', '')
                description_raw = description_raw.replace('\r\n\r\n', '')
                # description_printed = "{}".format(description_raw)
                # description_printed = "%s" % description_raw
                # description_printed = description_raw.replace("\r\n", "\\n")
                document['description'] = description_raw

                # set up type of flaw
                document['type'] = importer.get_flaw_type()
                # set up vendor
                document['vendor'] = importer.get_vendor()
                # set up system
                document['system'] = importer.get_robot_or_component()
                # set up CWE
                if importer.get_cwe_id():
                    document['cwe'] = "N/A" if importer.get_cwe_id() == "N/A" else "CWE-" + str(importer.get_cwe_id())
                else:
                    document['cwe'] = "N/A"
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
                document['severity']['rvss-vector'] = importer.get_rvss_vector()
                document['flaw']['trace'] = importer.get_stack_trace()

                # Deal with datetime issues
                document_final = json.dumps(document, indent=4,
                                            default=default)
                print(document_final)
                if push:
                    cyan("Pushing results to RVD...")
                    importer = Base()
                    # TODO, implement this one
                    raise NotImplementedError

        # YML
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
                    document_final = json.dumps(document_validated, indent=4)
                    print(document_final)
                    if push:
                        cyan("Pushing results to RVD...")
                        importer = Base()
                        # TODO, implement this one
                        raise NotImplementedError

        # Default
        #########
        else:
            red("URI: " + str(uri) + " not among the accepted ones")
            red("try with: yml, robust, url")
            sys.exit(1)


def start():
    main(obj={})

if __name__ == '__main__':
    start()
