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
from .utils import red, cyan, green
from .database.schema import *
# from .database.coercer import *
from .importer.robust import *
import sys
import json
import os

#  ┌┬┐┌─┐┬┌┐┌
#  │││├─┤││││
#  ┴ ┴┴ ┴┴┘└┘
@click.group()
def main():
    """Robot Vulnerability Database (RVD) command line tooling"""
    green("Starting rvd, the CLI tool for managing the Robot Vulnerability Database...")

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

#  ┬┌┬┐┌─┐┌─┐┬─┐┌┬┐
#  ││││├─┘│ │├┬┘ │ 
#  ┴┴ ┴┴  └─┘┴└─ ┴ 
@main.command("import")
# @click.option('--url', default=None, help='Base URL from where to import flaws.')
@click.argument('uri')
@click.argument('filename', required=False)
@click.option('--push/--no-push',
              help='Push import results to RVD.', default=False,)
def fetch(uri, filename, push):
    """Import flaws to RVD from a variety of sources

       rvd import yml <filepath>: imports from a yml file in the filepath
       provided, validates the file yml content against the database schema and
       then attempts to push it to RVD as a ticket.

       rvd import robust: imports from ROSin's robust project tickets
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
        if (uri == "https://github.com/robust-rosin/robust") or (uri == "robust"):
            importer = RobustImporter()
            cyan("Cloning robust project...")
            os.system("cd /tmp/rvd && git clone https://github.com/robust-rosin/robust")
            os.system("du -a /tmp/rvd/robust | grep '\.bug$' | awk '{print $2}'")

        # YML
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
                    print(json.dumps(document_validated, indent=4))
                    if push:
                        cyan("Pushing resutls to RVD...")
                        importer = Base()
                        # TODO, implement this one
                        raise NotImplementedError

        # Default
        else:
            red("URI: " + str(uri) + " not among the accepted ones")
            red("try with: yml, robust")
            sys.exit(1)


def start():
    main(obj={})

if __name__ == '__main__':
    start()