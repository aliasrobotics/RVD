# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Utilities for searching and adapting tickets to the
Common Vulnerabilities and Exposures (CVE).
"""

import sys
import os
import json
import jsonschema
from jsonschema import validate
from jsonschema import Draft4Validator
from ..importer.gitlab import *
from ..database.base import *
from . import static  # relative-import the *package* containing the static
from ..utils import red, yellow, green

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources


def cve_jsonvalidation(json_doc_path, version, mode="public"):
    """
    Validate CVE JSON format

    :param json_doc_path string, absolute path for the
    :returns bool
    """
    # fetch from official repository
    if version == 4:
        if mode == "public":
            os.system(
                "mkdir -p /tmp/cve; cd /tmp/cve/ ; \
                wget https://raw.githubusercontent.com/CVEProject/\
automation-working-group/master/cve_json_schema/CVE_JSON_4.0_min_public.schema"
            )
            schema_path = "/tmp/cve/CVE_JSON_4.0_min_public.schema"
        elif mode == "reject":
            os.system(
                "mkdir -p /tmp/cve; cd /tmp/cve/ ; \
                wget https://raw.githubusercontent.com/CVEProject/\
automation-working-group/master/cve_json_schema/CVE_JSON_4.0_min_reject.schema"
            )
            schema_path = "/tmp/cve/CVE_JSON_4.0_min_reject.schema"
        elif mode == "reserved":
            os.system(
                "mkdir -p /tmp/cve; cd /tmp/cve/ ; \
                wget https://raw.githubusercontent.com/CVEProject/\
automation-working-group/master/cve_json_schema/CVE_JSON_4.0_min_reserved.schema"
            )
            schema_path = "/tmp/cve/CVE_JSON_4.0_min_reserved.schema"
        else:
            print("Mode " + mode + "not implemented")
            raise NotImplementedError
    elif version == 3:
        raise NotImplementedError
    else:
        print("Invalid version")
        raise SystemExit

    # via a file, e.g.
    with open(schema_path, "r") as schema:
        schema_doc = json.load(schema)

    # Open the file for reading
    with open(json_doc_path, "r") as document:
        try:
            json_doc = json.load(document)
        except ValueError as err:
            sys.stderr.write("Failed to parse JSON : \n")
            sys.stderr.write("  " + str(err) + "\n")
            raise SystemExit

    try:
        validate(json_doc, schema_doc)
        green("Record passed validation \n")
    except jsonschema.exceptions.ValidationError as incorrect:
        validator = Draft4Validator(schema_doc)
        errors = sorted(validator.iter_errors(json_doc), key=lambda e: e.path)
        for error in errors:
            red("Record did not pass: \n")
            sys.stderr.write(str(error.message) + "\n")


def cve_export_file(number, version, mode, private, dump, push):
    """
    Export ticket number to CVE JSON format.

    :param number int, ticket number
    :param version int, CVE JSCON version number
    :param private bool, RVD public or private source
    :returns string, path to new ticket
    """
    if private:
        importer_private = GitlabImporter()
        flaw, labels = importer_private.get_flaw(number)
    else:
        importer = Base()
        flaw, labels = importer.get_flaw(number)

    # check if it already has a cve
    if flaw.cve and "CVE-" in flaw.cve:
        red("It seems the ticket already has a CVE ID, double check")
        sys.exit(1)

    with pkg_resources.path(static, "ids") as path:
        all_ids = path.read_text().split("\n")
        next_identifier = ""
        try:
            for identifier in all_ids:
                if identifier[0] == "~":
                    continue
                next_identifier = identifier
                break
        except IndexError:
            print("IndexError, probably more CVE IDs needed!")
            sys.exit(1)

    # Ensure that the detination exists
    os.system("mkdir -p /tmp/cve")
    flaw.export_to_cve(
        "/tmp/cve/" + str(next_identifier) + ".json", version, mode, next_identifier
    )
    green("Successfully exported to /tmp/cve/" + str(next_identifier) + ".json")

    # dump in stdout
    file_path = "/tmp/cve/" + str(next_identifier) + ".json"
    if dump:
        file = open(file_path, "r")
        print(file.read())
        file.close()

    # validate
    cyan("Validating the file...")
    cve_jsonvalidation(file_path, version)

    # push
    if push:
        os.system(
            "cd /tmp/; git clone https://github.com/vmayoral/cvelist;\
cd cvelist; git remote add cvelist https://github.com/CVEProject/cvelist; \
git fetch cvelist; git checkout -b "
            + str(next_identifier)
            + " cvelist/master; \
cp "
            + str(file_path)
            + " $(du -a | grep  CVE-2020-10266 | grep -v .git | awk '{print $2}');\
git add .; git commit -m 'Assign "
            + str(next_identifier)
            + "'; git push -u origin "
            + str(next_identifier)
        )

    cyan("Things left to do:")
    yellow("\t - Add version to new tickets, old ones should not conflict with it")
    yellow("\t - Update ticket in RVD automatically")
    yellow("\t - Edit ids file and indicate it appropriately!")
