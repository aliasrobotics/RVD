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
        sys.stdout.write("Record passed validation \n")
    except jsonschema.exceptions.ValidationError as incorrect:
        validator = Draft4Validator(schema_doc)
        errors = sorted(validator.iter_errors(json_doc), key=lambda e: e.path)
        for error in errors:
            sys.stderr.write("Record did not pass: \n")
            sys.stderr.write(str(error.message) + "\n")
