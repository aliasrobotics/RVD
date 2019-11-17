# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Script containing default values and structures for RVD
"""
from .schema import SCHEMA
from ..utils import red
import sys
from cerberus import Validator


def default_document():
    """
    Produce a default document based
    on the schema
    """
    document = {
        'id': 1,
        'title': "",
        'type': "weakness",
        'description': "",
        'cwe': "None",
        'cve': "None",
        'keywords': "",
        'system': "",
        'vendor': None,
        'severity': {
            'rvss-score': 0,
            'rvss-vector': "",
            'severity-description': "",
            'cvss-score': 0,
            'cvss-vector': "",
        },
        'links': "",
        'flaw': {
            'phase': "testing",
            'specificity': "N/A",
            'architectural-location': "N/A",
            'application': "N/A",
            'subsystem': "N/A",
            'package': "N/A",
            'languages': "None",
            'date-detected': "",
            'detected-by': "",
            'detected-by-method': "N/A",
            'date-reported': "",
            'reported-by': "",
            'reported-by-relationship': "N/A",
            'issue': "",
            'reproducibility': "",
            'trace': "",
            'reproduction': "",
            'reproduction-image': "",
        },
        'exploitation': {
            'description': "",
            'exploitation-image': "",
            'exploitation-vector': "",
        },
        'mitigation': {
            'description': "",
            'pull-request': "",
        },
    }

    v = Validator(SCHEMA, allow_unknown=True)
    if v.validate(document, SCHEMA):
        document = v.document
        return document
    else:
        red("Error generaring default document, not valid")
        # debug which values are causing problems with the validation
        for key in v.errors.keys():
            print("\t" + str(key) + ": ", end='')
            red("not valid", end='')
            print(': ' + str(v.errors[key]))
        sys.exit(1)

    return document
