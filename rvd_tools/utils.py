# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Utility functions
"""

from cerberus import Validator
from .database.schema import *


def black(text, end="\n"):
    print('\033[30m', text, '\033[0m', sep='', end = end)


def red(text, end="\n"):
    print('\033[31m', text, '\033[0m', sep='', end = end)


def inline_red(text):
    return '\033[31m%s\033[0m' % text


def green(text, end="\n"):
    print('\033[32m', text, '\033[0m', sep='', end = end)


def inline_green(text):
    return '\033[32m%s\033[0m' % text


def yellow(text, end="\n"):
    print('\033[33m', text, '\033[0m', sep='', end = end)


def inline_yellow(text):
    return '\033[33m%s\033[0m' % text


def blue(text, end="\n"):
    print('\033[34m', text, '\033[0m', sep='', end = end)


def inline_blue(text):
    return '\033[34m%s\033[0m' % text


def magenta(text, end="\n"):
    print('\033[35m', text, '\033[0m', sep='', end = end)


def inline_magenta(text):
    return '\033[35m%s\033[0m' % text


def cyan(text, end="\n"):
    print('\033[36m', text, '\033[0m', sep='', end = end)


def gray(text, end="\n"):
    print('\033[90m', text, '\033[0m', sep='', end = end)


def inline_gray(text):
    return '\033[90m%s\033[0m' % text


def validate_document(document):
    """
    Validate document passed as parameter and returns feedback on it.

    :return (valid, dict) where:
        - valid is a boolean that expresses the result of the operation
        - dict is a dictionary containing the errors
    """
    validated = False  # reflect whether the overall process suceeded
    v = Validator(SCHEMA, allow_unknown=True)  # allow unknown values
    if document:
        if not v.validate(document, SCHEMA):
            # print(v.errors)
            for key in v.errors.keys():
                print("\t" + str(key) + ": ", end='')
                red("not valid", end='')
                print(': ' + str(v.errors[key]))
        else:
            green("Validated successfully!")
            validated = True
    return (validated, v.errors)
