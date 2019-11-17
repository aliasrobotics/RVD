# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Utility functions
"""


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


def cyan(text, end="\n"):
    print('\033[36m', text, '\033[0m', sep='', end = end)


def gray(text, end="\n"):
    print('\033[90m', text, '\033[0m', sep='', end = end)
