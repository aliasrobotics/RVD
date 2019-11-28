# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Functions and primitives for editing the database
"""

from .base import *
from ..utils import gray, red, green, cyan, yellow, inline_magenta, validate_document
import qprompt
import ast


def ticket_menu(id, flaw):
    """
    Print the ticket and the menu

    :return choice
    """
    cyan("Editing ticket: ", end="")
    print(str(id))
    # print(flaw)
    menu = qprompt.Menu()
    menu.add("e", "Edit")
    menu.add("p", "Previous")
    menu.add("n", "Next")
    menu.add("s", "Save")
    menu.add("q", "Quit")
    return menu.show()


def edition_menu(flaw):
    """
    Edit the flaw and return it with the corresponding changes

    :return Flaw
    """
    # print(flaw)
    choice = qprompt.ask_str(inline_yellow("Enter property to edit with '_' \
to separate subfields. Some examples include \
'title', 'flaw_phase' or 'severity_rvss-score'\n"))
    new_flaw = None
    try:
        # differentiate options and edit value
        if len(choice.split("_")) == 1:
            current_value = flaw.document()[choice]
            new_value = qprompt.ask_str("Current value is: '" + inline_magenta(str(current_value)) + "'\n")
            new_document = flaw.document()
            new_document[choice] = new_value
        else:
            current_value = flaw.document()[choice.split("_")[0]][choice.split("_")[1]]
            new_value = qprompt.ask_str("Current value is: '" + inline_magenta(str(current_value)) + "'\n")
            new_document = flaw.document()
            new_document[choice.split("_")[0]][choice.split("_")[1]] = new_value
        validated, errors = validate_document(new_document)
        new_flaw = Flaw(new_document)
        return new_flaw
    except KeyError:
        yellow("Warning, subfield not found, no change applied")
        return flaw


def edit_function(id, subsequent, flaw=None):
    """
    Function that triggers the ticket edition logic, returns the last flaw edited

    Runs validation checks and reports accordingly on each edition iteration.

    :param id, ticket's ID
    :param subsequent bool, subsequent ticket editions
    :param: flaw, use existing flaw rather than creating a new one
    :return Flaw
    """
    importer = Base()

    # aiming to return flaw, not update it
    if not subsequent:
        # contruct flaw if not passed as a parameter
        if not flaw:
            flaw = importer.import_issue(id)

        continue_editing = True
        while continue_editing:
            print(flaw)
            # construct flaw
            menu = qprompt.Menu()
            menu.add("e", "Edit")
            menu.add("s", "Skip")
            menu.add("q", "Quit")
            choice = menu.show()

            if choice == 'e':
                new_flaw = edition_menu(flaw)
                flaw = new_flaw
            elif choice == 's':  # skip and return None
                return None
            else:
                continue_editing = False
        return flaw

    # automatically updates tickets when stepping over them ("n" or "p")
    else:
        continue_editing = subsequent  # variable that captures
                                       # subsequent editions
        flaw = importer.import_issue(id)
        # continue editing if applies
        while continue_editing:
            # construct flaw
            print(flaw)
            choice = ticket_menu(id, flaw)
            if choice == 'e':
                new_flaw = edition_menu(flaw)
                flaw = new_flaw
            elif choice == "n":
                importer.update_ticket(importer.repo.get_issue(int(id)), flaw)
                continue_editing = True
                id = int(id) + 1
                flaw = importer.import_issue(id)
                # TODO: consider overflow
            elif choice == "p":
                importer.update_ticket(importer.repo.get_issue(int(id)), flaw)
                continue_editing = True
                id = int(id) - 1
                if id < 1:
                    yellow("Reached first ticket")
                    sys.exit(0)
                flaw = importer.import_issue(id)
            elif choice == "s":
                importer.update_ticket(importer.repo.get_issue(int(id)), flaw)
            else:
                continue_editing = False
        return flaw
