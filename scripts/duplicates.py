"""
Alias Robotics SL 
https://aliasrobotics.com

Script that goes through all tickets and finds duplicates.

Run:
    python3 duplicates.py
"""

from import.import_base import RVDImport
from parser.parser import RVDParser

class Duplicates(RVDImport):    
    def __init__(self):
        """
        TODO
        """
        pass
        
    def find_duplicates(self):
        """
        Find duplicates.
        
        Content duplications is judged using ...
        
        :return list[list]
        """
        pass
    
    def report_close_duplicates(self, duplicates):
        """
        Processes the groups (list[lists]) and uses a heuristic to pick 
        one of the tickets for each group. Such ticket is used as the sink
        for all the rest elements in the group which get closed and referred
        (comment) to the sink ticket.        
        
        :return None
        """
        pass


d = Duplicates()
duplicates = d.find_duplicates() # returns a dict where the key represents 
d.report_close_duplicates() # reports and closes duplicates, leaving only one open