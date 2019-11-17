# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Flaw class, object to represent all flaws
"""
from ..utils import inline_green, inline_blue, inline_yellow, red, green
import json
from datetime import datetime
import arrow
from .schema import SCHEMA
from cerberus import Validator
from mergedeep import merge


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


class Flaw:
    """The Flaw class"""
    def __init__(self, document):
        # DO NOT KEEP THIS ATTRIBUTE, avoid issues and instead, generate it
        #  refer to the document() class method
        # self.document = document

        # parse document and assign all values to class attributes
        self.id = document['id']
        self.title = document['title']
        self.type = document['type']
        self.description = document['description']
        self.cwe = document['cwe']
        self.cve = document['cve']
        self.keywords = document['keywords']
        self.system = document['system']
        self.vendor = document['vendor']

        # severity
        try:
            self.rvss_score = document['severity']['rvss-score']
            self.rvss_vector = document['severity']['rvss-vector']
            self.severity_description = document['severity']['severity-description']
            self.cvss_score = document['severity']['cvss-score']
            self.cvss_vector = document['severity']['cvss-vector']
        except TypeError:
            self.rvss_score = 0
            self.rvss_vector = ""
            self.severity_description = ""
            self.cvss_score = 0
            self.cvss_vector = ""

        self.links = document['links']
        # flaw
        self.phase = document['flaw']['phase']
        self.specificity = document['flaw']['specificity']
        self.architectural_location = document['flaw']['architectural-location']
        self.application = document['flaw']['application']
        self.subsystem = document['flaw']['subsystem']
        self.package = document['flaw']['package']
        self.languages = document['flaw']['languages']
        self.date_detected = document['flaw']['date-detected']
        self.detected_by = document['flaw']['detected-by']
        self.detected_by_method = document['flaw']['detected-by-method']
        self.date_reported = document['flaw']['date-reported']
        self.reported_by = document['flaw']['reported-by']
        self.reported_by_relationship = document['flaw']['reported-by-relationship']
        self.issue = document['flaw']['issue']
        self.reproducibility = document['flaw']['reproducibility']
        self.trace = document['flaw']['trace']
        self.reproduction = document['flaw']['reproduction']
        self.reproduction_image = document['flaw']['reproduction-image']
        # exploitation
        try:
            self.description_exploitation = document['exploitation']['description']
            self.exploitation_image = document['exploitation']['exploitation-image']
            self.exploitation_vector = document['exploitation']['exploitation-vector']
        except TypeError:
            self.description_exploitation = ""
            self.exploitation_image = ""
            self.exploitation_vector = ""

        # mitigation
        self.description_mitigation = document['mitigation']['description']
        self.pull_request = document['mitigation']['pull-request']
        
        # additional values
        self.additional_fields = {}


    def __str__(self):
        """
        String representation
        """
        # pylint: disable = line-too-long
        return_str = ''
        return_str += inline_green("id") + ": " + str(self.id) + "\n"
        return_str += inline_green("title") + ": " + str(self.title) + "\n"
        return_str += inline_green("type") + ": " + str(self.type) + "\n"
        return_str += inline_green("description") + ": " + str(self.description) + "\n"
        return_str += inline_green("cwe") + ": " + str(self.cwe) + "\n"
        return_str += inline_green("cve") + ": " + str(self.cve) + "\n"
        return_str += inline_green("keywords") + ": " + str(self.keywords) + "\n"
        return_str += inline_green("system") + ": " + str(self.system) + "\n"
        return_str += inline_green("vendor") + ": " + str(self.vendor) + "\n"
        # severity
        return_str += inline_green("severity") + "\n"
        return_str += "\t" + inline_blue("rvss-score") + ": " + str(self.rvss_score) + "\n"
        return_str += "\t" + inline_blue("rvss-vector") + ": " + str(self.rvss_vector) + "\n"
        return_str += "\t" + inline_blue("severity-description") + ": " + str(self.severity_description) + "\n"
        return_str += "\t" + inline_blue("cvss-score") + ": " + str(self.cvss_score) + "\n"
        return_str += "\t" + inline_blue("cvss-vector") + ": " + str(self.cvss_vector) + "\n"
        
        return_str += inline_green("links") + ": " + str(self.links) + "\n"
        # flaw
        return_str += inline_green("flaw") + "\n"
        return_str += "\t" + inline_blue("phase") + ": " + str(self.phase) + "\n"
        return_str += "\t" + inline_blue("specificity") + ": " + str(self.specificity) + "\n"
        return_str += "\t" + inline_blue("architectural-location") + ": " + str(self.architectural_location) + "\n"
        return_str += "\t" + inline_blue("application") + ": " + str(self.application) + "\n"
        return_str += "\t" + inline_blue("subsystem") + ": " + str(self.subsystem) + "\n"
        return_str += "\t" + inline_blue("package") + ": " + str(self.package) + "\n"
        return_str += "\t" + inline_blue("languages") + ": " + str(self.languages) + "\n"
        return_str += "\t" + inline_blue("date-detected") + ": " + str(self.date_detected) + "\n"
        return_str += "\t" + inline_blue("detected-by") + ": " + str(self.detected_by) + "\n"
        return_str += "\t" + inline_blue("detected-by-method") + ": " + str(self.detected_by_method) + "\n"
        return_str += "\t" + inline_blue("date-reported") + ": " + str(self.date_reported) + "\n"
        return_str += "\t" + inline_blue("reported-by") + ": " + str(self.reported_by) + "\n"
        return_str += "\t" + inline_blue("reported-by-relationship") + ": " + str(self.reported_by_relationship) + "\n"
        return_str += "\t" + inline_blue("issue") + ": " + str(self.issue) + "\n"
        return_str += "\t" + inline_blue("reproducibility") + ": " + str(self.reproducibility) + "\n"
        return_str += "\t" + inline_blue("trace") + ": " + str(self.trace) + "\n"
        return_str += "\t" + inline_blue("reproduction") + ": " + str(self.reproduction) + "\n"
        return_str += "\t" + inline_blue("reproduction-image") + ": " + str(self.reproduction_image) + "\n"
        # additional_fields - flaw
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "flaw":
                    for key2 in self.additional_fields[key].keys():
                        return_str += "\t" + inline_yellow(key2) + ": " + str(self.additional_fields[key][key2]) + "\n"

        # exploitation
        return_str += inline_green("exploitation") + "\n"
        return_str += "\t" + inline_blue("description") + ": " + str(self.description_exploitation) + "\n"
        return_str += "\t" + inline_blue("exploitation-image") + ": " + str(self.exploitation_image) + "\n"
        return_str += "\t" + inline_blue("exploitation-vector") + ": " + str(self.exploitation_vector) + "\n"
        # additional_fields - exploitation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "exploitation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += "\t" + inline_yellow(key2) + ": " + str(self.additional_fields[key][key2]) + "\n"
        
        # mitigation
        return_str += inline_green("mitigation") + "\n"
        return_str += "\t" + inline_blue("description") + ": " + str(self.description_mitigation) + "\n"
        return_str += "\t" + inline_blue("pull-request") + ": " + str(self.pull_request) + "\n"
        # additional_fields - mitigation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "mitigation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += "\t" + inline_yellow(key2) + ": " + str(self.additional_fields[key][key2]) + "\n"

        # additional_fields (others)
        for key in self.additional_fields.keys():
            if key in ['mitigation', 'exploitation', 'flaw']:  # the ones contemplated above with additional_fields
                continue
            if isinstance(self.additional_fields[key], dict):
                return_str += inline_yellow(key) + "\n"
                for key2 in self.additional_fields[key].keys():
                    return_str += "\t" + inline_yellow(key2) + ": " + str(self.additional_fields[key][key2]) + "\n"
            else:
                return_str += "\t" + inline_yellow(key2) + ": " + str(self.additional_fields[key]) + "\n"

        return return_str

    def yml(self):
        """
        Produce YAML machine readable format

        :returns str
        """
        # Deal with datetime issues
        return json.dumps(self.document(), indent=4,
                          default=default)

    def yml_markdown(self):
        """
        Produce YAML machine readable format

        :returns str
        """
        # Deal with datetime issues
        return "```yaml\n" + json.dumps(self.document(), indent=4,
                          default=default) + "\n```"

    def document(self):
        """
        Return the YAML document of the flaw
        produce on the fly

        :returns dict
        """
        # Deal with datetime issues
        document = {
            'id': self.id,
            'title': self.title,
            'type': self.type,
            'description': self.description,
            'cwe': self.cwe,
            'cve': self.cve,
            'keywords': self.keywords,
            'system': self.system,
            'vendor': self.vendor,
            'severity': {
                    'rvss-score': self.rvss_score,
                    'rvss-vector': self.rvss_vector,
                    'severity-description': self.severity_description,
                    'cvss-score': self.cvss_score,
                    'cvss-vector': self.cvss_vector,
            },
            'links': self.links,
            'flaw': {
                    'phase': self.phase,
                    'specificity': self.specificity,
                    'architectural-location': self.architectural_location,
                    'application': self.application,
                    'subsystem': self.subsystem,
                    'package': self.package,
                    'languages': self.languages,
                    'date-detected': self.date_detected,
                    'detected-by': self.detected_by,
                    'detected-by-method': self.detected_by_method,
                    'date-reported': self.date_reported,
                    'reported-by': self.reported_by,
                    'reported-by-relationship': self.reported_by_relationship,
                    'issue': self.issue,
                    'reproducibility': self.reproducibility,
                    'trace': self.trace,
                    'reproduction': self.reproduction,
                    'reproduction-image': self.reproduction_image,
            },
            'exploitation': {
                    'description': self.description_exploitation,
                    'exploitation-image': self.exploitation_image,
                    'exploitation-vector': self.exploitation_vector,
            },
            'mitigation': {
                    'description': self.description_mitigation,
                    'pull-request': self.pull_request,
            },
        }

        # Merge schema values together with additional ones
        # document = merge(document, self.additional_fields)
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                for key2 in self.additional_fields[key].keys():
                    document[key][key2] = self.additional_fields[key][key2]
            else:
                # TODO: check that none of the relevant attributes is being modified
                document[key] = self.additional_fields[key]


        return document

    def validate(self):
        """
        Validate flaw against the schema

        :return bool
        """
        validated = False  # reflect whether the overall process suceeded
        v = Validator(SCHEMA, allow_unknown=True)  # allow unknown values
        if not v.validate(self.document(), SCHEMA):
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
        return validated
        
    def add_field(self, value, key, key2=None):
        """
        Add field to the flaw
        
        Used for importing resources that might have additional values
        """
        if key2:
            if key in self.additional_fields.keys():
                self.additional_fields[key][key2] = value
            else:
                # create sub-dict and add value
                self.additional_fields[key] = {}
                self.additional_fields[key][key2] = value
        else:
            self.additional_fields[key] = value