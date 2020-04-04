# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Flaw class, object to represent all flaws
"""
import json
from datetime import datetime
import arrow
import sys
from cerberus import Validator
from .schema import SCHEMA
from ..utils import inline_green, inline_blue, inline_yellow, red, green
from cvsslib.vector import detect_vector, calculate_vector, VectorError

# from mergedeep import merge


def default(obj):
    """
    Auxiliary function to import

    captures those cases where datetime is recognized from the yaml
    file and translates it using arrow
    """
    if isinstance(obj, datetime):
        # return { '_isoformat': obj.isoformat() }
        arrow_date = arrow.get(obj)
        return arrow_date.format("YYYY-MM-DD (HH:mm)")
        # return str(obj)  # return str instead
    # return super().default(obj)  # removed since it was causing issues


class Flaw:
    """The Flaw class"""

    def __init__(self, document):
        # DO NOT KEEP THIS ATTRIBUTE, avoid issues and instead, generate it
        #  refer to the document() class method
        # self.document = document

        # parse document and assign all values to class attributes
        self.id = document["id"]
        self.title = document["title"]
        self.type = document["type"]
        self.description = document["description"]
        self.cwe = document["cwe"]
        self.cve = document["cve"]
        self.keywords = document["keywords"]
        self.system = document["system"]
        self.vendor = document["vendor"]

        # severity
        try:
            self.rvss_score = document["severity"]["rvss-score"]
            self.rvss_vector = document["severity"]["rvss-vector"]
            self.severity_description = document["severity"]["severity-description"]
            self.cvss_score = document["severity"]["cvss-score"]
            self.cvss_vector = document["severity"]["cvss-vector"]
        except TypeError:
            self.rvss_score = 0
            self.rvss_vector = ""
            self.severity_description = ""
            self.cvss_score = 0
            self.cvss_vector = ""

        self.links = document["links"]
        # flaw
        self.phase = document["flaw"]["phase"]
        self.specificity = document["flaw"]["specificity"]
        self.architectural_location = document["flaw"]["architectural-location"]
        self.application = document["flaw"]["application"]
        self.subsystem = document["flaw"]["subsystem"]
        self.package = document["flaw"]["package"]
        self.languages = document["flaw"]["languages"]
        self.date_detected = document["flaw"]["date-detected"]
        self.detected_by = document["flaw"]["detected-by"]
        self.detected_by_method = document["flaw"]["detected-by-method"]
        self.date_reported = document["flaw"]["date-reported"]
        self.reported_by = document["flaw"]["reported-by"]
        self.reported_by_relationship = document["flaw"]["reported-by-relationship"]
        self.issue = document["flaw"]["issue"]
        self.reproducibility = document["flaw"]["reproducibility"]
        self.trace = document["flaw"]["trace"]
        self.reproduction = document["flaw"]["reproduction"]
        self.reproduction_image = document["flaw"]["reproduction-image"]
        # exploitation
        try:
            self.description_exploitation = document["exploitation"]["description"]
            self.exploitation_image = document["exploitation"]["exploitation-image"]
            self.exploitation_vector = document["exploitation"]["exploitation-vector"]
        except TypeError:
            self.description_exploitation = ""
            self.exploitation_image = ""
            self.exploitation_vector = ""

        # mitigation
        self.description_mitigation = document["mitigation"]["description"]
        self.pull_request = document["mitigation"]["pull-request"]
        if "date-mitigation" in document["mitigation"].keys():
            self.date_mitigation = document["mitigation"]["date-mitigation"]
        else:
            self.date_mitigation = None

        # additional values
        self.additional_fields = {}

        # CVE and CVSS handling related attributes
        self.elements = [
            "AC",
            "AV",
            "A",
            "severity",
            "C",
            "I",
            "PR",
            "S",
            "UI",
        ]

        self.elements_components = {
            "AC": {"L": "LOW", "H": "HIGH"},
            "AV": {
                "N": "NETWORK",
                "AN": "ADJACENT_NETWORK",
                "L": "LOCAL",
                "P": "PHYSICAL",
            },
            "A": {"L": "LOW", "H": "HIGH", "N": "NONE"},
            "severity": "",
            "C": {"L": "LOW", "H": "HIGH", "N": "NONE"},
            "I": {"L": "LOW", "H": "HIGH", "N": "NONE"},
            "PR": {"L": "LOW", "H": "HIGH", "N": "NONE"},
            "S": {"U": "UNCHANGED", "C": "CHANGED"},
            "UI": {"R": "REQUIRED", "N": "NONE"},
        }

    def __str__(self):
        """
        String representation
        """
        # pylint: disable = line-too-long
        return_str = ""
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
        return_str += (
            "\t" + inline_blue("rvss-score") + ": " + str(self.rvss_score) + "\n"
        )
        return_str += (
            "\t" + inline_blue("rvss-vector") + ": " + str(self.rvss_vector) + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("severity-description")
            + ": "
            + str(self.severity_description)
            + "\n"
        )
        return_str += (
            "\t" + inline_blue("cvss-score") + ": " + str(self.cvss_score) + "\n"
        )
        return_str += (
            "\t" + inline_blue("cvss-vector") + ": " + str(self.cvss_vector) + "\n"
        )

        return_str += inline_green("links") + ": " + str(self.links) + "\n"
        # flaw
        return_str += inline_green("flaw") + "\n"
        return_str += "\t" + inline_blue("phase") + ": " + str(self.phase) + "\n"
        return_str += (
            "\t" + inline_blue("specificity") + ": " + str(self.specificity) + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("architectural-location")
            + ": "
            + str(self.architectural_location)
            + "\n"
        )
        return_str += (
            "\t" + inline_blue("application") + ": " + str(self.application) + "\n"
        )
        return_str += (
            "\t" + inline_blue("subsystem") + ": " + str(self.subsystem) + "\n"
        )
        return_str += "\t" + inline_blue("package") + ": " + str(self.package) + "\n"
        return_str += (
            "\t" + inline_blue("languages") + ": " + str(self.languages) + "\n"
        )
        return_str += (
            "\t" + inline_blue("date-detected") + ": " + str(self.date_detected) + "\n"
        )
        return_str += (
            "\t" + inline_blue("detected-by") + ": " + str(self.detected_by) + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("detected-by-method")
            + ": "
            + str(self.detected_by_method)
            + "\n"
        )
        return_str += (
            "\t" + inline_blue("date-reported") + ": " + str(self.date_reported) + "\n"
        )
        return_str += (
            "\t" + inline_blue("reported-by") + ": " + str(self.reported_by) + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("reported-by-relationship")
            + ": "
            + str(self.reported_by_relationship)
            + "\n"
        )
        return_str += "\t" + inline_blue("issue") + ": " + str(self.issue) + "\n"
        return_str += (
            "\t"
            + inline_blue("reproducibility")
            + ": "
            + str(self.reproducibility)
            + "\n"
        )
        return_str += "\t" + inline_blue("trace") + ": " + str(self.trace) + "\n"
        return_str += (
            "\t" + inline_blue("reproduction") + ": " + str(self.reproduction) + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("reproduction-image")
            + ": "
            + str(self.reproduction_image)
            + "\n"
        )
        # additional_fields - flaw
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "flaw":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "\t"
                            + inline_yellow(key2)
                            + ": "
                            + str(self.additional_fields[key][key2])
                            + "\n"
                        )

        # exploitation
        return_str += inline_green("exploitation") + "\n"
        return_str += (
            "\t"
            + inline_blue("description")
            + ": "
            + str(self.description_exploitation)
            + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("exploitation-image")
            + ": "
            + str(self.exploitation_image)
            + "\n"
        )
        return_str += (
            "\t"
            + inline_blue("exploitation-vector")
            + ": "
            + str(self.exploitation_vector)
            + "\n"
        )
        # additional_fields - exploitation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "exploitation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "\t"
                            + inline_yellow(key2)
                            + ": "
                            + str(self.additional_fields[key][key2])
                            + "\n"
                        )

        # mitigation
        return_str += inline_green("mitigation") + "\n"
        return_str += (
            "\t"
            + inline_blue("description")
            + ": "
            + str(self.description_mitigation)
            + "\n"
        )
        return_str += (
            "\t" + inline_blue("pull-request") + ": " + str(self.pull_request) + "\n"
        )
        if self.date_mitigation:
            return_str += (
                "\t"
                + inline_blue("date-mitigation")
                + ": "
                + str(self.date_mitigation)
                + "\n"
            )
        # additional_fields - mitigation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "mitigation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "\t"
                            + inline_yellow(key2)
                            + ": "
                            + str(self.additional_fields[key][key2])
                            + "\n"
                        )

        # additional_fields (others)
        for key in self.additional_fields.keys():
            if key in [
                "mitigation",
                "exploitation",
                "flaw",
            ]:  # the ones contemplated above with additional_fields
                continue
            if isinstance(self.additional_fields[key], dict):
                return_str += inline_yellow(key) + "\n"
                for key2 in self.additional_fields[key].keys():
                    return_str += (
                        "\t"
                        + inline_yellow(key2)
                        + ": "
                        + str(self.additional_fields[key][key2])
                        + "\n"
                    )
            else:
                return_str += (
                    "\t"
                    + inline_yellow(key2)
                    + ": "
                    + str(self.additional_fields[key])
                    + "\n"
                )

        return return_str

    def markdown(self):
        """
        Return the markdown representation of the flaw

        Thought for generating reports, mainly PDF-based
        """
        # pylint: disable = line-too-long
        return_str = ""
        return_str += "# Vulnerability advisory: " + str(self.title) + "\n"
        return_str += "## General" + "\n"
        return_str += str(self.description) + "\n"
        return_str += "\n"
        return_str += "| Item | Value |" + "\n"
        return_str += "| ---- | ----- |" + "\n"
        return_str += "| RVD ID |" + str(self.id) + "|" + "\n"
        return_str += "| title |" + str(self.title) + "|" + "\n"
        return_str += "| type |" + str(self.type) + "|" + "\n"
        return_str += "| cwe |" + str(self.cwe) + "|" + "\n"
        return_str += "| cve |" + str(self.cve) + "|" + "\n"
        return_str += "| keywords |" + str(self.keywords) + "|" + "\n"
        return_str += "| vendor |" + str(self.vendor) + "|" + "\n"

        return_str += "\n"
        # return_str += "\newpage"

        # severity
        return_str += "## Severity" + "\n"
        return_str += "\n"
        return_str += "| Item | Value |" + "\n"
        return_str += "| ---- | ----- |" + "\n"
        return_str += "| rvss-score | " + str(self.rvss_score) + " |" + "\n"
        return_str += "| rvss-vector | " + str(self.rvss_vector) + " |" + "\n"
        return_str += (
            "| severity-description | " + str(self.severity_description) + " |" + "\n"
        )
        return_str += "| cvss-score | " + str(self.cvss_score) + " |" + "\n"
        return_str += "| cvss-vector | " + str(self.cvss_vector) + " |" + "\n"

        # return_str += "\n"
        return_str += "\\newpage"

        # flaw
        return_str += "## The flaw" + "\n"
        return_str += (
            "This section describes de flaw in more detail and \
captures relevant elements of it. For full understanding of the \
taxonomy used for its categorization, refer to \
[our taxonomy](https://github.com/aliasrobotics/RVD/blob/master/docs/TAXONOMY.md)"
            + "\n"
        )
        return_str += "\n"
        return_str += "| Item | Value |" + "\n"
        return_str += "| ---- | ----- |" + "\n"
        return_str += "| phase | " + str(self.phase) + " |" + "\n"
        return_str += "| specificity | " + str(self.specificity) + " |" + "\n"
        return_str += (
            "| architectural-location | "
            + str(self.architectural_location)
            + " |"
            + "\n"
        )
        return_str += "| application | " + str(self.application) + " |" + "\n"
        return_str += "| subsystem | " + str(self.subsystem) + " |" + "\n"
        return_str += "| package | " + str(self.package) + " |" + "\n"
        return_str += "| languages | " + str(self.languages) + " |" + "\n"
        return_str += "| date-detected | " + str(self.date_detected) + " |" + "\n"
        return_str += "| detected-by | " + str(self.detected_by) + " |" + "\n"
        return_str += (
            "| detected-by-method | " + str(self.detected_by_method) + " |" + "\n"
        )
        return_str += (
            "| date-reported | "
            + str(arrow.utcnow().format("YYYY-MM-DD"))
            + " |"
            + "\n"
        )
        return_str += "| reported-by | " + str(self.reported_by) + " |" + "\n"
        return_str += (
            "| reported-by-relationship | "
            + str(self.reported_by_relationship)
            + " |"
            + "\n"
        )
        return_str += "| issue | " + str(self.issue) + " |" + "\n"
        return_str += "| links | " + str(self.links) + " |" + "\n"
        return_str += "| reproducibility | " + str(self.reproducibility) + " |" + "\n"
        return_str += "| trace | " + str(self.trace) + " |" + "\n"
        return_str += "| reproduction | " + str(self.reproduction) + " |" + "\n"
        return_str += (
            "| reproduction-image | " + str(self.reproduction_image) + " |" + "\n"
        )

        # additional_fields - flaw
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "flaw":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "| "
                            + (key2)
                            + " | "
                            + str(self.additional_fields[key][key2])
                            + " | "
                            + "\n"
                        )

        return_str += "\\newpage" + "\n"

        # exploitation
        return_str += "## Exploitation" + "\n"
        return_str += "\n"
        return_str += "| Item | Value |" + "\n"
        return_str += "| ---- | ----- |" + "\n"
        return_str += (
            "| description | " + str(self.description_exploitation) + "|" + "\n"
        )
        return_str += (
            "| exploitation-image | " + str(self.exploitation_image) + "|" + "\n"
        )
        return_str += (
            "| exploitation-vector | " + str(self.exploitation_vector) + "|" + "\n"
        )
        # additional_fields - exploitation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "exploitation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "| "
                            + (key2)
                            + " | "
                            + str(self.additional_fields[key][key2])
                            + " | "
                            + "\n"
                        )

        return_str += "\\newpage" + "\n"

        # mitigation
        return_str += "## Mitigation" + "\n"
        return_str += "\n"
        return_str += "| Item | Value |" + "\n"
        return_str += "| ---- | ----- |" + "\n"
        return_str += "| description | " + str(self.description_mitigation) + "|" + "\n"
        return_str += "| pull-request | " + str(self.pull_request) + "|" + "\n"
        # additional_fields - mitigation
        for key in self.additional_fields.keys():
            if isinstance(self.additional_fields[key], dict):
                if key == "mitigation":
                    for key2 in self.additional_fields[key].keys():
                        return_str += (
                            "| "
                            + (key2)
                            + " | "
                            + str(self.additional_fields[key][key2])
                            + " | "
                            + "\n"
                        )

        return_str += "\n"

        # # additional_fields (others)
        # return_str += '## Mitigation' + "\n"
        # return_str += "\n"
        # return_str += '| Item | Value |' + "\n"
        # return_str += '| ---- | ----- |' + "\n"
        # for key in self.additional_fields.keys():
        #     if key in ['mitigation', 'exploitation', 'flaw']:  # the ones contemplated above with additional_fields
        #         continue
        #     if isinstance(self.additional_fields[key], dict):
        #         for key2 in self.additional_fields[key].keys():
        #             return_str +="| " + (key2) + " | " + str(self.additional_fields[key][key2]) + " | " + "\n"
        #     else:
        #         return_str +="| " + (key2) + " | " + str(self.additional_fields[key]) + " | " + "\n"
        # return_str += "\n"

        return return_str

    def yml(self):
        """
        Produce YAML machine readable format

        :returns str
        """
        # Deal with datetime issues
        return json.dumps(self.document(), indent=4, default=default)

    def yml_markdown(self):
        """
        Produce YAML machine readable format

        :returns str
        """
        # Deal with datetime issues
        return (
            "```yaml\n"
            + json.dumps(self.document(), indent=4, default=default)
            + "\n```"
        )

    def document(self):
        """
        Return the YAML document of the flaw
        produced on the fly

        :returns dict
        """
        # Deal with datetime issues
        document = {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "description": self.description,
            "cwe": self.cwe,
            "cve": self.cve,
            "keywords": self.keywords,
            "system": self.system,
            "vendor": self.vendor,
            "severity": {
                "rvss-score": self.rvss_score,
                "rvss-vector": self.rvss_vector,
                "severity-description": self.severity_description,
                "cvss-score": self.cvss_score,
                "cvss-vector": self.cvss_vector,
            },
            "links": self.links,
            "flaw": {
                "phase": self.phase,
                "specificity": self.specificity,
                "architectural-location": self.architectural_location,
                "application": self.application,
                "subsystem": self.subsystem,
                "package": self.package,
                "languages": self.languages,
                "date-detected": self.date_detected,
                "detected-by": self.detected_by,
                "detected-by-method": self.detected_by_method,
                "date-reported": self.date_reported,
                "reported-by": self.reported_by,
                "reported-by-relationship": self.reported_by_relationship,
                "issue": self.issue,
                "reproducibility": self.reproducibility,
                "trace": self.trace,
                "reproduction": self.reproduction,
                "reproduction-image": self.reproduction_image,
            },
            "exploitation": {
                "description": self.description_exploitation,
                "exploitation-image": self.exploitation_image,
                "exploitation-vector": self.exploitation_vector,
            },
            "mitigation": {
                "description": self.description_mitigation,
                "pull-request": self.pull_request,
                "date-mitigation": self.date_mitigation,
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

    def document_duplicates(self):
        """
        Return the YAML document of the flaw
        produced on the fly and thought for
        de-duplication, which implies data should be
        serializable.

        :returns dict
        """
        # Deal with datetime issues
        document = {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "description": self.description if self.description != "" else None,
            "cwe": self.cwe,
            "cve": self.cve,
            "keywords": self.keywords,
            "system": self.system,
            "vendor": self.vendor,
            "severity_rvss-score": self.rvss_score,
            "severity_rvss-vector": self.rvss_vector,
            "severity_severity-description": self.severity_description,
            "severity_cvss-score": self.cvss_score,
            "severity_cvss-vector": self.cvss_vector,
            "links": self.links,
            "flaw_phase": self.phase,
            "flaw_specificity": self.specificity,
            "flaw_architectural-location": self.architectural_location,
            "flaw_application": self.application,
            "flaw_subsystem": self.subsystem,
            "flaw_package": self.package,
            "flaw_languages": self.languages,
            "flaw_date-detected": str(self.date_detected),
            "flaw_detected-by": self.detected_by,
            "flaw_detected-by-method": self.detected_by_method,
            "flaw_date-reported": str(self.date_reported),
            "flaw_reported-by": self.reported_by,
            "flaw_reported-by-relationship": self.reported_by_relationship,
            "flaw_issue": self.issue,
            "flaw_reproducibility": self.reproducibility,
            "flaw_trace": self.trace,
            "flaw_reproduction": self.reproduction,
            "flaw_reproduction-image": self.reproduction_image,
            "exploitation_description": self.description_exploitation,
            "exploitation_exploitation-image": self.exploitation_image,
            "exploitation_exploitation-vector": self.exploitation_vector,
            "mitigation_description": self.description_mitigation,
            "mitigation_pull-request": self.pull_request,
        }
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
                print("\t" + str(key) + ": ", end="")
                red("not valid", end="")
                print(": " + str(v.errors[key]))
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

    def export_to_cve(self, filepath, version, mode):
        """
        Export flaw (self) to CVE JSON format in filepath

        :param filepath string, full path of the destiny file
        :param version int, version of CVE JSON, only 4 supported for now
        :param mode string, public, reserved or reject
        :returns None
        """
        if mode != "public":
            raise NotImplementedError

        if version == 4:
            file = open(filepath, "w")
            #########
            # TODO: review in the future this hand implementation
            #########
            file.write("{\n")
            # CVE_data_meta
            file.write('    "CVE_data_meta": {\n')
            file.write('        "ASSIGNER": "cve@aliasrobotics.com",\n')
            file.write(
                '        "DATE_PUBLIC": "'
                + str(arrow.utcnow().format("YYYY-MM-DDTHH:mm:ss ZZ"))
                + '",\n'
            )
            file.write('        "ID": "' + str(self.cve) + '",\n')
            file.write('        "STATE": "PUBLIC",\n')
            file.write('        "TITLE": "' + str(self.title) + '"\n')
            file.write("    },\n")
            # affects
            file.write('    "affects": {\n')
            file.write('        "vendor": {\n')
            file.write('            "vendor_data": [\n')
            file.write("                {\n")
            file.write('                    "product": {\n')
            file.write('                        "product_data": [\n')
            file.write("                            {\n")
            file.write(
                '                                "product_name": "'
                + str(self.system)
                + '",\n'
            )
            file.write('                                "version": {\n')
            file.write('                                    "version_data": [\n')
            file.write("                                        {\n")
            file.write(
                '                                            "version_value": ""\n'
            )
            file.write("                                        }\n")
            file.write("                                    ]\n")
            file.write("                                }\n")
            file.write("                            }\n")
            file.write("                        ]\n")
            file.write("                    },\n")
            file.write(
                '                    "vendor_name": "' + str(self.vendor) + '"\n'
            )
            file.write("                }\n")
            file.write("            ]\n")
            file.write("        }\n")
            file.write("    },\n")

            # credit
            file.write('    "credit": [\n')
            file.write("        {\n")
            file.write('            "lang": "eng",\n')
            file.write('            "value": "' + str(self.detected_by) + '"\n')
            file.write("        }\n")
            file.write("    ],\n")

            # format
            file.write('    "data_format": "MITRE",\n')
            file.write('    "data_type": "CVE",\n')
            file.write('    "data_version": "4.0",\n')

            # description
            file.write('    "description": {\n')
            file.write('        "description_data": [\n')
            file.write("            {\n")
            file.write('                "lang": "eng",\n')
            file.write('                "value": "' + str(self.description) + '"\n')
            file.write("            }\n")
            file.write("        ]\n")
            file.write("    },\n")

            # generator
            file.write('    "generator": {\n')
            file.write('        "engine": "Robot Vulnerability Database (RVD)"\n')
            file.write("    },\n")

            # impact
            file.write('    "impact": {\n')
            file.write('        "cvss": {\n')
            file.write(
                '            "attackComplexity": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "AC"))
                + '",\n'
            )
            file.write(
                '            "attackVector": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "AV"))
                + '",\n'
            )
            file.write(
                '            "availabilityImpact": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "A"))
                + '",\n'
            )
            file.write('            "baseScore": ' + str(self.cvss_score) + ",\n")
            file.write(
                '            "baseSeverity": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "severity"))
                + '",\n'
            )
            file.write(
                '            "confidentialityImpact": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "C"))
                + '",\n'
            )
            file.write(
                '            "integrityImpact": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "I"))
                + '",\n'
            )
            file.write(
                '            "privilegesRequired": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "PR"))
                + '",\n'
            )
            file.write(
                '            "scope": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "S"))
                + '",\n'
            )
            file.write(
                '            "userInteraction": "'
                + str(self.cvss_vector_extract(self.cvss_vector, "UI"))
                + '",\n'
            )
            file.write('            "vectorString": "' + str(self.cvss_vector) + '",\n')
            file.write('            "version": "3.0"\n')
            file.write("        }\n")
            file.write("    },\n")

            # problem-type
            file.write('    "problemtype": {\n')
            file.write('        "problemtype_data": [\n')
            file.write("            {\n")
            file.write('                "description": [\n')
            file.write("                    {\n")
            file.write('                        "lang": "eng",\n')
            file.write('                        "value": "' + str(self.cwe) + '"\n')
            file.write("                    }\n")
            file.write("                ]\n")
            file.write("            }\n")
            file.write("        ]\n")
            file.write("    },\n")

            # references
            file.write('    "references": {\n')
            file.write('    "reference_data": [\n')
            file.write("    {\n")
            file.write(
                '    "name": "https://www.universal-robots.com/how-tos-and-faqs/how-to/ur-how-tos/real-time-data-exchange-rtde-guide/",\n'
            )
            file.write('    "refsource": "CONFIRM",\n')
            file.write(
                '    "url": "https://www.universal-robots.com/how-tos-and-faqs/how-to/ur-how-tos/real-time-data-exchange-rtde-guide/"\n'
            )
            file.write("    }\n")
            file.write("    ]\n")
            file.write("    },    \n")

            # source
            file.write('    "source": {\n')
            file.write('        "defect": [\n')
            file.write('            "RVD#1444"\n')
            file.write("        ],\n")
            file.write('        "discovery": "EXTERNAL"\n')
            file.write("    }\n")

            # end
            file.write("}\n")
            file.close()

        else:
            raise NotImplementedError

    def cvss_vector_extract(self, vector, element):
        """
        This method extracts "element" from "vector" and
        returns it a CVE JSON-familiar format

        :param vector str, the CVSS vector
        :param element str, the element from the CVSS vector we wish to extract
        :returns str
        """
        if not element in self.elements:
            red("Element '" + str(element) + "' not registered")
            sys.exit(1)

        if element == "severity":
            module = detect_vector(vector)
            base, e, c = calculate_vector(vector, module)
            base = float(base)

            if base > 9.0:
                return "critical"
            elif base > 7.0:
                return "high"
            elif base > 4.0:
                return "medium"
            elif base > 0.1:
                return "low"
            else:
                return "none"

        for elem in vector.split("/")[1:]:
            if element is "A":
                if element + ":" in elem:
                    return self.elements_components[elem.split(":")[0]][
                        elem.split(":")[1]
                    ]
            else:
                if element in elem:
                    return self.elements_components[elem.split(":")[0]][
                        elem.split(":")[1]
                    ]
