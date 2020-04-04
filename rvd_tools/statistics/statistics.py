# -*- coding: utf-8 -*-
#
# Alias Robotics S.L.
# https://aliasrobotics.com

"""
Base statistics class

NOTE: Should be specialized by other subclasses that add functionality
"""

from ..database.base import Base
from ..utils import gray, red, green, cyan, yellow
import sys
from tabulate import tabulate
import pprint
from plotly import graph_objs as go

# import plotly.graph_objects as go
import numpy
import arrow
import requests
import bs4
import re


class Statistics(Base):
    """
    Base statistics class
    """

    def __init__(self):
        super().__init__()
        # All
        self.issues = []  # stores the name of each one of the issues
        # Open
        self.issues_open = []  # stores the name of each one of the issues
        # Closed
        self.issues_closed = []  # stores the name of each one of the issues

        self.vulnerabilities = []  # open and closed ones
        self.bugs = []  # open and closed ones
        self.init_issues_and_labels()

    def init_issues_and_labels(self):
        """
        Inits the existing issues in the repo by adding their
        names into the class attribute self.issues

        Removes 'invalid' and 'duplicate' tickets
        """
        cyan("Statistics, initializing tickets...")
        # All
        issues = self.repo.get_issues(state="all")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues.append(issue)

            # Classify as a vunerability or as a bug
            # print(issue)  # debugging purposes
            flaw = self.import_issue(issue.number, issue=issue)
            if "vulnerability" in labels:
                self.vulnerabilities.append(issue)
            elif flaw.type == "vulnerability":
                yellow(
                    "Warning, 'type == vulnerability' but no corresponding label found, classifying as vuln"
                )
                self.vulnerabilities.append(issue)
            else:
                self.bugs.append(issue)

        # Closed
        issues = self.repo.get_issues(state="closed")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues_closed.append(issue)

        # Open
        issues = self.repo.get_issues(state="open")
        for issue in issues:
            labels = [l.name for l in issue.labels]
            if "invalid" in labels:
                continue
            if "duplicate" in labels:
                continue
            self.issues_open.append(issue)

    def statistics_vulnerabilities_historic(self, label, isoption="all"):
        """Produce statististics on the historic discovery and report
        of robot vulnerabilities"""
        cyan("Produce statististics on the historic discovery of flaws...")
        table = None
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            # importer = Base()
            filtered = []
            if isoption == "all":
                issues = self.issues
            elif isoption == "open":
                issues = self.issues_open
            elif isoption == "closed":
                issues = self.issues_closed
            else:
                red("Error, not recognized isoption: " + str(isoption))
                sys.exit(1)

            # fetch the from attributes itself, see above
            # issues = importer.repo.get_issues(state=isoption)
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)

            table = self.historic(filtered)

        else:
            cyan("Using all vulnerabilities...")
            # Consider all tickets, open and close
            table = self.historic(self.vulnerabilities)

        if table:
            print(
                tabulate(
                    table,
                    headers=["ID", "Date reported", "vendor", "CVE", "CVSS", "RVSS"],
                )
            )

    def cvss_vs_rvss(self, label, isoption="all"):
        """Produce statististics on the scoring of vulns while comparing
        two mechanims, CVSS and RVSS"""
        cyan("Produce RVSS and CVSS comparisons...")
        table = None
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            # importer = Base()
            filtered = []
            if isoption == "all":
                issues = self.issues
            elif isoption == "open":
                issues = self.issues_open
            elif isoption == "closed":
                issues = self.issues_closed
            else:
                red("Error, not recognized isoption: " + str(isoption))
                sys.exit(1)

            # fetch the from attributes itself, see above
            # issues = importer.repo.get_issues(state=isoption)
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)

            print(table)
            table = self.historic(filtered)

        else:
            cyan("Using all vulnerabilities...")
            # Consider all tickets, open and close
            table = self.historic(self.vulnerabilities)

        if table:
            print(
                tabulate(
                    table,
                    headers=["ID", "Date reported", "vendor", "CVE", "CVSS", "RVSS"],
                )
            )

    def populate_cwe(self):
        """
        Populate a dictionary of CWE values
        """
        cwes = range(1, 1141)  # range of cwes to consider
        # cwes = range(30, 35)  # range of cwes to consider
        self.cwe_dict = {}
        for i in cwes:
            url = "https://cwe.mitre.org/data/definitions/" + str(i) + ".html"
            try:
                response = requests.get(url)
                soup = bs4.BeautifulSoup(response.text, "lxml")
                # cwe_num = cwe_num_parser(response, soup)
                headerII = soup.select("h2")
                for header in headerII:
                    complete_cwe = header.string
                    # print(complete_cwe)
                    cwe_id = complete_cwe.split(":", 1)[0]
                    cyan(cwe_id)
                    cwe_description = complete_cwe.split(":", 1)[1].strip()
                    # print(cwe_description)
                    pattern = re.compile("^CWE-[0-9][0-9]*.*$")
                    match = pattern.match(complete_cwe)
                    if match:
                        self.cwe_dict[cwe_id] = cwe_description
            except:
                print("[!] Something bad happened")
            # print('-'*25)

        # Add None as well
        self.cwe_dict["None"] = "N/A, generally needs further research"

        # visualize and import it statically
        print(self.cwe_dict)  # for importing it, use beaufiers
        pprint.pprint(self.cwe_dict)  # for visualization

    def populate_cwe_static(self):
        """
        Populates CWE dict using the output of previous method

        This way, we avoid filing tons of requests to CWE's web site
        every time

        NOTE: generated with 'populate_cwe'
        """
        self.cwe_dict = {
            "CWE-5": "J2EE Misconfiguration: Data Transmission Without Encryption",
            "CWE-6": "J2EE Misconfiguration: Insufficient Session-ID Length",
            "CWE-7": "J2EE Misconfiguration: Missing Custom Error Page",
            "CWE-8": "J2EE Misconfiguration: Entity Bean Declared Remote",
            "CWE-9": "J2EE Misconfiguration: Weak Access Permissions for EJB Methods",
            "CWE-11": "ASP.NET Misconfiguration: Creating Debug Binary",
            "CWE-12": "ASP.NET Misconfiguration: Missing Custom Error Page",
            "CWE-13": "ASP.NET Misconfiguration: Password in Configuration File",
            "CWE-14": "Compiler Removal of Code to Clear Buffers",
            "CWE-15": "External Control of System or Configuration Setting",
            "CWE-20": "Improper Input Validation",
            "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "CWE-23": "Relative Path Traversal",
            "CWE-24": "Path Traversal: '../filedir'",
            "CWE-25": "Path Traversal: '/../filedir'",
            "CWE-26": "Path Traversal: '/dir/../filename'",
            "CWE-27": "Path Traversal: 'dir/../../filename'",
            "CWE-28": "Path Traversal: '..\\filedir'",
            "CWE-29": "Path Traversal: '\\..\\filename'",
            "CWE-30": "Path Traversal: '\\dir\\..\\filename'",
            "CWE-31": "Path Traversal: 'dir\\..\\..\\filename'",
            "CWE-32": "Path Traversal: '...' (Triple Dot)",
            "CWE-33": "Path Traversal: '....' (Multiple Dot)",
            "CWE-34": "Path Traversal: '....//'",
            "CWE-35": "Path Traversal: '.../...//'",
            "CWE-36": "Absolute Path Traversal",
            "CWE-37": "Path Traversal: '/absolute/pathname/here'",
            "CWE-38": "Path Traversal: '\\absolute\\pathname\\here'",
            "CWE-39": "Path Traversal: 'C:dirname'",
            "CWE-40": "Path Traversal: '\\\\UNC\\share\\name\\' (Windows UNC Share)",
            "CWE-41": "Improper Resolution of Path Equivalence",
            "CWE-42": "Path Equivalence: 'filename.' (Trailing Dot)",
            "CWE-43": "Path Equivalence: 'filename....' (Multiple Trailing Dot)",
            "CWE-44": "Path Equivalence: 'file.name' (Internal Dot)",
            "CWE-45": "Path Equivalence: 'file...name' (Multiple Internal Dot)",
            "CWE-46": "Path Equivalence: 'filename ' (Trailing Space)",
            "CWE-47": "Path Equivalence: ' filename' (Leading Space)",
            "CWE-48": "Path Equivalence: 'file name' (Internal Whitespace)",
            "CWE-49": "Path Equivalence: 'filename/' (Trailing Slash)",
            "CWE-50": "Path Equivalence: '//multiple/leading/slash'",
            "CWE-51": "Path Equivalence: '/multiple//internal/slash'",
            "CWE-52": "Path Equivalence: '/multiple/trailing/slash//'",
            "CWE-53": "Path Equivalence: '\\multiple\\\\internal\\backslash'",
            "CWE-54": "Path Equivalence: 'filedir\\' (Trailing Backslash)",
            "CWE-55": "Path Equivalence: '/./' (Single Dot Directory)",
            "CWE-56": "Path Equivalence: 'filedir*' (Wildcard)",
            "CWE-57": "Path Equivalence: 'fakedir/../realdir/filename'",
            "CWE-58": "Path Equivalence: Windows 8.3 Filename",
            "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
            "CWE-61": "UNIX Symbolic Link (Symlink) Following",
            "CWE-62": "UNIX Hard Link",
            "CWE-64": "Windows Shortcut Following (.LNK)",
            "CWE-65": "Windows Hard Link",
            "CWE-66": "Improper Handling of File Names that Identify Virtual Resources",
            "CWE-67": "Improper Handling of Windows Device Names",
            "CWE-69": "Improper Handling of Windows ::DATA Alternate Data Stream",
            "CWE-71": "DEPRECATED: Apple '.DS_Store'",
            "CWE-72": "Improper Handling of Apple HFS+ Alternate Data Stream Path",
            "CWE-73": "External Control of File Name or Path",
            "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
            "CWE-75": "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)",
            "CWE-76": "Improper Neutralization of Equivalent Special Elements",
            "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
            "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "CWE-80": "Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
            "CWE-81": "Improper Neutralization of Script in an Error Message Web Page",
            "CWE-82": "Improper Neutralization of Script in Attributes of IMG Tags in a Web Page",
            "CWE-83": "Improper Neutralization of Script in Attributes in a Web Page",
            "CWE-84": "Improper Neutralization of Encoded URI Schemes in a Web Page",
            "CWE-85": "Doubled Character XSS Manipulations",
            "CWE-86": "Improper Neutralization of Invalid Characters in Identifiers in Web Pages",
            "CWE-87": "Improper Neutralization of Alternate XSS Syntax",
            "CWE-88": "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')",
            "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
            "CWE-91": "XML Injection (aka Blind XPath Injection)",
            "CWE-92": "DEPRECATED: Improper Sanitization of Custom Special Characters",
            "CWE-93": "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
            "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
            "CWE-95": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
            "CWE-96": "Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')",
            "CWE-97": "Improper Neutralization of Server-Side Includes (SSI) Within a Web Page",
            "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')",
            "CWE-99": "Improper Control of Resource Identifiers ('Resource Injection')",
            "CWE-102": "Struts: Duplicate Validation Forms",
            "CWE-103": "Struts: Incomplete validate() Method Definition",
            "CWE-104": "Struts: Form Bean Does Not Extend Validation Class",
            "CWE-105": "Struts: Form Field Without Validator",
            "CWE-106": "Struts: Plug-in Framework not in Use",
            "CWE-107": "Struts: Unused Validation Form",
            "CWE-108": "Struts: Unvalidated Action Form",
            "CWE-109": "Struts: Validator Turned Off",
            "CWE-110": "Struts: Validator Without Form Field",
            "CWE-111": "Direct Use of Unsafe JNI",
            "CWE-112": "Missing XML Validation",
            "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
            "CWE-114": "Process Control",
            "CWE-115": "Misinterpretation of Input",
            "CWE-116": "Improper Encoding or Escaping of Output",
            "CWE-117": "Improper Output Neutralization for Logs",
            "CWE-118": "Incorrect Access of Indexable Resource ('Range Error')",
            "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
            "CWE-121": "Stack-based Buffer Overflow",
            "CWE-122": "Heap-based Buffer Overflow",
            "CWE-123": "Write-what-where Condition",
            "CWE-124": "Buffer Underwrite ('Buffer Underflow')",
            "CWE-125": "Out-of-bounds Read",
            "CWE-126": "Buffer Over-read",
            "CWE-127": "Buffer Under-read",
            "CWE-128": "Wrap-around Error",
            "CWE-129": "Improper Validation of Array Index",
            "CWE-130": "Improper Handling of Length Parameter Inconsistency",
            "CWE-131": "Incorrect Calculation of Buffer Size",
            "CWE-132": "DEPRECATED (Duplicate): Miscalculated Null Termination",
            "CWE-134": "Use of Externally-Controlled Format String",
            "CWE-135": "Incorrect Calculation of Multi-Byte String Length",
            "CWE-138": "Improper Neutralization of Special Elements",
            "CWE-140": "Improper Neutralization of Delimiters",
            "CWE-141": "Improper Neutralization of Parameter/Argument Delimiters",
            "CWE-142": "Improper Neutralization of Value Delimiters",
            "CWE-143": "Improper Neutralization of Record Delimiters",
            "CWE-144": "Improper Neutralization of Line Delimiters",
            "CWE-145": "Improper Neutralization of Section Delimiters",
            "CWE-146": "Improper Neutralization of Expression/Command Delimiters",
            "CWE-147": "Improper Neutralization of Input Terminators",
            "CWE-148": "Improper Neutralization of Input Leaders",
            "CWE-149": "Improper Neutralization of Quoting Syntax",
            "CWE-150": "Improper Neutralization of Escape, Meta, or Control Sequences",
            "CWE-151": "Improper Neutralization of Comment Delimiters",
            "CWE-152": "Improper Neutralization of Macro Symbols",
            "CWE-153": "Improper Neutralization of Substitution Characters",
            "CWE-154": "Improper Neutralization of Variable Name Delimiters",
            "CWE-155": "Improper Neutralization of Wildcards or Matching Symbols",
            "CWE-156": "Improper Neutralization of Whitespace",
            "CWE-157": "Failure to Sanitize Paired Delimiters",
            "CWE-158": "Improper Neutralization of Null Byte or NUL Character",
            "CWE-159": "Failure to Sanitize Special Element",
            "CWE-160": "Improper Neutralization of Leading Special Elements",
            "CWE-161": "Improper Neutralization of Multiple Leading Special Elements",
            "CWE-162": "Improper Neutralization of Trailing Special Elements",
            "CWE-163": "Improper Neutralization of Multiple Trailing Special Elements",
            "CWE-164": "Improper Neutralization of Internal Special Elements",
            "CWE-165": "Improper Neutralization of Multiple Internal Special Elements",
            "CWE-166": "Improper Handling of Missing Special Element",
            "CWE-167": "Improper Handling of Additional Special Element",
            "CWE-168": "Improper Handling of Inconsistent Special Elements",
            "CWE-170": "Improper Null Termination",
            "CWE-172": "Encoding Error",
            "CWE-173": "Improper Handling of Alternate Encoding",
            "CWE-174": "Double Decoding of the Same Data",
            "CWE-175": "Improper Handling of Mixed Encoding",
            "CWE-176": "Improper Handling of Unicode Encoding",
            "CWE-177": "Improper Handling of URL Encoding (Hex Encoding)",
            "CWE-178": "Improper Handling of Case Sensitivity",
            "CWE-179": "Incorrect Behavior Order: Early Validation",
            "CWE-180": "Incorrect Behavior Order: Validate Before Canonicalize",
            "CWE-181": "Incorrect Behavior Order: Validate Before Filter",
            "CWE-182": "Collapse of Data into Unsafe Value",
            "CWE-183": "Permissive Whitelist",
            "CWE-184": "Incomplete Blacklist",
            "CWE-185": "Incorrect Regular Expression",
            "CWE-186": "Overly Restrictive Regular Expression",
            "CWE-187": "Partial String Comparison",
            "CWE-188": "Reliance on Data/Memory Layout",
            "CWE-190": "Integer Overflow or Wraparound",
            "CWE-191": "Integer Underflow (Wrap or Wraparound)",
            "CWE-192": "Integer Coercion Error",
            "CWE-193": "Off-by-one Error",
            "CWE-194": "Unexpected Sign Extension",
            "CWE-195": "Signed to Unsigned Conversion Error",
            "CWE-196": "Unsigned to Signed Conversion Error",
            "CWE-197": "Numeric Truncation Error",
            "CWE-198": "Use of Incorrect Byte Ordering",
            "CWE-200": "Information Exposure",
            "CWE-201": "Information Exposure Through Sent Data",
            "CWE-202": "Exposure of Sensitive Data Through Data Queries",
            "CWE-203": "Information Exposure Through Discrepancy",
            "CWE-204": "Response Discrepancy Information Exposure",
            "CWE-205": "Information Exposure Through Behavioral Discrepancy",
            "CWE-206": "Information Exposure of Internal State Through Behavioral Inconsistency",
            "CWE-207": "Information Exposure Through an External Behavioral Inconsistency",
            "CWE-208": "Information Exposure Through Timing Discrepancy",
            "CWE-209": "Information Exposure Through an Error Message",
            "CWE-210": "Information Exposure Through Self-generated Error Message",
            "CWE-211": "Information Exposure Through Externally-Generated Error Message",
            "CWE-212": "Improper Cross-boundary Removal of Sensitive Data",
            "CWE-213": "Intentional Information Exposure",
            "CWE-214": "Information Exposure Through Process Environment",
            "CWE-215": "Information Exposure Through Debug Information",
            "CWE-216": "Containment Errors (Container Errors)",
            "CWE-217": "DEPRECATED: Failure to Protect Stored Data from Modification",
            "CWE-218": "DEPRECATED (Duplicate): Failure to provide confidentiality for stored data",
            "CWE-219": "Sensitive Data Under Web Root",
            "CWE-220": "Sensitive Data Under FTP Root",
            "CWE-221": "Information Loss or Omission",
            "CWE-222": "Truncation of Security-relevant Information",
            "CWE-223": "Omission of Security-relevant Information",
            "CWE-224": "Obscured Security-relevant Information by Alternate Name",
            "CWE-225": "DEPRECATED (Duplicate): General Information Management Problems",
            "CWE-226": "Sensitive Information Uncleared Before Release",
            "CWE-228": "Improper Handling of Syntactically Invalid Structure",
            "CWE-229": "Improper Handling of Values",
            "CWE-230": "Improper Handling of Missing Values",
            "CWE-231": "Improper Handling of Extra Values",
            "CWE-232": "Improper Handling of Undefined Values",
            "CWE-233": "Improper Handling of Parameters",
            "CWE-234": "Failure to Handle Missing Parameter",
            "CWE-235": "Improper Handling of Extra Parameters",
            "CWE-236": "Improper Handling of Undefined Parameters",
            "CWE-237": "Improper Handling of Structural Elements",
            "CWE-238": "Improper Handling of Incomplete Structural Elements",
            "CWE-239": "Failure to Handle Incomplete Element",
            "CWE-240": "Improper Handling of Inconsistent Structural Elements",
            "CWE-241": "Improper Handling of Unexpected Data Type",
            "CWE-242": "Use of Inherently Dangerous Function",
            "CWE-243": "Creation of chroot Jail Without Changing Working Directory",
            "CWE-244": "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
            "CWE-245": "J2EE Bad Practices: Direct Management of Connections",
            "CWE-246": "J2EE Bad Practices: Direct Use of Sockets",
            "CWE-247": "DEPRECATED (Duplicate): Reliance on DNS Lookups in a Security Decision",
            "CWE-248": "Uncaught Exception",
            "CWE-249": "DEPRECATED: Often Misused: Path Manipulation",
            "CWE-250": "Execution with Unnecessary Privileges",
            "CWE-252": "Unchecked Return Value",
            "CWE-253": "Incorrect Check of Function Return Value",
            "CWE-256": "Unprotected Storage of Credentials",
            "CWE-257": "Storing Passwords in a Recoverable Format",
            "CWE-258": "Empty Password in Configuration File",
            "CWE-259": "Use of Hard-coded Password",
            "CWE-260": "Password in Configuration File",
            "CWE-261": "Weak Cryptography for Passwords",
            "CWE-262": "Not Using Password Aging",
            "CWE-263": "Password Aging with Long Expiration",
            "CWE-266": "Incorrect Privilege Assignment",
            "CWE-267": "Privilege Defined With Unsafe Actions",
            "CWE-268": "Privilege Chaining",
            "CWE-269": "Improper Privilege Management",
            "CWE-270": "Privilege Context Switching Error",
            "CWE-271": "Privilege Dropping / Lowering Errors",
            "CWE-272": "Least Privilege Violation",
            "CWE-273": "Improper Check for Dropped Privileges",
            "CWE-274": "Improper Handling of Insufficient Privileges",
            "CWE-276": "Incorrect Default Permissions",
            "CWE-277": "Insecure Inherited Permissions",
            "CWE-278": "Insecure Preserved Inherited Permissions",
            "CWE-279": "Incorrect Execution-Assigned Permissions",
            "CWE-280": "Improper Handling of Insufficient Permissions or Privileges",
            "CWE-281": "Improper Preservation of Permissions",
            "CWE-282": "Improper Ownership Management",
            "CWE-283": "Unverified Ownership",
            "CWE-284": "Improper Access Control",
            "CWE-285": "Improper Authorization",
            "CWE-286": "Incorrect User Management",
            "CWE-287": "Improper Authentication",
            "CWE-288": "Authentication Bypass Using an Alternate Path or Channel",
            "CWE-289": "Authentication Bypass by Alternate Name",
            "CWE-290": "Authentication Bypass by Spoofing",
            "CWE-291": "Reliance on IP Address for Authentication",
            "CWE-292": "DEPRECATED (Duplicate): Trusting Self-reported DNS Name",
            "CWE-293": "Using Referer Field for Authentication",
            "CWE-294": "Authentication Bypass by Capture-replay",
            "CWE-295": "Improper Certificate Validation",
            "CWE-296": "Improper Following of a Certificate's Chain of Trust",
            "CWE-297": "Improper Validation of Certificate with Host Mismatch",
            "CWE-298": "Improper Validation of Certificate Expiration",
            "CWE-299": "Improper Check for Certificate Revocation",
            "CWE-300": "Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
            "CWE-301": "Reflection Attack in an Authentication Protocol",
            "CWE-302": "Authentication Bypass by Assumed-Immutable Data",
            "CWE-303": "Incorrect Implementation of Authentication Algorithm",
            "CWE-304": "Missing Critical Step in Authentication",
            "CWE-305": "Authentication Bypass by Primary Weakness",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
            "CWE-308": "Use of Single-factor Authentication",
            "CWE-309": "Use of Password System for Primary Authentication",
            "CWE-311": "Missing Encryption of Sensitive Data",
            "CWE-312": "Cleartext Storage of Sensitive Information",
            "CWE-313": "Cleartext Storage in a File or on Disk",
            "CWE-314": "Cleartext Storage in the Registry",
            "CWE-315": "Cleartext Storage of Sensitive Information in a Cookie",
            "CWE-316": "Cleartext Storage of Sensitive Information in Memory",
            "CWE-317": "Cleartext Storage of Sensitive Information in GUI",
            "CWE-318": "Cleartext Storage of Sensitive Information in Executable",
            "CWE-319": "Cleartext Transmission of Sensitive Information",
            "CWE-321": "Use of Hard-coded Cryptographic Key",
            "CWE-322": "Key Exchange without Entity Authentication",
            "CWE-323": "Reusing a Nonce, Key Pair in Encryption",
            "CWE-324": "Use of a Key Past its Expiration Date",
            "CWE-325": "Missing Required Cryptographic Step",
            "CWE-326": "Inadequate Encryption Strength",
            "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-328": "Reversible One-Way Hash",
            "CWE-329": "Not Using a Random IV with CBC Mode",
            "CWE-330": "Use of Insufficiently Random Values",
            "CWE-331": "Insufficient Entropy",
            "CWE-332": "Insufficient Entropy in PRNG",
            "CWE-333": "Improper Handling of Insufficient Entropy in TRNG",
            "CWE-334": "Small Space of Random Values",
            "CWE-335": "Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)",
            "CWE-336": "Same Seed in Pseudo-Random Number Generator (PRNG)",
            "CWE-337": "Predictable Seed in Pseudo-Random Number Generator (PRNG)",
            "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
            "CWE-339": "Small Seed Space in PRNG",
            "CWE-340": "Predictability Problems",
            "CWE-341": "Predictable from Observable State",
            "CWE-342": "Predictable Exact Value from Previous Values",
            "CWE-343": "Predictable Value Range from Previous Values",
            "CWE-344": "Use of Invariant Value in Dynamically Changing Context",
            "CWE-345": "Insufficient Verification of Data Authenticity",
            "CWE-346": "Origin Validation Error",
            "CWE-347": "Improper Verification of Cryptographic Signature",
            "CWE-348": "Use of Less Trusted Source",
            "CWE-349": "Acceptance of Extraneous Untrusted Data With Trusted Data",
            "CWE-350": "Reliance on Reverse DNS Resolution for a Security-Critical Action",
            "CWE-351": "Insufficient Type Distinction",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-353": "Missing Support for Integrity Check",
            "CWE-354": "Improper Validation of Integrity Check Value",
            "CWE-356": "Product UI does not Warn User of Unsafe Actions",
            "CWE-357": "Insufficient UI Warning of Dangerous Operations",
            "CWE-358": "Improperly Implemented Security Check for Standard",
            "CWE-359": "Exposure of Private Information ('Privacy Violation')",
            "CWE-360": "Trust of System Event Data",
            "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
            "CWE-363": "Race Condition Enabling Link Following",
            "CWE-364": "Signal Handler Race Condition",
            "CWE-365": "Race Condition in Switch",
            "CWE-366": "Race Condition within a Thread",
            "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
            "CWE-368": "Context Switching Race Condition",
            "CWE-369": "Divide By Zero",
            "CWE-370": "Missing Check for Certificate Revocation after Initial Check",
            "CWE-372": "Incomplete Internal State Distinction",
            "CWE-373": "DEPRECATED: State Synchronization Error",
            "CWE-374": "Passing Mutable Objects to an Untrusted Method",
            "CWE-375": "Returning a Mutable Object to an Untrusted Caller",
            "CWE-377": "Insecure Temporary File",
            "CWE-378": "Creation of Temporary File With Insecure Permissions",
            "CWE-379": "Creation of Temporary File in Directory with Incorrect Permissions",
            "CWE-382": "J2EE Bad Practices: Use of System.exit()",
            "CWE-383": "J2EE Bad Practices: Direct Use of Threads",
            "CWE-384": "Session Fixation",
            "CWE-385": "Covert Timing Channel",
            "CWE-386": "Symbolic Name not Mapping to Correct Object",
            "CWE-390": "Detection of Error Condition Without Action",
            "CWE-391": "Unchecked Error Condition",
            "CWE-392": "Missing Report of Error Condition",
            "CWE-393": "Return of Wrong Status Code",
            "CWE-394": "Unexpected Status Code or Return Value",
            "CWE-395": "Use of NullPointerException Catch to Detect NULL Pointer Dereference",
            "CWE-396": "Declaration of Catch for Generic Exception",
            "CWE-397": "Declaration of Throws for Generic Exception",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-401": "Missing Release of Memory after Effective Lifetime",
            "CWE-402": "Transmission of Private Resources into a New Sphere ('Resource Leak')",
            "CWE-403": "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
            "CWE-404": "Improper Resource Shutdown or Release",
            "CWE-405": "Asymmetric Resource Consumption (Amplification)",
            "CWE-406": "Insufficient Control of Network Message Volume (Network Amplification)",
            "CWE-407": "Inefficient Algorithmic Complexity",
            "CWE-408": "Incorrect Behavior Order: Early Amplification",
            "CWE-409": "Improper Handling of Highly Compressed Data (Data Amplification)",
            "CWE-410": "Insufficient Resource Pool",
            "CWE-412": "Unrestricted Externally Accessible Lock",
            "CWE-413": "Improper Resource Locking",
            "CWE-414": "Missing Lock Check",
            "CWE-415": "Double Free",
            "CWE-416": "Use After Free",
            "CWE-419": "Unprotected Primary Channel",
            "CWE-420": "Unprotected Alternate Channel",
            "CWE-421": "Race Condition During Access to Alternate Channel",
            "CWE-422": "Unprotected Windows Messaging Channel ('Shatter')",
            "CWE-423": "DEPRECATED (Duplicate): Proxied Trusted Channel",
            "CWE-424": "Improper Protection of Alternate Path",
            "CWE-425": "Direct Request ('Forced Browsing')",
            "CWE-426": "Untrusted Search Path",
            "CWE-427": "Uncontrolled Search Path Element",
            "CWE-428": "Unquoted Search Path or Element",
            "CWE-430": "Deployment of Wrong Handler",
            "CWE-431": "Missing Handler",
            "CWE-432": "Dangerous Signal Handler not Disabled During Sensitive Operations",
            "CWE-433": "Unparsed Raw Web Content Delivery",
            "CWE-434": "Unrestricted Upload of File with Dangerous Type",
            "CWE-435": "Improper Interaction Between Multiple Correctly-Behaving Entities",
            "CWE-436": "Interpretation Conflict",
            "CWE-437": "Incomplete Model of Endpoint Features",
            "CWE-439": "Behavioral Change in New Version or Environment",
            "CWE-440": "Expected Behavior Violation",
            "CWE-441": "Unintended Proxy or Intermediary ('Confused Deputy')",
            "CWE-443": "DEPRECATED (Duplicate): HTTP response splitting",
            "CWE-444": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
            "CWE-446": "UI Discrepancy for Security Feature",
            "CWE-447": "Unimplemented or Unsupported Feature in UI",
            "CWE-448": "Obsolete Feature in UI",
            "CWE-449": "The UI Performs the Wrong Action",
            "CWE-450": "Multiple Interpretations of UI Input",
            "CWE-451": "User Interface (UI) Misrepresentation of Critical Information",
            "CWE-453": "Insecure Default Variable Initialization",
            "CWE-454": "External Initialization of Trusted Variables or Data Stores",
            "CWE-455": "Non-exit on Failed Initialization",
            "CWE-456": "Missing Initialization of a Variable",
            "CWE-457": "Use of Uninitialized Variable",
            "CWE-458": "DEPRECATED: Incorrect Initialization",
            "CWE-459": "Incomplete Cleanup",
            "CWE-460": "Improper Cleanup on Thrown Exception",
            "CWE-462": "Duplicate Key in Associative List (Alist)",
            "CWE-463": "Deletion of Data Structure Sentinel",
            "CWE-464": "Addition of Data Structure Sentinel",
            "CWE-466": "Return of Pointer Value Outside of Expected Range",
            "CWE-467": "Use of sizeof() on a Pointer Type",
            "CWE-468": "Incorrect Pointer Scaling",
            "CWE-469": "Use of Pointer Subtraction to Determine Size",
            "CWE-470": "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
            "CWE-471": "Modification of Assumed-Immutable Data (MAID)",
            "CWE-472": "External Control of Assumed-Immutable Web Parameter",
            "CWE-473": "PHP External Variable Modification",
            "CWE-474": "Use of Function with Inconsistent Implementations",
            "CWE-475": "Undefined Behavior for Input to API",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-477": "Use of Obsolete Function",
            "CWE-478": "Missing Default Case in Switch Statement",
            "CWE-479": "Signal Handler Use of a Non-reentrant Function",
            "CWE-480": "Use of Incorrect Operator",
            "CWE-481": "Assigning instead of Comparing",
            "CWE-482": "Comparing instead of Assigning",
            "CWE-483": "Incorrect Block Delimitation",
            "CWE-484": "Omitted Break Statement in Switch",
            "CWE-486": "Comparison of Classes by Name",
            "CWE-487": "Reliance on Package-level Scope",
            "CWE-488": "Exposure of Data Element to Wrong Session",
            "CWE-489": "Leftover Debug Code",
            "CWE-491": "Public cloneable() Method Without Final ('Object Hijack')",
            "CWE-492": "Use of Inner Class Containing Sensitive Data",
            "CWE-493": "Critical Public Variable Without Final Modifier",
            "CWE-494": "Download of Code Without Integrity Check",
            "CWE-495": "Private Data Structure Returned From A Public Method",
            "CWE-496": "Public Data Assigned to Private Array-Typed Field",
            "CWE-497": "Exposure of System Data to an Unauthorized Control Sphere",
            "CWE-498": "Cloneable Class Containing Sensitive Information",
            "CWE-499": "Serializable Class Containing Sensitive Data",
            "CWE-500": "Public Static Field Not Marked Final",
            "CWE-501": "Trust Boundary Violation",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-506": "Embedded Malicious Code",
            "CWE-507": "Trojan Horse",
            "CWE-508": "Non-Replicating Malicious Code",
            "CWE-509": "Replicating Malicious Code (Virus or Worm)",
            "CWE-510": "Trapdoor",
            "CWE-511": "Logic/Time Bomb",
            "CWE-512": "Spyware",
            "CWE-514": "Covert Channel",
            "CWE-515": "Covert Storage Channel",
            "CWE-516": "DEPRECATED (Duplicate): Covert Timing Channel",
            "CWE-520": ".NET Misconfiguration: Use of Impersonation",
            "CWE-521": "Weak Password Requirements",
            "CWE-522": "Insufficiently Protected Credentials",
            "CWE-523": "Unprotected Transport of Credentials",
            "CWE-524": "Information Exposure Through Caching",
            "CWE-525": "Information Exposure Through Browser Caching",
            "CWE-526": "Information Exposure Through Environmental Variables",
            "CWE-527": "Exposure of CVS Repository to an Unauthorized Control Sphere",
            "CWE-528": "Exposure of Core Dump File to an Unauthorized Control Sphere",
            "CWE-529": "Exposure of Access Control List Files to an Unauthorized Control Sphere",
            "CWE-530": "Exposure of Backup File to an Unauthorized Control Sphere",
            "CWE-531": "Information Exposure Through Test Code",
            "CWE-532": "Inclusion of Sensitive Information in Log Files",
            "CWE-533": "DEPRECATED: Information Exposure Through Server Log Files",
            "CWE-534": "DEPRECATED: Information Exposure Through Debug Log Files",
            "CWE-535": "Information Exposure Through Shell Error Message",
            "CWE-536": "Information Exposure Through Servlet Runtime Error Message",
            "CWE-537": "Information Exposure Through Java Runtime Error Message",
            "CWE-538": "File and Directory Information Exposure",
            "CWE-539": "Information Exposure Through Persistent Cookies",
            "CWE-540": "Information Exposure Through Source Code",
            "CWE-541": "Information Exposure Through Include Source Code",
            "CWE-542": "DEPRECATED: Information Exposure Through Cleanup Log Files",
            "CWE-543": "Use of Singleton Pattern Without Synchronization in a Multithreaded Context",
            "CWE-544": "Missing Standardized Error Handling Mechanism",
            "CWE-545": "DEPRECATED: Use of Dynamic Class Loading",
            "CWE-546": "Suspicious Comment",
            "CWE-547": "Use of Hard-coded, Security-relevant Constants",
            "CWE-548": "Information Exposure Through Directory Listing",
            "CWE-549": "Missing Password Field Masking",
            "CWE-550": "Information Exposure Through Server Error Message",
            "CWE-551": "Incorrect Behavior Order: Authorization Before Parsing and Canonicalization",
            "CWE-552": "Files or Directories Accessible to External Parties",
            "CWE-553": "Command Shell in Externally Accessible Directory",
            "CWE-554": "ASP.NET Misconfiguration: Not Using Input Validation Framework",
            "CWE-555": "J2EE Misconfiguration: Plaintext Password in Configuration File",
            "CWE-556": "ASP.NET Misconfiguration: Use of Identity Impersonation",
            "CWE-558": "Use of getlogin() in Multithreaded Application",
            "CWE-560": "Use of umask() with chmod-style Argument",
            "CWE-561": "Dead Code",
            "CWE-562": "Return of Stack Variable Address",
            "CWE-563": "Assignment to Variable without Use",
            "CWE-564": "SQL Injection: Hibernate",
            "CWE-565": "Reliance on Cookies without Validation and Integrity Checking",
            "CWE-566": "Authorization Bypass Through User-Controlled SQL Primary Key",
            "CWE-567": "Unsynchronized Access to Shared Data in a Multithreaded Context",
            "CWE-568": "finalize() Method Without super.finalize()",
            "CWE-570": "Expression is Always False",
            "CWE-571": "Expression is Always True",
            "CWE-572": "Call to Thread run() instead of start()",
            "CWE-573": "Improper Following of Specification by Caller",
            "CWE-574": "EJB Bad Practices: Use of Synchronization Primitives",
            "CWE-575": "EJB Bad Practices: Use of AWT Swing",
            "CWE-576": "EJB Bad Practices: Use of Java I/O",
            "CWE-577": "EJB Bad Practices: Use of Sockets",
            "CWE-578": "EJB Bad Practices: Use of Class Loader",
            "CWE-579": "J2EE Bad Practices: Non-serializable Object Stored in Session",
            "CWE-580": "clone() Method Without super.clone()",
            "CWE-581": "Object Model Violation: Just One of Equals and Hashcode Defined",
            "CWE-582": "Array Declared Public, Final, and Static",
            "CWE-583": "finalize() Method Declared Public",
            "CWE-584": "Return Inside Finally Block",
            "CWE-585": "Empty Synchronized Block",
            "CWE-586": "Explicit Call to Finalize()",
            "CWE-587": "Assignment of a Fixed Address to a Pointer",
            "CWE-588": "Attempt to Access Child of a Non-structure Pointer",
            "CWE-589": "Call to Non-ubiquitous API",
            "CWE-590": "Free of Memory not on the Heap",
            "CWE-591": "Sensitive Data Storage in Improperly Locked Memory",
            "CWE-592": "DEPRECATED: Authentication Bypass Issues",
            "CWE-593": "Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created",
            "CWE-594": "J2EE Framework: Saving Unserializable Objects to Disk",
            "CWE-595": "Comparison of Object References Instead of Object Contents",
            "CWE-596": "DEPRECATED: Incorrect Semantic Object Comparison",
            "CWE-597": "Use of Wrong Operator in String Comparison",
            "CWE-598": "Information Exposure Through Query Strings in GET Request",
            "CWE-599": "Missing Validation of OpenSSL Certificate",
            "CWE-600": "Uncaught Exception in Servlet",
            "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
            "CWE-602": "Client-Side Enforcement of Server-Side Security",
            "CWE-603": "Use of Client-Side Authentication",
            "CWE-605": "Multiple Binds to the Same Port",
            "CWE-606": "Unchecked Input for Loop Condition",
            "CWE-607": "Public Static Final Field References Mutable Object",
            "CWE-608": "Struts: Non-private Field in ActionForm Class",
            "CWE-609": "Double-Checked Locking",
            "CWE-610": "Externally Controlled Reference to a Resource in Another Sphere",
            "CWE-611": "Improper Restriction of XML External Entity Reference",
            "CWE-612": "Information Exposure Through Indexing of Private Data",
            "CWE-613": "Insufficient Session Expiration",
            "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            "CWE-615": "Information Exposure Through Comments",
            "CWE-616": "Incomplete Identification of Uploaded File Variables (PHP)",
            "CWE-617": "Reachable Assertion",
            "CWE-618": "Exposed Unsafe ActiveX Method",
            "CWE-619": "Dangling Database Cursor ('Cursor Injection')",
            "CWE-620": "Unverified Password Change",
            "CWE-621": "Variable Extraction Error",
            "CWE-622": "Improper Validation of Function Hook Arguments",
            "CWE-623": "Unsafe ActiveX Control Marked Safe For Scripting",
            "CWE-624": "Executable Regular Expression Error",
            "CWE-625": "Permissive Regular Expression",
            "CWE-626": "Null Byte Interaction Error (Poison Null Byte)",
            "CWE-627": "Dynamic Variable Evaluation",
            "CWE-628": "Function Call with Incorrectly Specified Arguments",
            "CWE-636": "Not Failing Securely ('Failing Open')",
            "CWE-637": "Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')",
            "CWE-638": "Not Using Complete Mediation",
            "CWE-639": "Authorization Bypass Through User-Controlled Key",
            "CWE-640": "Weak Password Recovery Mechanism for Forgotten Password",
            "CWE-641": "Improper Restriction of Names for Files and Other Resources",
            "CWE-642": "External Control of Critical State Data",
            "CWE-643": "Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
            "CWE-644": "Improper Neutralization of HTTP Headers for Scripting Syntax",
            "CWE-645": "Overly Restrictive Account Lockout Mechanism",
            "CWE-646": "Reliance on File Name or Extension of Externally-Supplied File",
            "CWE-647": "Use of Non-Canonical URL Paths for Authorization Decisions",
            "CWE-648": "Incorrect Use of Privileged APIs",
            "CWE-649": "Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking",
            "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
            "CWE-651": "Information Exposure Through WSDL File",
            "CWE-652": "Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')",
            "CWE-653": "Insufficient Compartmentalization",
            "CWE-654": "Reliance on a Single Factor in a Security Decision",
            "CWE-655": "Insufficient Psychological Acceptability",
            "CWE-656": "Reliance on Security Through Obscurity",
            "CWE-657": "Violation of Secure Design Principles",
            "CWE-662": "Improper Synchronization",
            "CWE-663": "Use of a Non-reentrant Function in a Concurrent Context",
            "CWE-664": "Improper Control of a Resource Through its Lifetime",
            "CWE-665": "Improper Initialization",
            "CWE-666": "Operation on Resource in Wrong Phase of Lifetime",
            "CWE-667": "Improper Locking",
            "CWE-668": "Exposure of Resource to Wrong Sphere",
            "CWE-669": "Incorrect Resource Transfer Between Spheres",
            "CWE-670": "Always-Incorrect Control Flow Implementation",
            "CWE-671": "Lack of Administrator Control over Security",
            "CWE-672": "Operation on a Resource after Expiration or Release",
            "CWE-673": "External Influence of Sphere Definition",
            "CWE-674": "Uncontrolled Recursion",
            "CWE-675": "Duplicate Operations on Resource",
            "CWE-676": "Use of Potentially Dangerous Function",
            "CWE-680": "Integer Overflow to Buffer Overflow",
            "CWE-681": "Incorrect Conversion between Numeric Types",
            "CWE-682": "Incorrect Calculation",
            "CWE-683": "Function Call With Incorrect Order of Arguments",
            "CWE-684": "Incorrect Provision of Specified Functionality",
            "CWE-685": "Function Call With Incorrect Number of Arguments",
            "CWE-686": "Function Call With Incorrect Argument Type",
            "CWE-687": "Function Call With Incorrectly Specified Argument Value",
            "CWE-688": "Function Call With Incorrect Variable or Reference as Argument",
            "CWE-689": "Permission Race Condition During Resource Copy",
            "CWE-690": "Unchecked Return Value to NULL Pointer Dereference",
            "CWE-691": "Insufficient Control Flow Management",
            "CWE-692": "Incomplete Blacklist to Cross-Site Scripting",
            "CWE-693": "Protection Mechanism Failure",
            "CWE-694": "Use of Multiple Resources with Duplicate Identifier",
            "CWE-695": "Use of Low-Level Functionality",
            "CWE-696": "Incorrect Behavior Order",
            "CWE-697": "Incorrect Comparison",
            "CWE-698": "Execution After Redirect (EAR)",
            "CWE-703": "Improper Check or Handling of Exceptional Conditions",
            "CWE-704": "Incorrect Type Conversion or Cast",
            "CWE-705": "Incorrect Control Flow Scoping",
            "CWE-706": "Use of Incorrectly-Resolved Name or Reference",
            "CWE-707": "Improper Enforcement of Message or Data Structure",
            "CWE-708": "Incorrect Ownership Assignment",
            "CWE-710": "Improper Adherence to Coding Standards",
            "CWE-732": "Incorrect Permission Assignment for Critical Resource",
            "CWE-733": "Compiler Optimization Removal or Modification of Security-critical Code",
            "CWE-749": "Exposed Dangerous Method or Function",
            "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
            "CWE-755": "Improper Handling of Exceptional Conditions",
            "CWE-756": "Missing Custom Error Page",
            "CWE-757": "Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')",
            "CWE-758": "Reliance on Undefined, Unspecified, or Implementation-Defined Behavior",
            "CWE-759": "Use of a One-Way Hash without a Salt",
            "CWE-760": "Use of a One-Way Hash with a Predictable Salt",
            "CWE-761": "Free of Pointer not at Start of Buffer",
            "CWE-762": "Mismatched Memory Management Routines",
            "CWE-763": "Release of Invalid Pointer or Reference",
            "CWE-764": "Multiple Locks of a Critical Resource",
            "CWE-765": "Multiple Unlocks of a Critical Resource",
            "CWE-766": "Critical Data Element Declared Public",
            "CWE-767": "Access to Critical Private Variable via Public Method",
            "CWE-768": "Incorrect Short Circuit Evaluation",
            "CWE-769": "DEPRECATED: Uncontrolled File Descriptor Consumption",
            "CWE-770": "Allocation of Resources Without Limits or Throttling",
            "CWE-771": "Missing Reference to Active Allocated Resource",
            "CWE-772": "Missing Release of Resource after Effective Lifetime",
            "CWE-773": "Missing Reference to Active File Descriptor or Handle",
            "CWE-774": "Allocation of File Descriptors or Handles Without Limits or Throttling",
            "CWE-775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
            "CWE-776": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
            "CWE-777": "Regular Expression without Anchors",
            "CWE-778": "Insufficient Logging",
            "CWE-779": "Logging of Excessive Data",
            "CWE-780": "Use of RSA Algorithm without OAEP",
            "CWE-781": "Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code",
            "CWE-782": "Exposed IOCTL with Insufficient Access Control",
            "CWE-783": "Operator Precedence Logic Error",
            "CWE-784": "Reliance on Cookies without Validation and Integrity Checking in a Security Decision",
            "CWE-785": "Use of Path Manipulation Function without Maximum-sized Buffer",
            "CWE-786": "Access of Memory Location Before Start of Buffer",
            "CWE-787": "Out-of-bounds Write",
            "CWE-788": "Access of Memory Location After End of Buffer",
            "CWE-789": "Uncontrolled Memory Allocation",
            "CWE-790": "Improper Filtering of Special Elements",
            "CWE-791": "Incomplete Filtering of Special Elements",
            "CWE-792": "Incomplete Filtering of One or More Instances of Special Elements",
            "CWE-793": "Only Filtering One Instance of a Special Element",
            "CWE-794": "Incomplete Filtering of Multiple Instances of Special Elements",
            "CWE-795": "Only Filtering Special Elements at a Specified Location",
            "CWE-796": "Only Filtering Special Elements Relative to a Marker",
            "CWE-797": "Only Filtering Special Elements at an Absolute Position",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-799": "Improper Control of Interaction Frequency",
            "CWE-804": "Guessable CAPTCHA",
            "CWE-805": "Buffer Access with Incorrect Length Value",
            "CWE-806": "Buffer Access Using Size of Source Buffer",
            "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
            "CWE-820": "Missing Synchronization",
            "CWE-821": "Incorrect Synchronization",
            "CWE-822": "Untrusted Pointer Dereference",
            "CWE-823": "Use of Out-of-range Pointer Offset",
            "CWE-824": "Access of Uninitialized Pointer",
            "CWE-825": "Expired Pointer Dereference",
            "CWE-826": "Premature Release of Resource During Expected Lifetime",
            "CWE-827": "Improper Control of Document Type Definition",
            "CWE-828": "Signal Handler with Functionality that is not Asynchronous-Safe",
            "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
            "CWE-830": "Inclusion of Web Functionality from an Untrusted Source",
            "CWE-831": "Signal Handler Function Associated with Multiple Signals",
            "CWE-832": "Unlock of a Resource that is not Locked",
            "CWE-833": "Deadlock",
            "CWE-834": "Excessive Iteration",
            "CWE-835": "Loop with Unreachable Exit Condition ('Infinite Loop')",
            "CWE-836": "Use of Password Hash Instead of Password for Authentication",
            "CWE-837": "Improper Enforcement of a Single, Unique Action",
            "CWE-838": "Inappropriate Encoding for Output Context",
            "CWE-839": "Numeric Range Comparison Without Minimum Check",
            "CWE-841": "Improper Enforcement of Behavioral Workflow",
            "CWE-842": "Placement of User into Incorrect Group",
            "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
            "CWE-862": "Missing Authorization",
            "CWE-863": "Incorrect Authorization",
            "CWE-908": "Use of Uninitialized Resource",
            "CWE-909": "Missing Initialization of Resource",
            "CWE-910": "Use of Expired File Descriptor",
            "CWE-911": "Improper Update of Reference Count",
            "CWE-912": "Hidden Functionality",
            "CWE-913": "Improper Control of Dynamically-Managed Code Resources",
            "CWE-914": "Improper Control of Dynamically-Identified Variables",
            "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
            "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-920": "Improper Restriction of Power Consumption",
            "CWE-921": "Storage of Sensitive Data in a Mechanism without Access Control",
            "CWE-922": "Insecure Storage of Sensitive Information",
            "CWE-923": "Improper Restriction of Communication Channel to Intended Endpoints",
            "CWE-924": "Improper Enforcement of Message Integrity During Transmission in a Communication Channel",
            "CWE-925": "Improper Verification of Intent by Broadcast Receiver",
            "CWE-926": "Improper Export of Android Application Components",
            "CWE-927": "Use of Implicit Intent for Sensitive Communication",
            "CWE-939": "Improper Authorization in Handler for Custom URL Scheme",
            "CWE-940": "Improper Verification of Source of a Communication Channel",
            "CWE-941": "Incorrectly Specified Destination in a Communication Channel",
            "CWE-942": "Overly Permissive Cross-domain Whitelist",
            "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
            "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
            "CWE-1007": "Insufficient Visual Distinction of Homoglyphs Presented to User",
            "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
            "CWE-1022": "Use of Web Link to Untrusted Target with window.opener Access",
            "CWE-1023": "Incomplete Comparison with Missing Factors",
            "CWE-1024": "Comparison of Incompatible Types",
            "CWE-1025": "Comparison Using Wrong Factors",
            "CWE-1037": "Processor Optimization Removal or Modification of Security-critical Code",
            "CWE-1038": "Insecure Automated Optimizations",
            "CWE-1039": "Automated Recognition Mechanism with Inadequate Detection or Handling of Adversarial Input Perturbations",
            "CWE-1041": "Use of Redundant Code",
            "CWE-1042": "Static Member Data Element outside of a Singleton Class Element",
            "CWE-1043": "Data Element Aggregating an Excessively Large Number of Non-Primitive Elements",
            "CWE-1044": "Architecture with Number of Horizontal Layers Outside of Expected Range",
            "CWE-1045": "Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor",
            "CWE-1046": "Creation of Immutable Text Using String Concatenation",
            "CWE-1047": "Modules with Circular Dependencies",
            "CWE-1048": "Invokable Control Element with Large Number of Outward Calls",
            "CWE-1049": "Excessive Data Query Operations in a Large Data Table",
            "CWE-1050": "Excessive Platform Resource Consumption within a Loop",
            "CWE-1051": "Initialization with Hard-Coded Network Resource Configuration Data",
            "CWE-1052": "Excessive Use of Hard-Coded Literals in Initialization",
            "CWE-1053": "Missing Documentation for Design",
            "CWE-1054": "Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer",
            "CWE-1055": "Multiple Inheritance from Concrete Classes",
            "CWE-1056": "Invokable Control Element with Variadic Parameters",
            "CWE-1057": "Data Access Operations Outside of Expected Data Manager Component",
            "CWE-1058": "Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element",
            "CWE-1059": "Incomplete Documentation",
            "CWE-1060": "Excessive Number of Inefficient Server-Side Data Accesses",
            "CWE-1061": "Insufficient Encapsulation",
            "CWE-1062": "Parent Class with References to Child Class",
            "CWE-1063": "Creation of Class Instance within a Static Code Block",
            "CWE-1064": "Invokable Control Element with Signature Containing an Excessive Number of Parameters",
            "CWE-1065": "Runtime Resource Management Control Element in a Component Built to Run on Application Servers",
            "CWE-1066": "Missing Serialization Control Element",
            "CWE-1067": "Excessive Execution of Sequential Searches of Data Resource",
            "CWE-1068": "Inconsistency Between Implementation and Documented Design",
            "CWE-1069": "Empty Exception Block",
            "CWE-1070": "Serializable Data Element Containing non-Serializable Item Elements",
            "CWE-1071": "Empty Code Block",
            "CWE-1072": "Data Resource Access without Use of Connection Pooling",
            "CWE-1073": "Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses",
            "CWE-1074": "Class with Excessively Deep Inheritance",
            "CWE-1075": "Unconditional Control Flow Transfer outside of Switch Block",
            "CWE-1076": "Insufficient Adherence to Expected Conventions",
            "CWE-1077": "Floating Point Comparison with Incorrect Operator",
            "CWE-1078": "Inappropriate Source Code Style or Formatting",
            "CWE-1079": "Parent Class without Virtual Destructor Method",
            "CWE-1080": "Source Code File with Excessive Number of Lines of Code",
            "CWE-1082": "Class Instance Self Destruction Control Element",
            "CWE-1083": "Data Access from Outside Expected Data Manager Component",
            "CWE-1084": "Invokable Control Element with Excessive File or Data Access Operations",
            "CWE-1085": "Invokable Control Element with Excessive Volume of Commented-out Code",
            "CWE-1086": "Class with Excessive Number of Child Classes",
            "CWE-1087": "Class with Virtual Method without a Virtual Destructor",
            "CWE-1088": "Synchronous Access of Remote Resource without Timeout",
            "CWE-1089": "Large Data Table with Excessive Number of Indices",
            "CWE-1090": "Method Containing Access of a Member Element from Another Class",
            "CWE-1091": "Use of Object without Invoking Destructor Method",
            "CWE-1092": "Use of Same Invokable Control Element in Multiple Architectural Layers",
            "CWE-1093": "Excessively Complex Data Representation",
            "CWE-1094": "Excessive Index Range Scan for a Data Resource",
            "CWE-1095": "Loop Condition Value Update within the Loop",
            "CWE-1096": "Singleton Class Instance Creation without Proper Locking or Synchronization",
            "CWE-1097": "Persistent Storable Data Element without Associated Comparison Control Element",
            "CWE-1098": "Data Element containing Pointer Item without Proper Copy Control Element",
            "CWE-1099": "Inconsistent Naming Conventions for Identifiers",
            "CWE-1100": "Insufficient Isolation of System-Dependent Functions",
            "CWE-1101": "Reliance on Runtime Component in Generated Code",
            "CWE-1102": "Reliance on Machine-Dependent Data Representation",
            "CWE-1103": "Use of Platform-Dependent Third Party Components",
            "CWE-1104": "Use of Unmaintained Third Party Components",
            "CWE-1105": "Insufficient Encapsulation of Machine-Dependent Functionality",
            "CWE-1106": "Insufficient Use of Symbolic Constants",
            "CWE-1107": "Insufficient Isolation of Symbolic Constant Definitions",
            "CWE-1108": "Excessive Reliance on Global Variables",
            "CWE-1109": "Use of Same Variable for Multiple Purposes",
            "CWE-1110": "Incomplete Design Documentation",
            "CWE-1111": "Incomplete I/O Documentation",
            "CWE-1112": "Incomplete Documentation of Program Execution",
            "CWE-1113": "Inappropriate Comment Style",
            "CWE-1114": "Inappropriate Whitespace Style",
            "CWE-1115": "Source Code Element without Standard Prologue",
            "CWE-1116": "Inaccurate Comments",
            "CWE-1117": "Callable with Insufficient Behavioral Summary",
            "CWE-1118": "Insufficient Documentation of Error Handling Techniques",
            "CWE-1119": "Excessive Use of Unconditional Branching",
            "CWE-1120": "Excessive Code Complexity",
            "CWE-1121": "Excessive McCabe Cyclomatic Complexity",
            "CWE-1122": "Excessive Halstead Complexity",
            "CWE-1123": "Excessive Use of Self-Modifying Code",
            "CWE-1124": "Excessively Deep Nesting",
            "CWE-1125": "Excessive Attack Surface",
            "CWE-1126": "Declaration of Variable with Unnecessarily Wide Scope",
            "CWE-1127": "Compilation with Insufficient Warnings or Errors",
            "None": "N/A, generally needs further research",
        }

    def cwe(self, label, nolabel):
        """
        Plots flaw CWEs grouped by value among the filtered ones
        """
        # Populate CWE
        # self.populate_cwe()
        self.populate_cwe_static()

        # Process tickets and organize them based on CWE
        issues = self.vulnerabilities  # select all possible tickets
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabel:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        dict_vulns_cwe = {}
        for issue in issues:
            vulnerability = self.import_issue(issue.number, issue=issue)
            # print(vulnerability.cwe)
            pattern = re.compile("^.*(CWE-[0-9][0-9]*).*$")
            result = pattern.search(vulnerability.cwe)
            # print(vulnerability.cwe)
            # print(result)
            if result:
                # print(result.group(0))
                cwe_value = result.group(1)
                if cwe_value in dict_vulns_cwe.keys():
                    dict_vulns_cwe[cwe_value].append(issue)
                else:
                    dict_vulns_cwe[cwe_value] = [issue]
                print(result.group(1))
            else:
                if "None" in dict_vulns_cwe.keys():
                    dict_vulns_cwe["None"].append(issue)
                else:
                    dict_vulns_cwe["None"] = [issue]

        # pprint.pprint(dict_vulns_cwe)

        #######
        # Plot
        #######
        fig = go.Figure()
        for key in dict_vulns_cwe.keys():
            fig.add_trace(
                go.Bar(
                    name=str(key) + ": " + str(self.cwe_dict[key]),
                    x=[key],
                    y=[len(dict_vulns_cwe[key])],
                )
            )

        # fig.update_layout(
        #     title='Time until mitigation (in days), robot vulnerabilities',
        #     yaxis=dict(
        #         autorange=True,
        #         showgrid=False,
        #         zeroline=True,
        #         gridcolor='rgb(255, 255, 255)',
        #         gridwidth=1,
        #         zerolinecolor='rgb(255, 255, 255)',
        #         zerolinewidth=2,
        #     ),
        #     margin=dict(
        #         l=40,
        #         r=30,
        #         b=80,
        #         t=100,
        #     ),
        #     # paper_bgcolor='rgb(243, 243, 243)',
        #     # plot_bgcolor='rgb(243, 243, 243)',
        #     showlegend=True
        # )
        fig.show()

    def public_private(self, label, nolabel):
        """
        Plots public vs private flaws given a set of filters through labels
        """
        # Find out public vs private flaws
        pass

        # Plot
        fig = go.Figure()

        # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)',
        #           'rgba(207, 114, 255, 0.5)', 'rgba(127, 96, 0, 0.5)']

        # public
        fig.add_trace(
            go.Bar(
                name="Publicly available",
                x=["Public"],
                y=[5],
                marker=dict(color="rgba(93, 164, 214, 0.5)",),
                # opacity=0.6
            )
        )
        # private
        fig.add_trace(
            go.Bar(
                name="Discovered by Alias Robotics",
                x=["Alias"],
                y=[140],
                marker=dict(color="rgba(44, 160, 101, 0.5)",),
            )
        )
        # total
        fig.add_trace(
            go.Bar(
                name="All (known) vulnerabilities",
                x=["Total"],
                y=[145],
                marker=dict(color="rgba(255, 144, 14, 0.5)",),
            )
        )
        fig.show()

    def zero_vs_mitigated(self, label, nolabel):
        """
        Plots 0-days vs mitigated flaws, among the filtered ones
        """
        # issues = self.vulnerabilities  # select all possible tickets
        # zero_days = []
        # mitigated = []
        # if label:  # account for only filtered tickets
        #     cyan("Using label: " + str(label))
        #     cyan("Using nolabel: " + str(nolabel))
        #     filtered = []
        #     # fetch the from attributes itself, see above
        #     for issue in issues:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in label:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         for l in nolabel:
        #             # id l in labels, we don't want it
        #             if l in labels:
        #                 all_labels = False
        #                 break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        #
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     # vulnerability = self.import_issue(issue.number, issue=issue)
        #     print("Issue " + str(issue.number) + " state: " + str(issue.state))
        #     labels = [l.name for l in issue.labels]
        #     if issue.state == "open" and not "mitigated" in labels:
        #         zero_days.append(issue)
        #     else:
        #         mitigated.append(issue)
        #
        # yellow("0-days: " + str(len(zero_days)))
        # yellow("Mitigated: " + str(len(mitigated)))
        #
        # # Plot
        # # animals = ['ROS', 'ROS 2', 'Universal Robots']
        # animals = [str(label)]
        #
        # fig = go.Figure(data=[
        #     go.Bar(name='0-days', x=animals, y=[len(zero_days)]),
        #     go.Bar(name='Mitigated', x=animals, y=[len(mitigated)])
        # ])
        # # Change the bar mode
        # fig.update_layout(barmode='group')
        # fig.show()

        issues_nonfiltered = self.vulnerabilities
        issues = self.vulnerabilities  # select all possible tickets
        # ROS
        zero_days_ROS = []
        mitigated_ROS = []
        labels_ROS = ["robot component: ROS"]
        nolabels_ROS = []
        if labels_ROS:  # account for only filtered tickets
            cyan("Using labels_ROS: " + str(labels_ROS))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ROS:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ROS:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ROS.append(issue)
            else:
                mitigated_ROS.append(issue)

        yellow("0-days: " + str(len(zero_days_ROS)))
        yellow("Mitigated: " + str(len(mitigated_ROS)))

        # ROS2
        zero_days_ROS2 = []
        mitigated_ROS2 = []
        labels_ROS2 = ["robot component: ROS2"]
        nolabels_ROS2 = []
        if labels_ROS2:  # account for only filtered tickets
            cyan("Using labels_ROS2: " + str(labels_ROS2))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ROS2:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ROS2:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ROS2.append(issue)
            else:
                mitigated_ROS2.append(issue)

        yellow("0-days: " + str(len(zero_days_ROS2)))
        yellow("Mitigated: " + str(len(mitigated_ROS2)))

        # UR
        zero_days_UR = []
        mitigated_UR = []
        labels_UR = ["vendor: Universal Robots"]
        nolabels_UR = []
        if labels_UR:  # account for only filtered tickets
            cyan("Using labels_UR: " + str(labels_UR))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_UR:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_UR:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_UR.append(issue)
            else:
                mitigated_UR.append(issue)

        yellow("0-days: " + str(len(zero_days_UR)))
        yellow("Mitigated: " + str(len(mitigated_UR)))

        # ABB
        zero_days_ABB = []
        mitigated_ABB = []
        labels_ABB = ["vendor: ABB"]
        nolabels_ABB = ["triage"]
        if labels_ABB:  # account for only filtered tickets
            cyan("Using labels_ABB: " + str(labels_ABB))
            cyan("Using nolabel: " + str(nolabel))
            filtered = []
            # fetch the from attributes itself, see above
            for issue in issues_nonfiltered:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in labels_ABB:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabels_ABB:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            # vulnerability = self.import_issue(issue.number, issue=issue)
            print("Issue " + str(issue.number) + " state: " + str(issue.state))
            labels = [l.name for l in issue.labels]
            if issue.state == "open" and "mitigated" not in labels:
                zero_days_ABB.append(issue)
            else:
                mitigated_ABB.append(issue)

        yellow("0-days: " + str(len(zero_days_ABB)))
        yellow("Mitigated: " + str(len(mitigated_ABB)))

        ########
        # Plot
        ########
        animals = ["ROS", "ROS 2", "Universal Robots", "ABB"]
        # animals = [str(label)]

        fig = go.Figure(
            data=[
                go.Bar(
                    name="Mitigated",
                    x=animals,
                    y=[
                        len(mitigated_ROS),
                        len(mitigated_ROS2),
                        len(mitigated_UR),
                        len(mitigated_ABB),
                    ],
                ),
                go.Bar(
                    name="0-days",
                    x=animals,
                    y=[
                        len(zero_days_ROS),
                        len(zero_days_ROS2),
                        len(zero_days_UR),
                        len(zero_days_ABB),
                    ],
                ),
            ]
        )
        # Change the bar mode
        fig.update_layout(barmode="group")
        fig.show()

    def mitigation_timing(self, label, nolabel):
        """
        Creates a plot showing the time to mitigation for the selected tickets
        via label (labels).

        :param label tuple()
        :return None
        """
        cyan("Produce plot with time required to mitigate each flaw...")

        issues = self.vulnerabilities  # select all possible tickets
        time_difference = []  #  in days
        if label:  # account for only filtered tickets
            cyan("Using label: " + str(label))
            # importer = Base()
            filtered = []

            # fetch the from attributes itself, see above
            for issue in issues:
                all_labels = True  # indicates whether all labels are present
                labels = [l.name for l in issue.labels]
                for l in label:
                    # if l not in labels or "invalid" in labels or "duplicate" in labels:
                    if l not in labels:
                        all_labels = False
                        break
                for l in nolabel:
                    # id l in labels, we don't want it
                    if l in labels:
                        all_labels = False
                        break
                if all_labels:
                    filtered.append(issue)
            issues = filtered
        else:
            cyan("Using all vulnerabilities...")

        # Calculate time difference for each ticket - in days
        for issue in issues:
            vulnerability = self.import_issue(issue.number, issue=issue)
            # favour selection of earliest date (date_detected)
            if vulnerability.date_detected == "" or vulnerability.date_detected is None:
                if (
                    vulnerability.date_reported == ""
                    or vulnerability.date_reported is None
                ):
                    # report error in dates
                    red(
                        "Error, both date_detected and date_reported seem \
                    wrong in "
                        + str(vulnerability)
                    )
                    sys.exit(1)
                else:
                    initial_date = arrow.get(
                        vulnerability.date_reported, ["YYYY-MM-DD"]
                    )
            else:
                initial_date = arrow.get(vulnerability.date_detected, ["YYYY-MM-DD"])

            # select mitigation date
            if vulnerability.date_mitigation:
                mitigation_date = arrow.get(
                    vulnerability.date_mitigation, ["YYYY-MM-DD"]
                )
            else:
                mitigation_date = arrow.now()  # default to now for statistics

            yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
            print(str((mitigation_date - initial_date).days))
            time_difference.append(int((mitigation_date - initial_date).days))

        ############
        # Create plot
        ############

        # x_data = ['Carmelo Anthony']
        x_data = [str(label)]

        y0 = time_difference

        # y_data = [y0, y1, y2, y3, y4, y5]
        y_data = [y0]

        # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)',
        #           'rgba(207, 114, 255, 0.5)', 'rgba(127, 96, 0, 0.5)']
        colors = ["rgba(93, 164, 214, 0.5)"]

        fig = go.Figure()

        for xd, yd, cls in zip(x_data, y_data, colors):
            fig.add_trace(
                go.Box(
                    y=yd,
                    name=xd,
                    boxpoints="all",
                    jitter=0.5,
                    whiskerwidth=0.2,
                    fillcolor=cls,
                    marker_size=2,
                    line_width=1,
                )
            )

        fig.update_layout(
            title="Time to mitigation (in days), robot vulnerabilities",
            yaxis=dict(
                autorange=True,
                showgrid=False,
                zeroline=True,
                gridcolor="rgb(255, 255, 255)",
                gridwidth=1,
                zerolinecolor="rgb(255, 255, 255)",
                zerolinewidth=2,
            ),
            margin=dict(l=40, r=30, b=80, t=100,),
            paper_bgcolor="rgb(243, 243, 243)",
            plot_bgcolor="rgb(243, 243, 243)",
            showlegend=False,
        )
        fig.show()

        # issues_nonfiltered = self.vulnerabilities
        # issues = self.vulnerabilities  # select all possible tickets
        #
        # # ROS
        # time_difference_ROS = []  # in days
        # labels_ROS = ["robot component: ROS"]
        # if labels_ROS:  # account for only filtered tickets
        #     cyan("Using labels_ROS: " + str(labels_ROS))
        #     # importer = Base()
        #     filtered = []
        #
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ROS:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        #
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(vulnerability.date_detected, ['YYYY-MM-DD'])
        #
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        #
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     # print(str((mitigation_date - initial_date).days))
        #     time_difference_ROS.append(int((mitigation_date - initial_date).days))
        #
        # # ROS2
        # time_difference_ROS2 = []  # in days
        # labels_ROS2 = ["robot component: ROS2"]
        # if labels_ROS2:  # account for only filtered tickets
        #     cyan("Using labels_ROS2: " + str(labels_ROS2))
        #     # importer = Base()
        #     filtered = []
        #
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ROS2:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        #
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(vulnerability.date_detected, ['YYYY-MM-DD'])
        #
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        #
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     # print(str((mitigation_date - initial_date).days))
        #     time_difference_ROS2.append(int((mitigation_date - initial_date).days))
        #
        # # UR
        # time_difference_UR = []  # in days
        # labels_UR = ["vendor: Universal Robots"]
        # if labels_UR:  # account for only filtered tickets
        #     cyan("Using labels_UR: " + str(labels_UR))
        #     # importer = Base()
        #     filtered = []
        #
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_UR:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         # for l in nolabel:
        #         #     # id l in labels, we don't want it
        #         #     if l in labels:
        #         #         all_labels = False
        #         #         break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        #
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(str(vulnerability.date_detected), ['YYYY-MM-DD'])
        #
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        #
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     print(str((mitigation_date - initial_date).days))
        #     time_difference_UR.append(int((mitigation_date - initial_date).days))
        #
        # # ABB
        # time_difference_ABB = []  # in days
        # labels_ABB = ["vendor: ABB"]
        # if labels_ABB:  # account for only filtered tickets
        #     cyan("Using labels_ABB: " + str(labels_ABB))
        #     # importer = Base()
        #     filtered = []
        #
        #     # fetch the from attributes itself, see above
        #     for issue in issues_nonfiltered:
        #         all_labels = True  # indicates whether all labels are present
        #         labels = [l.name for l in issue.labels]
        #         for l in labels_ABB:
        #             # if l not in labels or "invalid" in labels or "duplicate" in labels:
        #             if l not in labels:
        #                 all_labels = False
        #                 break
        #         for l in nolabel:
        #             # id l in labels, we don't want it
        #             if l in labels:
        #                 all_labels = False
        #                 break
        #         if all_labels:
        #             filtered.append(issue)
        #     issues = filtered
        # else:
        #     cyan("Using all vulnerabilities...")
        #
        # # Calculate time difference for each ticket - in days
        # for issue in issues:
        #     vulnerability = self.import_issue(issue.number, issue=issue)
        #     # favour selection of earliest date (date_detected)
        #     if vulnerability.date_detected == "" or vulnerability.date_detected is None:
        #         if vulnerability.date_reported == "" or vulnerability.date_reported is None:
        #             # report error in dates
        #             red("Error, both date_detected and date_reported seem \
        #             wrong in " + str(vulnerability))
        #             sys.exit(1)
        #         else:
        #             initial_date = arrow.get(vulnerability.date_reported, ['YYYY-MM-DD'])
        #     else:
        #         initial_date = arrow.get(str(vulnerability.date_detected), ['YYYY-MM-DD'])
        #
        #     # select mitigation date
        #     if vulnerability.date_mitigation:
        #         mitigation_date = arrow.get(vulnerability.date_mitigation, ['YYYY-MM-DD'])
        #     else:
        #         mitigation_date = arrow.now()  # default to now for statistics
        #
        #     yellow("Mitigation time for " + str(vulnerability.id) + ": ", end="")
        #     print(str((mitigation_date - initial_date).days))
        #     # print(mitigation_date)
        #     # print(initial_date)
        #     time_difference_ABB.append(int((mitigation_date - initial_date).days))
        #
        # ############
        # # Create plot
        # ############
        #
        # # x_data = ['Carmelo Anthony']
        # x_data = ["ROS", "ROS2", "Universal Robots", "ABB"]
        #
        # y0 = time_difference_ROS
        # y1 = time_difference_ROS2
        # y2 = time_difference_UR
        # y3 = time_difference_ABB
        #
        # # y_data = [y0, y1, y2, y3, y4, y5]
        # y_data = [y0, y1, y2, y3]
        #
        # # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        # #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)',
        # #           'rgba(207, 114, 255, 0.5)', 'rgba(127, 96, 0, 0.5)']
        # colors = ['rgba(93, 164, 214, 0.5)', 'rgba(255, 144, 14, 0.5)',
        #           'rgba(44, 160, 101, 0.5)', 'rgba(255, 65, 54, 0.5)']
        #
        # fig = go.Figure()
        #
        # for xd, yd, cls in zip(x_data, y_data, colors):
        #     fig.add_trace(go.Box(
        #             y=yd,
        #             name=xd,
        #             boxpoints='all',
        #             jitter=0.5,
        #             whiskerwidth=0.2,
        #             fillcolor=cls,
        #             marker_size=5,
        #             line_width=1)
        #         )
        #
        # # fig.add_shape(
        # #         # Line Horizontal
        # #         go.layout.Shape(
        # #             type="line",
        # #             y0=365,
        # #             # x0=0,
        # #             # x1=5,
        # #             y1=365,
        # #             line=dict(
        # #                 color="LightSeaGreen",
        # #                 width=3,
        # #                 dash="dashdot",
        # #             ),
        # #         )
        # # )
        #
        # fig.update_layout(
        #     title='Time until mitigation (in days), robot vulnerabilities',
        #     yaxis=dict(
        #         autorange=True,
        #         showgrid=False,
        #         zeroline=True,
        #         gridcolor='rgb(255, 255, 255)',
        #         gridwidth=1,
        #         zerolinecolor='rgb(255, 255, 255)',
        #         zerolinewidth=2,
        #     ),
        #     margin=dict(
        #         l=40,
        #         r=30,
        #         b=80,
        #         t=100,
        #     ),
        #     # paper_bgcolor='rgb(243, 243, 243)',
        #     # plot_bgcolor='rgb(243, 243, 243)',
        #     showlegend=True
        # )
        # fig.show()

    def historic(self, issues):
        """
        Compile a table with historic data.

        Items in the table (in this order):
        - ID
        - date reported
        - vendor
        - CVE
        - CVSS
        - RVSS

        :returns table [[]]
        """
        return_table = []
        for issue in issues:
            flaw = self.import_issue(issue.number, issue=issue, debug=False)
            return_table.append(
                [
                    flaw.id,
                    flaw.date_reported,
                    flaw.vendor,
                    flaw.cve,
                    flaw.cvss_score,
                    flaw.rvss_score,
                ]
            )
            # print(flaw.date_reported)
            # print(flaw.vendor)
        return return_table

    def summary(self, issues):
        """
        """
        pass

    def vendor_vulnerabilities(self, issues):
        """
        Barplot showing number of vulns by vendor

        return None
        """
        vulnerabilities_flaws = []  # flaw objects, simplify processing
        for vulnerability in self.vulnerabilities:
            vulnerabilities_flaws.append(
                self.import_issue(
                    vulnerability.number, issue=vulnerability, debug=False
                )
            )

        # Create a dict that organizes vulns by vendor
        dict_vulnerabilities = {}
        vulnerabilities_averaged = {}
        for vuln in vulnerabilities_flaws:
            score = vuln.cvss_score
            if score == 0:
                score = 10  #  asign by default a max. score to those non triaged
                # score = 0  # asign by default a min score to those non triaged
            if score == "N/A":
                score = 10
                # score = 0

            dict_vulnerabilities["None"] = []
            if vuln.vendor:
                if vuln.vendor.strip() in dict_vulnerabilities.keys():
                    dict_vulnerabilities[vuln.vendor.strip()].append(score)
                else:
                    dict_vulnerabilities[vuln.vendor.strip()] = [score]
            else:
                dict_vulnerabilities["None"].append(score)

        # pprint.pprint(dict_vulnerabilities)

        # Create the figure
        fig = go.Figure()
        # populate low_percentages
        x = []
        y_num_vulns = []
        for vendor in dict_vulnerabilities.keys():
            if vendor == "N/A":
                x.append("Others")
            else:
                x.append(vendor)
            y_num_vulns.append(len(dict_vulnerabilities[vendor]))
            print(vendor)
            print(len(dict_vulnerabilities[vendor]))

        # colors = ['yellow', 'orange', 'red', 'darkred']
        fig.add_trace(go.Bar(x=x, y=y_num_vulns, name="Number of vulnerabilities"))

        fig.update_layout(
            barmode="stack", xaxis={"categoryorder": "category ascending"}
        )
        fig.show()

    def cvss_score_distribution(self, label, isoption="all"):
        """
        Generates an averaged score distribution for all tickets,
        unless a label is provided (which would filter tickets)

        Produces a plot.

        :return None
        """
        vulnerabilities_flaws = []  # flaw objects, simplify processing
        for vulnerability in self.vulnerabilities:
            vuln = self.import_issue(
                vulnerability.number, issue=vulnerability, debug=False
            )
            vulnerabilities_flaws.append(vuln)

        # Create a dict that organizes vulns by vendor
        dict_vulnerabilities = {}
        vulnerabilities_averaged = {}
        for vuln in vulnerabilities_flaws:
            if not vuln:
                # continue
                red("Vuln fetched in None")
                sys.exit(1)
            score = vuln.cvss_score
            if score == 0:
                # score = 10  # asign by default a max. score to those non triaged
                score = 0  #  asign by default a min score to those non triaged
            if score == "N/A":
                # score = 10
                score = 0

            # if vuln.vendor and vuln.vendor.strip() in dict_vulnerabilities.keys():
            #     dict_vulnerabilities[vuln.vendor.strip()].append(score)
            # else:
            #     if vuln.vendor:
            #         yellow("Creating new vendor group: " + str(vuln.vendor.strip()))
            #         dict_vulnerabilities[vuln.vendor.strip()] = [score]
            #     else:
            #         yellow("Adding to vendor group: None (" + str(vuln.id) + ")")
            #         dict_vulnerabilities["None"] = [score]

            dict_vulnerabilities["None"] = []
            if vuln.vendor:
                if vuln.vendor.strip() in dict_vulnerabilities.keys():
                    dict_vulnerabilities[vuln.vendor.strip()].append(score)
                else:
                    yellow("Creating new vendor group: " + str(vuln.vendor.strip()))
                    dict_vulnerabilities[vuln.vendor.strip()] = [score]
            else:
                red("Adding to vendor group None (" + str(vuln.id) + ")")
                dict_vulnerabilities["None"].append(score)

        pprint.pprint(dict_vulnerabilities)

        # construct data for plotting
        for key in dict_vulnerabilities.keys():
            # lists to quantify how severe are tickets for each vendor
            low_scale = []  # 0 - 3.9
            medium_scale = []  # 4.0 - 6.9
            high_scale = []  # 7.0 - 8.9
            critical_scale = []  # 9.0 - 10.0

            for score in dict_vulnerabilities[key]:
                if score >= 0 and score < 4:
                    low_scale.append(score)
                elif score >= 4 and score < 7:
                    medium_scale.append(score)
                elif score >= 7 and score < 9:
                    high_scale.append(score)
                elif score >= 9 and score <= 10:
                    critical_scale.append(score)
                else:
                    red("Error, not accepted score: " + str(score))
                    sys.exit(1)

            total = len(dict_vulnerabilities[key])
            low_percentage = len(low_scale) / total
            medium_percentage = len(medium_scale) / total
            high_percentage = len(high_scale) / total
            critical_percentage = len(critical_scale) / total

            vulnerabilities_averaged[key] = [
                low_percentage,
                medium_percentage,
                high_percentage,
                critical_percentage,
            ]

        # pprint.pprint(vulnerabilities_averaged)

        # x = list(dict_vulnerabilities.keys())
        fig = go.Figure()
        # populate low_percentages
        x = []
        y_low_percentage = []
        y_medium_percentage = []
        y_high_percentage = []
        y_critical_percentage = []
        for vendor in vulnerabilities_averaged.keys():
            if vendor == "N/A":
                x.append("Others")
            else:
                x.append(vendor)

            y_low_percentage.append(vulnerabilities_averaged[vendor][0])
            y_medium_percentage.append(vulnerabilities_averaged[vendor][1])
            y_high_percentage.append(vulnerabilities_averaged[vendor][2])
            y_critical_percentage.append(vulnerabilities_averaged[vendor][3])

        # colors = ['yellow', 'orange', 'red', 'darkred']
        fig.add_trace(go.Bar(x=x, y=y_low_percentage, name="Low"))

        fig.add_trace(go.Bar(x=x, y=y_medium_percentage, name="Medium"))

        fig.add_trace(go.Bar(x=x, y=y_high_percentage, name="High"))

        fig.add_trace(go.Bar(x=x, y=y_critical_percentage, name="Critical"))

        fig.update_layout(
            barmode="stack", xaxis={"categoryorder": "category ascending"}
        )
        fig.show()
