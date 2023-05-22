from setuptools import setup, find_packages

setup(
    name="rvd-tools",
    version="0.9",
    packages=find_packages(),
    include_package_data=True,  # this requires a MANIFEST.in
    install_requires=[
        "Click",
        "PyGithub",
        "arrow",
        "bs4",
        "cerberus",
        "dedupe==1.10.0",
        "jsonschema",
        "mergedeep",
        "numpy",
        "plotly",
        #"pprint",
        "pygithub",
        "python-dateutil==2.7.3",
        "python-gitlab",
        "pyyaml==6.0",
        "qprompt",
        "retrying",
        "tabulate",
        "retrying",
        "vulners",
    	"xmltodict",
    	"importlib-resources",
    	"python-gitlab==2.0.0",
        "requests==2.31.0",
        "pycvesearch==1.0",
        "cvsslib@git+https://github.com/aliasrobotics/RVSS#egg=cvsslib",
    ],
    url="https://github.com/aliasrobotics/RVD",
    project_urls={"Source Code": "https://github.com/aliasrobotics/RVD"},
    license="GPLv3",
    author="Alias Robotics",
    author_email="contact@aliasrobotics.com",
    description="Toolset for the Robot Vulnerability Database (RVD)",
    long_description="""
    The Robot Vulnerability Database or RVD for short is an archive of
    robot vulnerabilities and bugs. This Python 3 package provides a set of tools to
    manage, operate and automate RVD.'
    """,
    keywords=["RVD", "vulnerability", "security", "tools", "ics"],
    entry_points={"console_scripts": ["rvd = rvd_tools.cli:start"]},
)
