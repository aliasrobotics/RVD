from setuptools import setup, find_packages

setup(
    name='rvd-tools',
    version='0.4',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'arrow',
        'bs4',
        'cerberus',
        'Click',
        'dedupe',
        'mergedeep',
        'numpy',
        'plotly',
        'PyGithub',
        'python-dateutil==2.7.3',
        'python-gitlab',
        'pyyaml',
        'qprompt',
        'tabulate',
        'vulners',
        # 'pycvesearch',  # needs to be installed manually, see https://github.com/cve-search/PyCVESearch
    ],
    url='https://github.com/aliasrobotics/RVD',
    project_urls={
     'Source Code': 'https://github.com/aliasrobotics/RVD'
    },
    license='GPLv3',
    author='Alias Robotics',
    author_email='contact@aliasrobotics.com',
    description='Toolset for RVD',
    long_description='''
    Set of tools and scripts to maintain, process and submit
    flaws in the the Robot Vulnerability Database (RVD).
    ''',
    keywords=['RVD', 'vulnerability', 'security', 'tools', 'ics'],
    entry_points={
        'console_scripts': ['rvd = rvd_tools.cli:start']
    }
)
