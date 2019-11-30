from setuptools import setup, find_packages

setup(
    name='rvd-tools',
    version='0.3',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click',
        'PyGithub',
        'pyyaml',
        'cerberus',
        'arrow',
        'mergedeep',
        'python-gitlab',
        'tabulate',
        'numpy',
        'dedupe',
        'qprompt',
        'vulners',
        'plotly',
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
    flaws in the the Robot Vulnerability Database (RVD)
    ''',
    keywords=['RVD', 'vulnerability', 'security', 'tools', 'ics'],
    entry_points={
        'console_scripts': ['rvd = rvd_tools.cli:start']
    }
)
