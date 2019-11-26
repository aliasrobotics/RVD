# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Database schema
    see https://github.com/aliasrobotics/RVD/blob/master/docs/TAXONOMY.md for
    a complete description of the taxonomy
"""


SCHEMA = {
    'id': {
        'required': True,
        'oneof': [{'type': 'string'}, {'type': 'number'}],
        # 'type': 'number',
        'empty': False,
        'min': 0,
        # 'max': 100
        'default_setter':
            lambda doc: 0,
        # 'default': 0
    },
    'title': {
        'required': True,
        'type': 'string',
        'maxlength': 100,  # extend beyond 65 to cope with a few tickets
    },
    'type': {
        'required': True,
        'type': 'string',
        'allowed': ['bug', 'weakness', 'vulnerability', 'exposure'],
        'default_setter':
            lambda doc: 'bug'
    },
    'description': {
        'required': True,
        'type': 'string',
        # 'empty': False,
        # 'default_setter':
        #     lambda doc: None,
    },
    'cwe': {
        'required': True,
        'type': 'string',
        # 'oneof': [{'type': 'string'}, {'type': 'number'}],
        # # Changed in version 0.7: nullable is valid on
        # #  fields lacking type definition.
        # 'nullable': True,
        'regex': '^CWE-[0-9]*.*$|^None$',
        'default_setter':
            lambda doc: 'None'
    },
    'cve': {
        'required': True,
        'type': 'string',
        'regex': '^CVE-[0-9]*-[0-9]*$|^None$',  # CVE-2019-13585
        'default_setter':
            lambda doc: 'None'
    },
    'keywords': {
        'required': True,
        'oneof': [{'type': 'string'}, {'type': 'list'}],
        'default_setter':
            lambda doc: ''
    },
    'system': {
        'required': True,
        'type': 'string',
        'default_setter':
            lambda doc: ''
    },
    'vendor': {
        'required': True,
        'type': 'string',
        'nullable': True,
        'default_setter':
            lambda doc: None
    },
    'severity': {
        'required': True,
        'schema': {
            'rvss-score': {
                'oneof': [{'type': 'string'}, {'type': 'number'}],
                'regex': '^None$',
                'min': 0,
                'max': 10,
                'required': True,
            },
            'rvss-vector': {
                'type': 'string',
                'required': True,
            },
            'severity-description': {
                'type': 'string',
                'required': True,
            },
            'cvss-score': {
                'oneof': [{'type': 'string'}, {'type': 'number'}],
                'regex': '^None$',
                'min': 0,
                'max': 10,
                'required': False,
            },
            'cvss-vector': {
                'type': 'string',
                'required': False,
            },
        }
    },
    'links': {
        'required': False,
        'oneof': [{'type': 'string'}, {'type': 'list'}],
        # 'regex': '^None$',
        'default_setter':
            lambda doc: 'None',
    },
    'bug': {
        'rename': 'flaw'
    },
    'flaw': {
        'required': True,
        'schema': {
            'phase': {
                'required': True,
                'type': 'string',
                'allowed': ['programming-time', 'build-time', 'compile-time',
                            'deployment-time', 'runtime', 'runtime-initialization',
                            'runtime-operation', 'testing', 'unknown'],
                'default_setter':
                    lambda doc: 'unknown'
            },
            'specificity': {
                'required': True,
                'type': 'string',
                # 'allowed': ['general issue', 'robotics specific',
                #             'ROS-specific', 'subject-specific', 'N/A'],
                'default_setter':
                    lambda doc: 'N/A',
            },
            'architectural-location': {
                'required': True,
                'type': 'string',
                'allowed': ['application-specific code', 'application-specific',
                            'platform-code', 'platform code', 'ROS-specific',
                            'third-party', 'N/A'],
                'default_setter':
                    lambda doc: 'N/A',
            },
            'application': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: 'N/A',
            },
            'subsystem': {
                'type': 'string',
                'required': True,
                'regex':
                    '^(sensing|actuation|communication|cognition|UI|power).*$|^N/A$|.*',
                    # TODO: modify this value and enforce the subsystem's policies
                    # '^(sensing|actuation|communication|cognition|UI|power).*$|^N/A$',
                'default_setter':
                    lambda doc: 'N/A',
            },
            'package': {
                'oneof': [{'type': 'string'}, {'type': 'list'}],
                # 'type': 'string',
                'default_setter':
                    lambda doc: 'N/A',
            },
            'languages': {
                'required': True,
                'oneof': [{'type': 'string'}, {'type': 'list'}],
                # 'type': 'string',
                'allowed': ['Python', 'python', 'cmake', 'CMake', 'C', 'C++',
                            'package.xml', 'launch XML', 'URScript', 'shell',
                            'msg', 'srv', 'xacro', 'urdf', 'None', 'rosparam YAML',
                            'XML', 'ASCII STL', 'N/A', 'YAML', 'Package XML'],
                'default_setter':
                    lambda doc: 'None'
            },
            'date-detected': {
                ## TODO: review this and force date check
                # 'type': 'date',
                'type': 'string',
                'required': True,
                # 'coerce': 'datecoercer',
                'default_setter':
                    lambda doc: ''
            },
            'detected-by': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: ''
            },
            'detected-by-method': {
                'type': 'string',
                'required': True,
                'allowed': ['build system', 'compiler',
                            'assertions', 'runtime detection', 'runtime crash'
                            'testing violation', 'testing static',
                            'testing dynamic', 'N/A'],
                'default_setter':
                    lambda doc: 'N/A'
            },
            'date-reported': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: ''
            },
            'reported-by': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: ''
            },
            'reported-by-relationship': {
                'type': 'string',
                'required': True,
                'allowed': ['guest user', 'contributor',
                            'member developer', 'automatic',
                            'security researcher', 'N/A'],
                'default_setter':
                    lambda doc: 'N/A'
            },
            'issue': {
                'type': 'string',
                'default_setter':
                    lambda doc: '',
            },
            'reproducibility': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: '',
            },
            'trace': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: '',
            },
            'reproduction': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: ''
            },
            'reproduction-image': {
                'type': 'string',
                'required': True,
                'default_setter':
                    lambda doc: ''
            },
        }
    },
    'exploitation': {
        'required': True,
        'default_setter':
            lambda doc: '',
        'schema': {
            'description': {
                'required': True,
                'type': 'string',
                'default_setter':
                    lambda doc: ''
            },
            'exploitation-image': {
                'required': True,
                'type': 'string',
                'default_setter':
                    lambda doc: ''
            },
            'exploitation-vector': {
                'required': True,
                'type': 'string',
                'default_setter':
                    lambda doc: ''
            },
        }
    },
    'fix': {
        'rename': 'mitigation'
    },
    'mitigation': {
        'required': True,
        'schema': {
            'description': {
                'required': True,
                'type': 'string',
                'default_setter':
                    lambda doc: ''
            },
            'pull-request': {
                'oneof': [{'type': 'string'}, {'type': 'number'}],
                # 'type': 'string',
                'default_setter':
                    lambda doc: ''
            },
        }
    },
}
