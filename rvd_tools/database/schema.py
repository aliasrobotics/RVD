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
        'type': 'number',
        # 'nullable': False,
        'empty': False,
        'min': 1,
        # 'max': 100
        'default_setter':
            lambda doc: 0,
        # 'default': 0
    },
    'title': {
        'required': True,
        'type': 'string',
        'maxlength': 65,
    },
    'type': {
        'required': True,
        'type': 'string',
        'allowed': ['weakness', 'vulnerability', 'exposure'],
        'default_setter':
            lambda doc: 'weakness'
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
    },
    'cve': {
        'required': True,
        'type': 'string',
        'regex': '^CVE-[0-9]*-[0-9]*$|^None$',  # CVE-2019-13585
    },
    'keywords': {
        'required': True,
        'type': 'list',
    },
    'system': {
        'required': True,
        'type': 'string',
    },
    'vendor': {
        'required': True,
        'type': 'string',
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
        'regex': '^None$',
    },
    'flaw': {
        'required': True,
        'schema': {
            'phase': {
                'required': True,
                'type': 'string',
                'allowed': ['programming-time', 'build-time', 'compile-time',
                            'deployment-time', 'runtime-initialization',
                            'runtime-operation', 'testing'],
                'default_setter':
                    lambda doc: 'testing'
            },
            'specificity': {
                'required': True,
                'type': 'string',
                'allowed': ['general issue', 'robotics specific',
                            'ROS-specific', 'subject-specific', 'N/A'],
            },
            'architectural-location': {
                'required': True,
                'type': 'string',
                'allowed': ['application-specific code',
                            'platform code', 'third-party'],
            },
            'application': {
                'type': 'string',
                'required': True,
            },
            'subsystem': {
                'type': 'string',
                'required': True,
                'regex':
                    '^(sensing|actuation|communication|cognition|UI|power).*$',
            },
            'package': {
                'type': 'string',
            },
            'languages': {
                'required': True,
                'type': 'string',
                'allowed': ['python', 'cmake', 'C', 'C++',
                            'package.xml', 'launch XML',
                            'msg', 'srv', 'xacro', 'urdf', 'None'],
                'default': 'None'
            },
            'date-detected': {
                ## TODO: review this and force date check
                # 'type': 'date',
                'type': 'string',
                'required': True,
                # 'coerce': 'datecoercer',
            },
            'detected-by': {
                'type': 'string',
                'required': True,
            },
            'detected-by-method': {
                'type': 'string',
                'required': True,
                'allowed': ['build system', 'compiler',
                            'assertions', 'runtime detection', 'runtime crash'
                            'testing violation', 'testing static',
                            'testing dynamic'],
            },
            'date-reported': {
                'type': 'string',
                'required': True,
            },
            'reported-by': {
                'type': 'string',
                'required': True,
            },
            'reported-by-relationship': {
                'type': 'string',
                'required': True,
                'allowed': ['guest user', 'contributor',
                            'member developer', 'automatic',
                            'security researcher', 'N/A', 'None'],
            },
            'issue': {
                'type': 'string',
            },
            'reproducibility': {
                'type': 'string',
                'required': True,
            },
            'trace': {
                'type': 'string',
            },
            'reproduction': {
                'type': 'string',
                'required': True,
            },
            'reproduction-image': {
                'type': 'string',
                'required': True,
            },
        }
    },
    'exploitation': {
        'required': True,
        'schema': {
            'description': {
                'required': True,
                'type': 'string',
            },
            'exploitation-image': {
                'required': True,
                'type': 'string',
            },
            'exploitation-vector': {
                'required': True,
                'type': 'string',
            },
        }
    },
    'mitigation': {
        'required': True,
        'schema': {
            'description': {
                'required': True,
                'type': 'string',
            },
            'pull-request': {
                'type': 'string',
            },
        }
    },
}
