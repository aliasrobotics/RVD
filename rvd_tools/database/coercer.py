# -*- coding: utf-8 -*-
#
# Alias Robotics SL
# https://aliasrobotics.com

"""
Database coercers (for cerberus)

Coercion allows you to apply a callable
(given as object or the name of a custom
coercion method) to a value before the document
is validated.
"""
from cerberus import Validator
import arrow


class MyNormalizer(Validator):
    def __init__(self, *args, **kwargs):
        super(MyNormalizer, self).__init__(*args, **kwargs)

    def _normalize_coerce_datecoercer(self, date):
        arrow_date = arrow.get(date, ['YYYY-MM-DD (HH:mm)', 'ddd, DD MMM YYYY HH:mm:ss Z'])
        return arrow_date.format('YYYY-MM-DD')
