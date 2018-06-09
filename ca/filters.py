#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-09
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
from django.db.models import Q

import django_filters

from . import models


class PubKeyFilter(django_filters.FilterSet):
    class Meta:
        model = models.PubKey
        fields = ['keytype', 'size']


class CertFilter(django_filters.FilterSet):
    cn = django_filters.CharFilter(method='cn_filter')

    class Meta:
        model = models.Cert
        fields = ['cn', 'ca']

    def cn_filter(self, qs, name, value):
        return qs.filter(Q(cn__contains=value) |
                         Q(alternative__contains=value))
