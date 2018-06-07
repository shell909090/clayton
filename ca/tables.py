#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-05
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
import django_tables2 as tables

from .models import PubKey, Cert


class KeyTable(tables.Table):
    export_ops = tables.TemplateColumn(
        '<a href="{% url \'ca:export_key\' record.dgst %}">export key</a>  '
        '<a href="{% url \'ca:export_pubkey\' record.dgst %}">export pubkey</a>'
    )
    ops = tables.TemplateColumn(
        '<a href="{% url \'ca:build_req\' record.dgst %}">build req</a>  '
        '<a href="{% url \'ca:delete_key\' record.dgst %}">delete</a>'
    )

    class Meta:
        model = PubKey
        fields = ('dgst', 'certs')
        template_name = 'django_tables2/bootstrap.html'


class CertTable(tables.Table):
    ops = tables.TemplateColumn(
        '<a href="{% url \'ca:delete_cert\' record.dgst %}">delete</a>'
    )

    class Meta:
        model = Cert
        fields = ('dgst', 'sn', 'cn', 'issuer',
                  'notbefore', 'notafter', 'ca')
        template_name = 'django_tables2/bootstrap.html'
