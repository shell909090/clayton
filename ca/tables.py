#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-05
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
import django_tables2 as tables

from .models import PubKey, Cert


class PubKeyTable(tables.Table):
    dgst = tables.TemplateColumn(
        '<a href="{% url \'ca:detail_key\' record.dgst %}">{{record.dgst}}</a>'
        '  <span class="badge">{{record.cert_count}}</span>'
    )
    ops = tables.TemplateColumn(
        '<a href="{% url \'ca:remove_key\' record.dgst %}">remove</a>'
    )

    class Meta:
        model = PubKey
        fields = ('dgst', 'keytype', 'size')
        template_name = 'django_tables2/bootstrap.html'
        attrs = {'class': 'table-striped table-condensed table-responsive'}


STATUS_COLOR_MAP = {
    0: '',
    42: 'warning',
}


class CertTable(tables.Table):
    dgst = tables.TemplateColumn(
        '<a href="{% url \'ca:detail_cert\' record.dgst %}">'
        '{{record.dgst}}</a>'
        '  <span class="badge">{{record.signed_count}}</span>'
    )
    issuer = tables.TemplateColumn(
        '{%if record.issuer%}'
        '<a href="{% url \'ca:detail_cert\' record.issuer %}">'
        '{{record.issuer}}</a>{%else%}--{%endif%}'
    )
    key = tables.TemplateColumn(
        '{%if record.key%}'
        '<a href="{% url \'ca:detail_key\' record.key_id %}">'
        '{{record.key_id}}</a>{%else%}--{%endif%}'
    )
    notbefore = tables.DateColumn()
    notafter = tables.DateColumn()
    ops = tables.TemplateColumn(
        '<a href="{% url \'ca:revoke_cert\' record.dgst %}">revoke</a>  '
        '<a href="{% url \'ca:remove_cert\' record.dgst %}">remove</a>'
    )

    class Meta:
        model = Cert
        fields = ('dgst', 'sn', 'cn', 'issuer', 'key',
                  'ca', 'notbefore', 'notafter')
        template_name = 'django_tables2/bootstrap.html'
        attrs = {
            'id': 'cert_list',
            'class': 'table-striped table-condensed table-responsive'
        }
        row_attrs = {
            'class': lambda record: STATUS_COLOR_MAP.get(record.status, ''),
        }
