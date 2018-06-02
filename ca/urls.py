#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-02
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'a',
        views.list_ca, name='list_ca'),
    url(r'ba',
        views.build_ca, name='build_ca'),
    url(r'd/(?P<dgst>[0-9a-f]{32})',
        views.cert_detail, name='cert_detail'),
    url(r'c/(?P<dgst>[0-9a-f]*)',
        views.list_cert, name='list_cert'),
    url(r'ip',
        views.import_pem, name='import_pem'),
    url(r'bc',
        views.build_cert, name='build_cert'),
    url(r'br',
        views.build_req, name='build_req'),
    url(r'sr/(?P<dgst>[0-9a-f]{32})',
        views.sign_req, name='sign_req'),
    url(r'ep/(?P<dgst>[0-9a-f]{32})',
        views.export_pem, name='export_pem'),
    url(r'ed/(?P<dgst>[0-9a-f]{32})',
        views.export_der, name='export_der'),
    url(r'ek/(?P<dgst>[0-9a-f]{32})',
        views.export_key, name='export_key'),
    url(r'ec/(?P<dgst>[0-9a-f]{32})',
        views.export_chain, name='export_chain'),
    url(r'ep12/(?P<dgst>[0-9a-f]{32})',
        views.export_pkcs12, name='export_pkcs12'),
    url(r'mm/(?P<dgst>[0-9a-f]{32})',
        views.mail_me, name='mail_me'),
    url(r'rc/(?P<dgst>[0-9a-f]{32})',
        views.revoke_cert, name='revoke_cert'),
    url(r'(?P<dgst>[0-9a-f]{32}).crl',
        views.show_crl, name='show_crl'),
]
