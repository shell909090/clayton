#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-02
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from django.conf.urls import url

from . import views


app_name = 'ca'
urlpatterns = [
    url(r'^k/',
        views.ListKeyView.as_view(), name='list_key'),
    url(r'^dk/(?P<dgst>[0-9A-F]{16})',
        views.detail_key, name='detail_key'),
    url(r'^rk/(?P<dgst>[0-9A-F]{16})',
        views.remove_key, name='remove_key'),
    url(r'^brsa',
        views.build_rsa, name='build_rsa'),
    url(r'^bec',
        views.build_ec, name='build_ec'),
    url(r'^enc/(?P<dgst>[0-9A-F]{16})',
        views.encrypt, name='encrypt'),
    url(r'^dec/(?P<dgst>[0-9A-F]{16})',
        views.decrypt, name='decrypt'),
    url(r'^s/(?P<dgst>[0-9A-F]{16})',
        views.sign, name='sign'),
    url(r'^v/(?P<dgst>[0-9A-F]{16})',
        views.verify, name='verify'),
    url(r'^ik',
        views.import_key, name='import_key'),
    url(r'^ek/(?P<dgst>[0-9A-F]{16})',
        views.export_key, name='export_key'),
    url(r'^epk/(?P<dgst>[0-9A-F]{16})',
        views.export_pubkey, name='export_pubkey'),
    url(r'^eps/(?P<dgst>[0-9A-F]{16})',
        views.export_sshpub, name='export_sshpub'),
    url(r'^br/(?P<dgst>[0-9A-F]{16})',
        views.build_req, name='build_req'),

    url(r'^c/(?P<dgst>[0-9A-F]{0,16})',
        views.ListCertView.as_view(), name='list_cert'),
    url(r'^dc/(?P<dgst>[0-9A-F]{16})',
        views.detail_cert, name='detail_cert'),
    url(r'^ip',
        views.import_pem, name='import_pem'),
    url(r'^rc/(?P<dgst>[0-9A-F]{16})',
        views.remove_cert, name='remove_cert'),
    url(r'^bc/(?P<dgst>[0-9A-F]{16})',
        views.build_cert, name='build_cert'),
    url(r'^sr/(?P<dgst>[0-9A-F]{16})',
        views.sign_req, name='sign_req'),
    url(r'^ep/(?P<dgst>[0-9A-F]{16})',
        views.export_pem, name='export_pem'),
    url(r'^ed/(?P<dgst>[0-9A-F]{16})',
        views.export_der, name='export_der'),
    url(r'^ec/(?P<dgst>[0-9A-F]{16})',
        views.export_chain, name='export_chain'),
    url(r'^ep12/(?P<dgst>[0-9A-F]{16})',
        views.export_pkcs12, name='export_pkcs12'),
    url(r'^rvk/(?P<dgst>[0-9A-F]{16})',
        views.revoke_cert, name='revoke_cert'),
    url(r'^(?P<dgst>[0-9A-F]{16}).crl',
        views.show_crl, name='show_crl'),
]
