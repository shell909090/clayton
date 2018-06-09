#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2018-06-04
@author: Shell.Xu
@copyright: 2018, Shell.Xu <shell909090@gmail.com>
@license: BSD-3-clause
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
from django import forms

from cryptography.x509.oid import ExtendedKeyUsageOID

from . import crypt


class BuildRSAForm(forms.Form):
    size = forms.IntegerField(initial=2048)


class BuildECForm(forms.Form):
    curve_names = sorted(crypt.CURVE_MAPPING.keys())
    CURVE_CHOICES = zip(curve_names, curve_names)
    curve = forms.ChoiceField(choices=CURVE_CHOICES, initial='secp256r1')


class TextForm(forms.Form):
    txt = forms.CharField(widget=forms.Textarea)


class DoubleTextForm(forms.Form):
    txt1 = forms.CharField(widget=forms.Textarea)
    txt2 = forms.CharField(widget=forms.Textarea)


class UploadForm(forms.Form):
    upload = forms.FileField()


EXT_USAGE_CHOICES = (
    ('', '--'),
    (ExtendedKeyUsageOID.SERVER_AUTH._name,
     'SSL/TLS Web Server Authentication'),
    (ExtendedKeyUsageOID.CLIENT_AUTH._name,
     'SSL/TLS Web Client Authentication'),
    (ExtendedKeyUsageOID.CODE_SIGNING._name,
     'Code signing'),
    (ExtendedKeyUsageOID.EMAIL_PROTECTION._name,
     'E-mail Protection (S/MIME)'),
    (ExtendedKeyUsageOID.TIME_STAMPING._name,
     'Trusted Timestampin'),
    (ExtendedKeyUsageOID.OCSP_SIGNING._name,
     'OCSP Signin'),
)


class ReqForm(forms.Form):
    cn = forms.CharField(max_length=50)
    country = forms.CharField(max_length=3, required=False)
    province = forms.CharField(max_length=10, required=False)
    city = forms.CharField(max_length=30, required=False)
    org = forms.CharField(max_length=30, required=False)
    email = forms.CharField(max_length=50, required=False)
    ou = forms.CharField(max_length=30, required=False)
    alternative = forms.CharField(max_length=200, required=False,
                                  widget=forms.Textarea)
    usage = forms.ChoiceField(choices=EXT_USAGE_CHOICES, required=False)
    ca = forms.BooleanField(required=False)
    selfsign = forms.BooleanField(required=False)


class SignConfirmForm(forms.Form):
    csr = forms.CharField(max_length=100000,
                          widget=forms.HiddenInput())
    days = forms.CharField(max_length=5, required=False)
