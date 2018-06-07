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

from . import models


class ImpKeyForm(forms.Form):
    prikey = forms.FileField()


class ImpCertForm(forms.ModelForm):
    certchain = forms.FileField()
    prikey = forms.FileField()

    class Meta:
        model = models.Cert
        fields = ['certchain', 'prikey']


class ReqForm(forms.Form):
    cn = forms.CharField(max_length=50)
    country = forms.CharField(max_length=3, required=False)
    province = forms.CharField(max_length=10, required=False)
    city = forms.CharField(max_length=30, required=False)
    org = forms.CharField(max_length=50, required=False)
    email = forms.CharField(max_length=50, required=False)
    ou = forms.CharField(max_length=50, required=False)
    alternative = forms.CharField(max_length=200, required=False)
    usage = forms.ChoiceField(choices=(
        ('', '--'),
        ('serverAuth', 'SSL/TLS Web Server Authentication'),
        ('clientAuth', 'SSL/TLS Web Client Authentication'),
        ('codeSigning', 'Code signing'),
        ('emailProtection', 'E-mail Protection (S/MIME)'),
        ('timeStamping', 'Trusted Timestampin'),
        ('OCSPSigning', 'OCSP Signin'),
        ('ipsecIKE', 'ipsec Internet Key Exchang'),
        ('msCodeInd', 'Microsoft Individual Code Signing (authenticode)'),
        ('msCodeCom', 'Microsoft Commercial Code Signing (authenticode)'),
        ('msCTLSign', 'Microsoft Trust List Signin'),
        ('msEFS', 'Microsoft Encrypted File Syste'),
    ), required=False)
    ca = forms.BooleanField(required=False)
    selfsign = forms.BooleanField(required=False)
    days = forms.CharField(max_length=3, required=False)

    def get_subj(self):
        subj = {}
        mapping = [
            ('CN', 'cn'), ('C', 'country'), ('ST', 'province'), ('L', 'city'),
            ('O', 'org'), ('OU', 'ou'), ('emailAddress', 'email')]
        for n, m in mapping:
            if self.cleaned_data[m]:
                subj[n] = self.cleaned_data[m].strip()
        return ''.join(['/%s=%s' % (k, v) for k, v in subj.items()]) + '/'


class SignForm(forms.Form):
    req = forms.FileField()
    days = forms.CharField(max_length=3, required=False)
