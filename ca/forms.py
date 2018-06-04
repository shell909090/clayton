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


class CertForm(forms.ModelForm):
    certchain = forms.FileField()
    prikey = forms.FileField()

    class Meta:
        model = models.Cert
        fields = ['certchain', 'prikey']
