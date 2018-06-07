#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.


class PubKey(models.Model):
    dgst = models.CharField(max_length=33, primary_key=True)
    pub = models.TextField(null=True)
    key = models.TextField()

    def certs(self):
        return Cert.objects.filter(key=self).count()


class Cert(models.Model):
    dgst = models.CharField(max_length=33, primary_key=True)
    status = models.IntegerField()
    sn = models.CharField(max_length=30)
    sub = models.CharField(max_length=200)
    cn = models.CharField(max_length=100)
    notbefore = models.DateTimeField()
    notafter = models.DateTimeField()
    issuer = models.ForeignKey('self', null=True)
    keyid = models.CharField(max_length=100)
    alternative = models.TextField(null=True)
    certfile = models.TextField()
    key = models.ForeignKey('PubKey', null=True, on_delete=models.DO_NOTHING)

    class Meta:
        unique_together = (
            ("issuer", "sn"),
        )

    def __str__(self):
        return self.dgst
