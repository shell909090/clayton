#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models


class PubKey(models.Model):

    KEY_CHOICES = (
        (1, 'RSAPrivateKey'),
        (2, 'RSAPublicKey'),
        (3, 'ECCPrivateKey'),
        (4, 'ECCPublicKey'),
    )

    dgst = models.CharField(max_length=33, primary_key=True)
    keytype = models.IntegerField(choices=KEY_CHOICES)
    size = models.IntegerField()
    dat = models.BinaryField()

    def cert_count(self):
        return Cert.objects.filter(key=self).count()

    def __str__(self):
        return self.dgst


class Cert(models.Model):
    dgst = models.CharField(max_length=33, primary_key=True)
    status = models.IntegerField()
    sn = models.CharField(max_length=30)
    sub = models.CharField(max_length=200)
    cn = models.CharField(max_length=100)
    notbefore = models.DateTimeField()
    notafter = models.DateTimeField()
    issuer = models.ForeignKey(
        'self', null=True,
        on_delete=models.DO_NOTHING, db_constraint=False)
    ca = models.BooleanField()
    authkeyid = models.CharField(max_length=65)
    keyid = models.CharField(max_length=65)
    alternative = models.TextField(null=True)
    dat = models.BinaryField()
    key = models.ForeignKey(
        'PubKey', null=True, related_name='certs',
        on_delete=models.DO_NOTHING, db_constraint=False)

    class Meta:
        unique_together = (
            ("issuer", "sn"),
        )

    def __str__(self):
        return self.dgst

    def signed_count(self):
        return Cert.objects.filter(issuer=self).count()
