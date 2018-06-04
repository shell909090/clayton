from __future__ import unicode_literals

from django.db import models

# Create your models here.


class PubKey(models.Model):
    dgst = models.CharField(max_length=33, primary_key=True)
    pub = models.TextField(null=True)
    key = models.TextField()


class Cert(models.Model):
    dgst = models.CharField(max_length=33, primary_key=True)
    status = models.IntegerField()
    sn = models.CharField(max_length=30)
    sub = models.CharField(max_length=200)
    email = models.CharField(max_length=30)
    cn = models.CharField(max_length=100)
    notbefore = models.DateTimeField()
    notafter = models.DateTimeField()
    issuer = models.ForeignKey('self', null=True)
    usage = models.CharField(max_length=30)
    vtype = models.IntegerField()
    keyid = models.CharField(max_length=100)
    ca = models.BooleanField()
    alternative = models.TextField(null=True)
    certfile = models.TextField()
    key = models.ForeignKey('PubKey', null=True)

    class Meta:
        unique_together = (
            ("issuer", "sn"),
            ("sub", "keyid"),
        )

    def __str__(self):
        return '%s %s' % (self.sn, self.sub)
