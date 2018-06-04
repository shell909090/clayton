# -*- coding: utf-8 -*-
# Generated by Django 1.10.7 on 2018-06-04 11:17
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ca', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cert',
            name='keyid',
            field=models.CharField(default='', max_length=100),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name='cert',
            unique_together=set([('issuer', 'sn'), ('sub', 'keyid')]),
        ),
    ]
