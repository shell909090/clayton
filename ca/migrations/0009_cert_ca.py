# -*- coding: utf-8 -*-
# Generated by Django 1.10.7 on 2018-06-08 17:35
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ca', '0008_pubkey_size'),
    ]

    operations = [
        migrations.AddField(
            model_name='cert',
            name='ca',
            field=models.BooleanField(default=False),
            preserve_default=False,
        ),
    ]