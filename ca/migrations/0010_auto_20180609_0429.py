# Generated by Django 2.0.6 on 2018-06-09 04:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ca', '0009_cert_ca'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cert',
            name='certfile',
        ),
        migrations.RemoveField(
            model_name='pubkey',
            name='key',
        ),
        migrations.AddField(
            model_name='cert',
            name='authkeyid',
            field=models.CharField(default=0, max_length=65),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='cert',
            name='dat',
            field=models.BinaryField(default=b''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='pubkey',
            name='dat',
            field=models.BinaryField(default=b''),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='cert',
            name='issuer',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='ca.Cert'),
        ),
        migrations.AlterField(
            model_name='cert',
            name='keyid',
            field=models.CharField(max_length=65),
        ),
    ]
