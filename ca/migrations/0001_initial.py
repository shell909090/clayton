# Generated by Django 2.0.6 on 2018-06-09 09:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Cert',
            fields=[
                ('dgst', models.CharField(max_length=33, primary_key=True, serialize=False)),
                ('status', models.IntegerField()),
                ('sn', models.CharField(max_length=30)),
                ('sub', models.CharField(max_length=200)),
                ('cn', models.CharField(max_length=100)),
                ('notbefore', models.DateTimeField()),
                ('notafter', models.DateTimeField()),
                ('ca', models.BooleanField()),
                ('authkeyid', models.CharField(max_length=65)),
                ('keyid', models.CharField(max_length=65)),
                ('alternative', models.TextField(null=True)),
                ('dat', models.BinaryField()),
                ('issuer', models.ForeignKey(db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='ca.Cert')),
            ],
        ),
        migrations.CreateModel(
            name='PubKey',
            fields=[
                ('dgst', models.CharField(max_length=33, primary_key=True, serialize=False)),
                ('keytype', models.IntegerField(choices=[(1, 'RSAPrivateKey'), (2, 'RSAPublicKey'), (3, 'ECCPrivateKey'), (4, 'ECCPublicKey')])),
                ('size', models.IntegerField()),
                ('dat', models.BinaryField()),
            ],
        ),
        migrations.AddField(
            model_name='cert',
            name='key',
            field=models.ForeignKey(db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='certs', to='ca.PubKey'),
        ),
        migrations.AlterUniqueTogether(
            name='cert',
            unique_together={('issuer', 'sn')},
        ),
    ]
