# Generated by Django 5.2.1 on 2025-05-26 11:05

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('NA_Apps', '0008_log_command_log_output'),
        ('segmentation', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='segmentation',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='segmentation.segmentation'),
        ),
    ]
