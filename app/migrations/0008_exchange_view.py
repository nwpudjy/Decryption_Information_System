# Generated by Django 4.0.1 on 2023-04-13 02:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app01', '0007_cyber_date_message_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='exchange',
            name='view',
            field=models.CharField(default='0', max_length=32, verbose_name='是否查看'),
        ),
    ]