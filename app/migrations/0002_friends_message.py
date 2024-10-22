# Generated by Django 4.0.1 on 2023-03-22 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app01', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='friends',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user1', models.CharField(max_length=32, verbose_name='账号')),
                ('user1name', models.CharField(max_length=64, verbose_name='我的姓名')),
                ('user2', models.CharField(max_length=32, verbose_name='账号')),
                ('user2name', models.CharField(max_length=64, verbose_name='朋友姓名')),
                ('user2Bname', models.CharField(default='无', max_length=64, verbose_name='朋友备注')),
                ('user1ID', models.IntegerField(blank=True, default=0, null=True, verbose_name='我的ID')),
                ('user2ID', models.IntegerField(blank=True, default=0, null=True, verbose_name='朋友ID')),
            ],
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user1', models.CharField(max_length=32, verbose_name='发送者')),
                ('user2', models.CharField(max_length=32, verbose_name='接收者')),
                ('message', models.TextField(blank=True, default='', null=True, verbose_name='内容')),
                ('encrypt', models.CharField(max_length=32, verbose_name='加密算法')),
                ('view', models.CharField(default='0', max_length=32, verbose_name='是否查看')),
                ('user1ID', models.IntegerField(blank=True, default=0, null=True, verbose_name='发送者ID')),
                ('user2ID', models.IntegerField(blank=True, default=0, null=True, verbose_name='接收者ID')),
            ],
        ),
    ]