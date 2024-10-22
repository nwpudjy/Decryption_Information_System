from django.db import models
import datetime
#用户信息
class UserInfo(models.Model):
    user = models.CharField(verbose_name="账号", max_length=32)
    name = models.CharField(verbose_name="姓名", max_length=16)
    email = models.EmailField(verbose_name="邮箱", max_length=32, null=True, blank=True)
    phone = models.CharField(verbose_name="手机号", max_length=32, default=0, null=True, blank=True)
    password = models.CharField(verbose_name="密码", max_length=64)
#邮件信息
class Message(models.Model):
    user1 = models.CharField(verbose_name="发送者", max_length=32)
    user2 = models.CharField(verbose_name="接收者", max_length=32)
    name1 = models.CharField(verbose_name="发送者姓名", default='', max_length=16)
    name2 = models.CharField(verbose_name="接收者姓名", default='', max_length=16)
    subject = models.CharField(verbose_name="主题", default='', max_length=256)
    message = models.TextField(verbose_name="内容", default="", null=True, blank=True)
    time = models.TimeField(verbose_name="创建时间", default=datetime.time(0, 0))
    date = models.DateField(verbose_name="创建日期", default=datetime.date(2023, 1, 1))
    encrypt = models.CharField(verbose_name="加密算法",default='0', max_length=32)
    view = models.CharField(verbose_name="是否查看", default="0", max_length=32)
    user1ID = models.IntegerField(verbose_name="发送者ID", default=0, null=True, blank=True)
    user2ID = models.IntegerField(verbose_name="接收者ID", default=0, null=True, blank=True)

#好友信息
class friends(models.Model):
    user1 = models.CharField(verbose_name="账号", max_length=32)
    user1name = models.CharField(verbose_name="我的姓名", max_length=64)
    user2 = models.CharField(verbose_name="账号", max_length=32)
    user2name = models.CharField(verbose_name="朋友姓名", max_length=64)
    user2Bname = models.CharField(verbose_name="朋友备注", default="无",max_length=64)
    user1ID = models.IntegerField(verbose_name="我的ID", default=0, null=True, blank=True)
    user2ID = models.IntegerField(verbose_name="朋友ID", default=0, null=True, blank=True)

class view(models.Model):
    times = models.IntegerField(verbose_name="访问次数", default=0, null=True, blank=True)
    usernum = models.IntegerField(verbose_name="用户总数", default=0, null=True, blank=True)

#密钥交换
class exchange(models.Model):
    user1 = models.CharField(verbose_name="发送者", max_length=32)
    user2 = models.CharField(verbose_name="接收者", max_length=32)
    name1 = models.CharField(verbose_name="发送者姓名", default='', max_length=16)
    name2 = models.CharField(verbose_name="接收者姓名", default='', max_length=16)
    p = models.CharField(verbose_name="p", default='', max_length=256)
    g = models.CharField(verbose_name="g", default='', max_length=256)
    encrypt = models.CharField(verbose_name="加密算法", default='0', max_length=32)
    a = models.CharField(verbose_name="a", default='', max_length=256)
    b = models.CharField(verbose_name="b", default='', max_length=256)
    view = models.CharField(verbose_name="是否查看", default="0", max_length=32)
    user1ID = models.IntegerField(verbose_name="发送者ID", default=0, null=True, blank=True)
    user2ID = models.IntegerField(verbose_name="接收者ID", default=0, null=True, blank=True)

#密钥管理
class cyber(models.Model):
    user = models.CharField(verbose_name="发送者", max_length=32)
    userID = models.IntegerField(verbose_name="ID", default=0, null=True, blank=True)
    name = models.CharField(verbose_name="姓名", max_length=16)
    cyber = models.CharField(verbose_name="密钥", max_length=256)
    cybername = models.CharField(verbose_name="密钥名称", max_length=256)
    length = models.IntegerField(verbose_name="密钥长度", default=0, null=True, blank=True)
    time = models.TimeField(verbose_name="创建时间", default=datetime.time(0, 0))
    date = models.DateField(verbose_name="截止日期", default=datetime.date(2023, 1, 1))



