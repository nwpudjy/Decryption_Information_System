import datetime
import os, sys
import random
import time
from collections import Counter
from io import BytesIO

import pymysql as pymysql
import numpy as np
import time

import pythoncom
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.forms import ModelForm, Form
from django import forms
from django.http import HttpResponse, JsonResponse, Http404
from django.conf import settings
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django_redis import get_redis_connection
from django.db.models import Q
from django_redis.serializers import json
from openpyxl import load_workbook
import win32com.client
from app01 import models
from django.utils.safestring import mark_safe
import copy

from django.http import HttpResponse, Http404, StreamingHttpResponse
import hashlib
from django.shortcuts import render, HttpResponse
from app01.encrypt import sm4,aes,des,rc4,sm3,rsa,elgamal

import urllib
import ssl
from urllib import request, parse
import json

#字符串转二进制
def char_b(text):
    b_text = text.encode()
    list_b_text = list(b_text)
    re = []
    for num in list_b_text:
        re.append(bin(num)[2:].zfill(8))

    bin_str = ''.join(re)
    return bin_str
#二进制转字符串
def bin_char(dec):
    list_bin = [dec[i:i + 8] for i in range(0, len(dec), 8)]
    list_int = []
    for bin_s in list_bin:
        list_int.append(int(bin_s, 2))
    try:
        ans = bytes(list_int).decode()
    except:
        ans = '秘钥错误'
    return ans
#二进制串转16进制
def change_16(a):
    str_en = []
    for i in range(int(len(a) / 4)):
        s = a[i * 4:i * 4 + 4]
        m = 8
        sum = 0
        for j in s:
            sum += (int(j) - 0) * m
            m = int(m / 2)
        r = hex(sum)[2:]
        str_en.append(r)
    str_en = ''.join(str_en)
    return str_en
#16进制串转二进制串
def change_2(b):
    str_de = []
    for i in b:
        if i>='a':
            m = ord(i) - ord('a') + 10
        else:
            m = ord(i) - ord('0')
        str_de.append(bin(m)[2:].zfill(4))
    str_de = ''.join(str_de)
    return str_de
#二进制转十进制
def bin_d(a):
    d = []
    for i in range(int(len(a)/8)+1):
        s = a[8*i:8*i+8]
        b = 1
        sum = 0
        for j in range(len(s)):
            t = int(s[len(s)-j-1])-int('0')
            sum += t*b
            b *= 2
        d.append(sum)
    return d
#十进制转二进制
def d_bin(a):
    b = []
    for i in a:
        b.append(bin(i)[2:].zfill(8))
    b = ''.join(b)
    return b


# client_id 为官网获取的AK， client_secret 为官网获取的SK
def get_token():
    context = ssl._create_unverified_context()
    host = 'https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=0TgKq0soxmDV6bq6D0cdmo0y&client_secret=0U94GGCbjMH3bMGzjahmQsgdRgOwn9EM'
    request = urllib.request.Request(host)
    request.add_header('Content-Type', 'application/json; charset=UTF-8')
    response = urllib.request.urlopen(request, context=context)
    # 获取请求结果
    content = response.read()
    # 转换为字符
    content = bytes.decode(content)
    # 转换为字典
    content = eval(content[:-1])
    return content['access_token']


# 转换图片
# 读取文件内容，转换为base64编码
# 二进制方式打开图文件
def imgdata(file1path, file2path):
    import base64
    f = open(r'%s' % file1path, 'rb')
    pic1 = base64.b64encode(f.read())
    f.close()
    f = open(r'%s' % file2path, 'rb')
    pic2 = base64.b64encode(f.read())
    f.close()
    # 将图片信息格式化为可提交信息，这里需要注意str参数设置
    params = json.dumps(
        [{"image": str(pic1, 'utf-8'), "image_type": "BASE64", "face_type": "LIVE", "quality_control": "LOW"},
         {"image": str(pic2, 'utf-8'), "image_type": "BASE64", "face_type": "IDCARD", "quality_control": "LOW"}]
    )
    return params.encode(encoding='UTF8')


# 进行对比获得结果
def img(file1path, file2path):
    token = get_token()
    # 人脸识别API
    # url = 'https://aip.baidubce.com/rest/2.0/face/v3/detect?access_token='+token
    # 人脸对比API
    context = ssl._create_unverified_context()
    # url = 'https://aip.baidubce.com/rest/2.0/face/v3/match?access_token=' + token
    params = imgdata(file1path, file2path)

    request_url = "https://aip.baidubce.com/rest/2.0/face/v3/match"
    request_url = request_url + "?access_token=" + token
    request = urllib.request.Request(url=request_url, data=params)
    request.add_header('Content-Type', 'application/json')
    response = urllib.request.urlopen(request, context=context)
    content = response.read()
    print(content)
    str1 = str(content, encoding="utf-8")
    str1 = str1.replace('null',"'null'")
    str1 = eval(str1)
    if str1['result'] == 'null':
        print('检测失败')
        return 2
    else:
        content = eval(content)
        # # 获得分数
        score = content['result']['score']
        print(score)
        if score > 80:
            return 1
        else:
            return 2


#人脸识别
def Face(request):

    if request.method == 'GET':
        if request.session.get('info'):
            name = request.GET.get('name')
            return render(request, 'ltest.html',{"name":name})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})

    formdate = request.FILES.get('file')
    id = request.session['info'].get('id')
    default_storage.save('app01/static/img/'+formdate.name,ContentFile(formdate.read()))

    file1path = 'app01/static/img/'+str(id)+'.jpg'
    file2path = 'app01/static/img/'+formdate.name
    res = img(file1path, file2path)
    default_storage.delete('app01/static/img/'+formdate.name)
    if res == 1:
        return JsonResponse({"code":200,"message":"检测通过"})
    else:
        return JsonResponse({"code": 400, "message": "检测未通过"})
#密钥管理
def Cybermanage(request):
    if request.method == 'GET':
        if request.session.get('info'):
            name = request.GET.get('name')
            form = models.cyber.objects.filter(user=request.session['info'].get('user')).all()
            mima = 'nhfmdjsicndjcis9'
            mima = char_b(mima)  # 初始秘钥二进制
            mima = bin_d(mima)  # 初始秘钥十进制
            for i in form:
                text = change_2(i.cyber)
                text = bin_d(text)
                cyb = rc4.RC4(mima, text)
                encry = []
                for j in range(len(text)):
                    encry.append(text[j] ^ cyb[j])
                encry = d_bin(encry)
                l = len(encry)
                encry = encry[:l - 16]
                encry = bin_char(encry)
                i.cyber = encry
            return render(request, 'cybermanage.html',{"name":name,"form":form})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})

    cyber = request.POST.get('cyber')
    #加密存储
    cyber = char_b(cyber)  # 初始秘钥二进制
    cyber = bin_d(cyber)  # 初始秘钥十进制
    mima = 'nhfmdjsicndjcis9'
    mima = char_b(mima)  # 初始秘钥二进制
    mima = bin_d(mima)  # 初始秘钥十进制
    text = rc4.RC4(mima,cyber)
    print('444',cyber)
    encry = []
    for i in range(len(text)):
        encry.append(text[i] ^ cyber[i])
    encry = d_bin(encry)
    cyber = change_16(encry)

    cybername = request.POST.get('cybername')
    cyberlen = int(request.POST.get('cyberlen'))
    d = datetime.datetime.now()
    date = d.date()
    time = d.time()
    models.cyber.objects.create(
        user=request.session['info'].get('user'),
        userID = request.session['info'].get('id'),
        cyber=cyber,
        cybername=cybername,
        length=cyberlen,
        time=time,
        date=date
    )
    return redirect("/cybermanage/")

def Delete_cyber(request):
    models.cyber.objects.filter(id=request.GET.get('id')).delete()
    return redirect("/cybermanage/")

def Chack(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        id = request.GET.get('id')
        form = models.Message.objects.filter(id=id).first()
        models.Message.objects.filter(id=id).update(view='1')
        message= form.message
        return render(request, "chack.html", {'aa': en,"form":form,"message":message})





#计算 a^p mod g
def momi(a,p,g):
    s = 1
    t = a
    m = bin(p)[2:]
    for i in m[::-1]:
        if i=='1':
            s *= t
        t *= t
        t %= g
        s %= g
    return s


def RSA(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        f = rsa.put_p_q(524)
        fi = f[2]
        e = (f[3])
        n = (f[4])
        d = hex(rsa.put_d(e,fi))
        e = hex(f[3])
        n = hex(f[4])
        return render(request, "rsa.html",{'aa':en,'encryption':'RSA','n':n,'e':e,'d':d})
    text = request.POST.get('text')
    if text == "":
        return redirect("/rsa/")
    dec = request.POST.get('dec')
    e = int(request.POST.get('e'),16)
    d = int(request.POST.get('d'),16)
    n = int(request.POST.get('n'),16)
    if dec == '1':
        text = char_b(text)
        print('\n','t',text,'\n')
        text = int(text,2)
        aa = (bin(momi(text,e,n))[2:])
    else:
        text = int(text,2)
        aa = bin_char(bin(momi(text,d,n))[2:])

    return redirect("/rsa/?aa=" + aa)


def Elgamal(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        f = elgamal.elgamal()
        p,a,y,d,k = f
        p = hex(p)
        a = hex(a)
        y = hex(d)
        k = hex(k)
        d = hex(d)
        return render(request, "elgamal.html",{'aa':en,'encryption':'Elgamal','p':p,'a':a,'y':y,'d':d,'k':k})
    text = request.POST.get('text')
    if text == "":
        return redirect("/rsa/")
    dec = request.POST.get('dec')
    p = int(request.POST.get('p'),16)
    d = int(request.POST.get('d'),16)
    a = int(request.POST.get('a'),16)
    k = int(request.POST.get('k'), 16)
    y = int(request.POST.get('y'), 16)
    if dec == '1':
        text = char_b(text)
        text = int(text,2)
        aa = elgamal.en_elgamal(text,p,a,y,d,k)
    else:
        aa = elgamal.de_elgamal(text,d,p)
        aa = bin_char(bin(aa)[2:])

    return redirect("/elgamal/?aa=" + aa)
def DES2(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        return render(request, "des2.html",{'aa':en,'encryption':'二重DES'})
    text = request.POST.get('text')

    if text == "":
        return redirect("/des2/")
    dec = request.POST.get('dec')
    cyber1 = request.POST.get('cyber1')
    cyber2 = request.POST.get('cyber2')
    if len(cyber1) < 8:
        cyber1 = cyber1.zfill(8)
    elif len(cyber1) > 8:
        cyber1 = cyber1[0:8]
    if len(cyber2) < 8:
        cyber2 = cyber2.zfill(8)
    elif len(cyber2) > 8:
        cyber2 = cyber2[0:8]
    aa = ''
    if dec == '1':
        aa = des.DES(text, 1, cyber1)
        aa = des.DES(aa,3,cyber2)
        aa = change_16(aa)
    elif dec == '2':
        text = change_2(text)
        aa = des.DES(text, 2, cyber2)
        aa = des.DES(aa,2,cyber1)
    return redirect("/des2/?aa=" + aa)

def DES3(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        return render(request, "des3.html",{'aa':en,'encryption':'三重DES'})
    text = request.POST.get('text')
    if text == "":
        return redirect("/des3/")
    dec = request.POST.get('dec')
    cyber1 = request.POST.get('cyber1')
    cyber2 = request.POST.get('cyber2')
    cyber3 = request.POST.get('cyber3')
    if len(cyber1) < 8:
        cyber1 = cyber1.zfill(8)
    elif len(cyber1) > 8:
        cyber1 = cyber1[0:8]
    if len(cyber2) < 8:
        cyber2 = cyber2.zfill(8)
    elif len(cyber2) > 8:
        cyber2 = cyber2[0:8]
    if len(cyber3) < 8:
        cyber3 = cyber3.zfill(8)
    elif len(cyber3) > 8:
        cyber3 = cyber3[0:8]
    aa = ''
    if dec == '1':
        aa = des.DES(text, 1, cyber1)
        aa = des.DES(aa,1,cyber2)
        aa = des.DES(aa,1,cyber3)
        aa = change_16(aa)
    elif dec == '2':
        text = change_2(text)
        aa = des.DES(text, 2, cyber3)
        aa = des.DES(aa, 2, cyber2)
        aa = des.DES(aa,2,cyber1)
    return redirect("/des3/?aa=" + aa)

def DES(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        print(en)
        if en == None:
            en = ''
        return render(request, "main.html",{'aa':en,'encryption':'DES'})

    text = request.POST.get('text')
    if text == "":
        return redirect("/main/")
    dec = request.POST.get('dec')
    cyber = request.POST.get('cyber')
    if len(cyber) < 8:
        cyber = cyber.zfill(8)
    elif len(cyber) > 8:
        cyber = cyber[0:8]

    aa = ''
    if dec == '1':
        aa = des.DES(text,1,cyber)
        aa = change_16(aa)
    elif dec == '2':
        text = change_2(text)
        aa = des.DES(text,2,cyber)

    return redirect("/des/?aa="+aa)

def SM4(request):
    if request.method == 'GET':

        en = request.GET.get('aa')
        print(en)
        if en == None:
            en = ''
        return render(request, "SM4.html", {'aa': en, 'encryption': 'SM4'})
    text = request.POST.get('text')
    if text == "":
        return redirect("/sm4/")
    dec = request.POST.get('dec')
    cyber = request.POST.get('cyber')
    aa = sm4.SM4(text,cyber,dec)
    return redirect("/sm4/?aa=" + aa)

def AES(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        print(en)
        if en == None:
            en = ''
        return render(request, "aes.html",{'aa':en,'encryption':'AES'})
    text = request.POST.get('text')
    if text == "":
        return redirect("/aes/")
    dec = request.POST.get('dec')
    cyber = request.POST.get('cyber')
    if len(cyber)<16:
        cyber = cyber.zfill(16)
    elif len(cyber)>16:
        cyber = cyber[0:16]
    cyber = change_16(char_b(cyber))
    cyber = aes.changelr(cyber)
    if dec == '1':
        bin_str = change_16(char_b(text))
        aa = aes.AES_Encrypt(bin_str,cyber)
        aa = ''.join(aa)
    else:
        aa = aes.AES_Decrypt(text,cyber)
        aa = ''.join(aa)
        aa = change_2(aa)
        aa = bin_char(aa)

    return redirect("/aes/?aa="+aa)

def RC4(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        return render(request, "rc4.html",{'aa':en,'encryption':'RC4'})
    text = request.POST.get('text')
    if text == "":
        return redirect("/rc4/")
    dec = request.POST.get('dec')
    cyber = request.POST.get('cyber')
    if len(cyber)<16:
        cyber = cyber.zfill(16)
    elif len(cyber)>16:
        cyber = cyber[0:16]
    cyber = char_b(cyber) #初始秘钥二进制
    cyber = bin_d(cyber) #初始秘钥十进制
    if dec == '1':
        text = char_b(text)  # 明文二进制
        text = bin_d(text)  # 明文序列 十进制数
        cyber = rc4.RC4(cyber, text)  # 秘钥序列 十进制数
        encry = []
        for i in range(len(text)):
            encry.append(text[i]^cyber[i])
        encry = d_bin(encry)
        encry = change_16(encry)
    if dec == '2':
        text = change_2(text)
        text = bin_d(text)
        cyber = rc4.RC4(cyber, text)  # 秘钥序列 十进制数
        encry = []
        for i in range(len(text)):
            encry.append(text[i]^cyber[i])
        encry = d_bin(encry)
        l = len(encry)
        encry = encry[:l-16]
        encry = bin_char(encry)

    return redirect("/rc4/?aa=" + encry)

def SM3(request):
    if request.method == 'GET':
        en = request.GET.get('aa')
        if en == None:
            en = ''
        return render(request, "sm3.html",{'aa':en,'encryption':'SM3'})
    text = request.POST.get('text')
    if text == "":
        return redirect("/sm3/")
    dec = request.POST.get('dec')
    encry = sm3.sm3(dec)

    return redirect("/sm3/?aa=" + encry)




class LoginUserForm(forms.Form):
    user = forms.CharField(label="账号", widget=forms.TextInput(attrs={"class": "form-control"}), required=True)
    password = forms.CharField(label="密码",
                               widget=forms.PasswordInput(render_value=True, attrs={"class": "form-control"}),
                               required=True)

    def clean_password(self):
        pwd = self.cleaned_data.get("password")
        return pwd
# 学生登录
def login_user(request):
    if request.method == "GET":
        log = request.GET.get('log')
        form = LoginUserForm()
        return render(request, 'login_user.html', {"form": form})
    form = LoginUserForm(data=request.POST)
    if form.is_valid():

        user = form.cleaned_data.get('user')
        # master_object = models.UserInfo.objects.filter(**form.cleaned_data).first()
        master_object = models.UserInfo.objects.filter(user=user).first()
        if not master_object:
            form.add_error("password", "用户名或密码错误")
            return render(request, 'login_user.html', {"form": form})
        # cookie
        request.session["info"] = {'id': master_object.id, 'name': master_object.name, 'user': master_object.user,
                                   'flag': 'S'}
        # 登录信息保存12小时
        request.session.set_expiry(60 * 60 * 12)

        d = datetime.datetime.now()
        # models.Record.objects.create(
        #     userID=request.session['info'].get('id'),
        #     name=request.session['info'].get('name'),
        #     thing='登录',
        #     flag=1,
        #     date=d.date(),
        #     time=d.time(),
        # )
        log = request.GET.get('log')
        if log == '1':
            return redirect("/exchange/")
        if log == '2':
            return redirect("/import/")
        if log == '3':
            return redirect("/send/")
        if log == '4':
            return redirect("/receive/")
        return redirect("/import/")
    return render(request, 'login_user.html', {"form": form})

class BootModelForm(forms.ModelForm):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        for name,field in self.fields.items():
            if field.widget.attrs:
                field.widget.attrs["class"] = "form-control"
                #field.widget.attrs["placeholder"] = "请输入"+field.label
            else:
                field.widget.attrs = {"class":"form-control"}

class UserRegisterForm(BootModelForm):
    name = forms.CharField(label="姓名")
    phone = forms.CharField(label="手机号", validators=[RegexValidator(r'(1[3|4|5|6|7|8|9])\d{9}$', '手机号格式错误')])
    password = forms.CharField(
        widget=forms.PasswordInput(render_value=True),
        label="密码",
    )
    con_password = forms.CharField(label="确认密码", widget=forms.PasswordInput(render_value=True))

    class Meta:
        model = models.UserInfo
        fields = ['user', 'name', 'password', 'con_password', 'phone']

    def clean_password(self):
        pwd = self.cleaned_data.get("password")
        if len(pwd) < 0:
            raise ValidationError('密码长度不能小于8')
        return pwd

    def clean_user(self):
        user = self.cleaned_data['user']
        for i in user:
            flag = 0
            if i >='0' and i <= '9':
                flag = 1
            if i >='a' and i <= 'z':
                flag = 1
            if i >='A' and i <= 'Z':
                flag = 1
            if flag == 0:
                raise ValidationError('账号只能包含字母和数字')

        if models.UserInfo.objects.filter(user=user).exists():
            raise ValidationError('账号已存在')
        return user

    def clean_name(self):
        name = self.cleaned_data['name']
        if len(name)>32:
            raise ValidationError('姓名不合格')
        return name

    def clean_con_password(self):
        pwd = self.cleaned_data.get("password")
        con = self.cleaned_data.get("con_password")
        if pwd != con:
            raise ValidationError("密码不一致，请重新输入")
        return con

    def clean_phone(self):
        phone = self.cleaned_data['phone']
        if models.UserInfo.objects.filter(phone=phone).exists():
            raise ValidationError('手机号已注册')
        return phone


#退出
def logout(request):

    request.session.clear()
    return redirect('/des/')

# 用户注册
def Register(request):
    if request.method == "GET":
        form = UserRegisterForm()
        return render(request, 'register.html', {'form': form})
    form = UserRegisterForm(data=request.POST)
    if form.is_valid():
        form.save()
        usernum = models.view.objects.filter(id=1).first().usernum
        models.view.objects.filter(id=1).update(usernum=usernum + 1)
        return JsonResponse({'status': True, 'data': '/login/user/'})
    return JsonResponse({'status': False, 'error': form.errors})


def Message(request):
    if request.method == 'GET':
        times = models.view.objects.filter(id=1).first().times
        models.view.objects.filter(id=1).update(times = times + 1)
        times = models.view.objects.filter(id=1).first().times
        usernum = models.view.objects.filter(id=1).first().usernum

        f = request.GET.get('f')
        if request.session.get('info'):
            name = request.session['info'].get('name')
            user = request.session['info'].get('user')
        else:
            name = "未登录"
            user = ""
        return render(request, "message.html",{"name":name,"user":user,"f":f,"times":times,"usernum":usernum})


class ImportForm(forms.Form):
    user = forms.CharField(label="账号", widget=forms.TextInput(attrs={"class": "inp","value":""}), required=True)
    class Meta:
        model = models.UserInfo
        fields = ['user']
    def clean_user(self):
        user = self.cleaned_data['user']
        if models.UserInfo.objects.filter(user=user).exists():
            return user
        elif user == request.session['info'].get('user'):
            return ValidationError("不能发给自己")
        else:
            return ValidationError("用户不存在")

#加密传送
def Import(request):
    if request.method == 'GET':

        if request.session.get('info'):
            form = ImportForm()
            name = request.session['info'].get('name')
            print(name)
            return render(request, "import.html",{"name":name,"form":form})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})

    form = ImportForm(data=request.POST)
    message = request.POST['message']
    subject = request.POST['subject']
    if form.is_valid():
        user = form.cleaned_data.get('user')
        if not models.UserInfo.objects.filter(user=user).exists():
            form.add_error("user", "用户不存在")
            return render(request, 'import.html', {"form": form,"message":message,"subject":subject})
        if user == request.session['info'].get('user'):
            form.add_error("user", "不能发给自己")
            return render(request, 'import.html', {"form": form,"message":message,"subject":subject})
        d = datetime.datetime.now()
        date = d.date()
        time = d.time()
        models.Message.objects.create(
            user1=request.session['info'].get('user'),
            user2=user,
            name1 = models.UserInfo.objects.filter(id=request.session['info'].get('id')).first().name,
            name2 = models.UserInfo.objects.filter(user=user).first().name,
            subject = subject,
            message = message,
            user1ID = request.session['info'].get('id'),
            user2ID = models.UserInfo.objects.filter(user=user).first().id,
            date=date,
            time=time
        )
    else:
        form.add_error("user", "不能为空")
        return render(request, 'import.html', {"form": form,"message":message,"subject":subject})

    return redirect("/success/")

def Success(request):
    if request.method == 'GET':

        return render(request, "success.html")

def Receive(request):
    if request.method == 'GET':
        if request.session.get('info'):
            form = models.Message.objects.filter(user2=request.session['info'].get('user'))
            return render(request, "receive.html", {"form": form})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})


def Send(request):
    if request.method == 'GET':
        if request.session.get('info'):
            form = models.Message.objects.filter(user1=request.session['info'].get('user'))
            return render(request, "send.html", {"form": form})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})
class ExchangeForm(forms.Form):
    user = forms.CharField(label="账号", widget=forms.TextInput(attrs={"class": "inp","value":""}), required=True)
    p = forms.CharField(label="p", widget=forms.TextInput(attrs={"class": "inp", "value": ""}), required=True)
    g = forms.CharField(label="g", widget=forms.TextInput(attrs={"class": "inp", "value": ""}), required=True)
    a = forms.CharField(label="a", widget=forms.TextInput(attrs={"class": "inp", "value": ""}), required=True)
    class Meta:
        model = models.UserInfo
        fields = ['user','p','g','a']
    def clean_user(self):
        user = self.cleaned_data['user']
        if models.UserInfo.objects.filter(user=user).exists():
            return user
        elif user == request.session['info'].get('user'):
            return ValidationError("不能发给自己")
        else:
            return ValidationError("用户不存在")



def Exchange(request):
    if request.method == 'GET':
        if request.session.get('info'):
            form = ExchangeForm()
            form1 = models.exchange.objects.filter(user1=request.session['info'].get('user'))
            form2 = models.exchange.objects.filter(user2=request.session['info'].get('user'))
            return render(request, "exchange.html",{"form":form,"form1":form1,"form2":form2})
        else:
            log = request.GET.get('log')
            form = LoginUserForm()
            return render(request, 'login_user.html', {"form": form,"log":log})

    form = ExchangeForm(data=request.POST)
    if form.is_valid():
        user = form.cleaned_data.get('user')
        p = int(form.cleaned_data.get('p'))
        g = int(form.cleaned_data.get('g'))
        a = int(form.cleaned_data.get('a'))

        print('ii', user)
        if not models.UserInfo.objects.filter(user=user).exists():
            form.add_error("user", "用户不存在")
            return render(request, 'import.html', {"form": form,"message":message,"subject":subject})
        if user == request.session['info'].get('user'):
            form.add_error("user", "不能发给自己")
            return render(request, 'import.html', {"form": form,"message":message,"subject":subject})
        models.exchange.objects.create(
            user1=request.session['info'].get('user'),
            user2=user,
            p=p,
            g=g,
            a=momi(p,a,g),
            user1ID = request.session['info'].get('id'),
            user2ID = models.UserInfo.objects.filter(user=user).first().id
        )



    return redirect("/success/")
#秘钥交换删除请求
def Delete_please(request):
    models.exchange.objects.filter(id=request.GET.get('id')).delete()
    form = ExchangeForm()
    form1 = models.exchange.objects.filter(user1=request.session['info'].get('user'))
    form2 = models.exchange.objects.filter(user2=request.session['info'].get('user'))
    return render(request, "exchange.html",{"form":form,"form1":form1,"form2":form2})
#秘钥交换拒绝请求
def Refuse_please(request):
    models.exchange.objects.filter(id=request.GET.get('id')).update(view='1')
    form = ExchangeForm()
    form1 = models.exchange.objects.filter(user1=request.session['info'].get('user'))
    form2 = models.exchange.objects.filter(user2=request.session['info'].get('user'))
    return render(request, "exchange.html",{"form":form,"form1":form1,"form2":form2})
#秘钥交换同意请求
def Agree_please(request):
    models.exchange.objects.filter(id=request.GET.get('id')).update(view='2')
    form = ExchangeForm()
    form1 = models.exchange.objects.filter(user1=request.session['info'].get('user'))
    form2 = models.exchange.objects.filter(user2=request.session['info'].get('user'))
    return render(request, "exchange.html",{"form":form,"form1":form1,"form2":form2})

#文件加上密码
def pwd_xlsx(old_filename, new_filename, pwd_str, pw_str=''):
    pythoncom.CoInitialize()
    xcl = win32com.client.Dispatch("Excel.Application")
    # pw_str为打开密码, 若无 访问密码, 则设为 ''
    wb = xcl.Workbooks.Open(old_filename, False, False, None, pw_str)
    xcl.DisplayAlerts = False

    # 保存时可设置访问密码.
    wb.SaveAs(new_filename, None, pwd_str, '')

    xcl.Quit()

#加密文件
def fileencrypt(request):

    if request.method == 'GET':

        return render(request, 'fileencrypt.html')
    file_object = request.FILES.get('ffile')
    if file_object == None:
        return render(request, 'fileencrypt.html')
    cyber = request.POST.get('cyber')
    if file_object:
        fname = file_object.name
        pname = str(fname)
        print(fname)
        file_path = os.path.join(settings.UPLOAD, fname)
        file_path1 = os.path.join(settings.UPLOAD1, fname)
        with open(file_path, 'ab') as f:
            # 大于2.5MB分段传输
            for myf in file_object.chunks():
                # 下雨2.5MB整体传输
                f.write(myf)
        with open(file_path1, 'ab') as f:
            # 大于2.5MB分段传输
            for myf in file_object.chunks():
                # 下雨2.5MB整体传输
                f.write(myf)

        old_filename = 'E:\\softwareStore\\py\\pywork\\cypher\\app01\\static\\file\\' + pname
        new_filename = 'E:\\softwareStore\\py\\pywork\\cypher\\app01\\static\\file\\' + 'ss' + pname
        print(old_filename,new_filename)
        pwd_str = cyber  # 新密码自定义
        pwd_xlsx(old_filename, new_filename, pwd_str)
        #
        file_path = r'E:\softwareStore\py\pywork\cypher\\app01\static\\file\\ss' + pname


        file_path = os.path.join(settings.MEDIA_ROOT, file_path)
        if os.path.exists(file_path):
           # with open(file_path, 'rb') as fh:
                # response = HttpResponse(fh.read(), content_type="application/filename")
                # response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
                #
            response = StreamingHttpResponse(open(file_path, 'rb'))
            response['content_type'] = "application/octet-stream"
            response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(file_path)
            os.remove('E:\\softwareStore\\py\\pywork\\cypher\\app01\\static\\file\\' + pname)
            return response

        raise Http404

        # r = HttpResponse(open(file_path, "rb"))
        # print(r)
        # r["content_type"] = "application/octet-stream"
        # r["Content-Disposition"] = "attachment;filename="+pname
        # os.remove('E:\\softwareStore\\py\\pywork\\cypher\\app01\\static\\file\\' + pname)
        # return r



