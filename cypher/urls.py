"""cypher URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app01 import views

urlpatterns = [
    path('main/', views.Message),
    path('', views.Message),
    path('des/', views.DES),
    path('fileencrypt/', views.fileencrypt),
    path('des2/', views.DES2),
    path('des3/', views.DES3),
    path('aes/', views.AES),
    path('sm4/', views.SM4),
    path('rc4/', views.RC4),
    path('sm3/', views.SM3),
    path('rsa/', views.RSA),
    path('elgamal/', views.Elgamal),
    path('login/user/', views.login_user),
    path('register/', views.Register),
    path('message/', views.Message),
    path('import/', views.Import),
    path('logout/', views.logout),
    path('success/', views.Success),
    path('receive/', views.Receive),
    path('send/', views.Send),
    path('exchange/', views.Exchange),
    path('delete/please/', views.Delete_please),
    path('refuse/please/', views.Refuse_please),
    path('agree/please/', views.Agree_please),
    path('face/',views.Face),
    path('chack/',views.Chack),
    path('cybermanage/',views.Cybermanage),
    path('delete/cyber/', views.Delete_cyber),



]
