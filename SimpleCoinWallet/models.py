# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class UserInfo(models.Model):
    accid = models.CharField('address', max_length=66)
    # Account name
    acc = models.ForeignKey(User, related_name='Customer')

    # auth object 
    authobj = models.TextField('AuthenticationData',blank=False, max_length=1500)

    # balance
    balance = models.IntegerField('Account_Balance', blank=True)

    # last transection date
    last_update = models.DateTimeField('last account udpate',auto_now_add=True)

class rtxn(models.Model):
    acc = models.ForeignKey(User, related_name='Receiver')
    transections = models.CharField('Receving_Transections', max_length=66)
    last_update = models.DateTimeField('last account udpate',auto_now_add=True)

class stxn(models.Model):
    acc = models.ForeignKey(User, related_name='Sender')
    transections = models.CharField("Sent Transections", max_length=66)
    last_update = models.DateTimeField('last account udpate',auto_now_add=True)



