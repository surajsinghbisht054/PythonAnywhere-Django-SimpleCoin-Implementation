# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from . import models

class DisplayAdmin(admin.ModelAdmin):
    list_display = ['acc','accid', 'balance']


# Register your models here.
# User Authentication Object Handling
admin.site.register(models.UserInfo, DisplayAdmin)
# User Receving Transection Record
admin.site.register(models.rtxn)
# User Sent Transection Record
admin.site.register(models.stxn)

