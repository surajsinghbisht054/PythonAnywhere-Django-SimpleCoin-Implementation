"""blog URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.conf.urls import include
from django.shortcuts import redirect
from django.views.generic import RedirectView
from dcode import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'simplecoin/', include('SimpleCoinWallet.urls')),
    url(r'dcode/', views.dcode, name='dcodeindex'),
    # Currently This BLog Contain Only One App, So That's Why Using Redirect
    url(r'.*', views.mainindex, name='mainindex')
]
