# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from .wallet import new_user, create_transection, getchain, startblockchain, UserInfoBalance
from django.shortcuts import render
from django.http.response import HttpResponse, HttpResponseRedirect
from .cforms import SignUpForm, change_password, login as loginform, MoneySent
from .models import User, UserInfo, rtxn, stxn
from django.contrib.auth import authenticate, login, logout

def receving_transection(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')    
    f =[i.transections for i in rtxn.objects.filter(acc=request.user)]
    context = {
        'listdata':f,
    }
    
    return render(request, 'pages/listdata.html', context )

def sent_transections(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')   
    f =[i.transections for i in stxn.objects.filter(acc=request.user)] 
    context = {
        'listdata':f,
    }
    
    return render(request, 'pages/listdata.html', context )


def walletinfo(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    i = UserInfo.objects.filter(acc = request.user)

    if not i:
        obj = User.objects.filter(username=request.user.username)[0]
        if obj:
            new_user(obj, request.user.username)
            return walletinfo(request)
        else:
            return HttpResponseRedirect('walletnew')
    else:
        i = i[0]

    a = [
        '  Address : ' + i.accid.__str__(),
        '  User : ' + i.acc.__str__(),
        '  Balance : ' + UserInfoBalance(i.acc).__str__(),
        '  LastUpdate : ' + i.last_update.__str__()
    ]
    context = {
        'listdata':a,
    }
    
    return render(request, 'pages/listdata.html', context )

def about(request):
    return HttpResponseRedirect('http://www.bitforestinfo.com/p/about.html')

def detailsaccounts(request):
    a = [i.accid for i in UserInfo.objects.all()]
    context = {
        'listdata':a,
    }
    
    return render(request, 'pages/listdata.html', context )


def minefirstblock(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('walletlogin')
    startblockchain(request)
    return HttpResponse('I Think First Block Mining Is Complete')


def get_chain(request):
    return HttpResponse("<xmp>{}</xmp>".format(getchain()))

# Create your views here.
def index(request):
    return render(request, 'pages/index.html')

def createtransection(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')    
    msg = 'It May Take Few Minutes To Conform This Transection Because Of Inbuilt Proof Of Work mechanizm.'
    form = MoneySent
    if request.method=='POST':
        form = MoneySent(request.POST)
        if form.is_valid() and request.user.is_authenticated():
            c = create_transection(request.user, request.POST['receiver_address'], request.POST['sent_coin'])
            if c:
                msg = 'Check Your Wallet Balance For Conforming Your Trasection.'
                form = MoneySent
            else:
                msg = "Transection Not Accepted. Sorry"
        else:
            msg = 'Your Transection Requestion Is not valid.'
    context = {
        'msg' :  msg,
        'form': form,
        }
    return render(request, 'registration/form.html', context )


def signup(request):
    # default values
    form = SignUpForm()
    msg = ''

    # check post Data
    if request.method=='POST':

        # form
        form = SignUpForm(request.POST)
        # check form format
        if form.is_valid():
            # check password
            if request.POST['conform_password']==request.POST['password']:
                
                # get parameters
                username = request.POST['username'] 
                firstname = request.POST['first_name']
                lastname = request.POST['last_name']
                password = request.POST['password']
                email = request.POST['email']

                if User.objects.filter(username=username):
                    msg = "Username Already Occupied."
                else:

                    # load object
                    obj = User.objects.create_user(
                        username,
                        email = email,
                        password=password,
                        first_name = firstname,
                        last_name = lastname,
                    )
                    
                    obj.save()
                    new_user(obj, username)
                    msg = 'Signup Complete.!'
                    return HttpResponseRedirect('/')
            else:
                msg = ' Password And Conform Password Not Matching'
                
        else:
            msg = 'Invalid Form Input' 

    #  
    context = {
        'msg' :  msg,
        'form': form,
        }
    return render(request, 'registration/form.html', context )


def loginpage(request):
    msg = ''
    form = loginform
    # check request
    if request.user.is_authenticated():
        return HttpResponseRedirect('/')
    
    if request.method=='POST':
        form = loginform(request.POST)   
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(username=username, password=password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect('/')
                else:
                    msg = "Account Disabled"
            else:
                msg = "Invalid Login"
        else:
            msg = "login unformatted input!"   


    #  
    context = {
        'msg' :  msg,
        'form': form,
        }
    return render(request, 'registration/form.html', context)

def logoutpage(request):
    logout(request)
    return HttpResponseRedirect('/')

def change_pass(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/')
    context = {
        'form':change_password()
        }
    return render(request, 'registration/form.html', context )
