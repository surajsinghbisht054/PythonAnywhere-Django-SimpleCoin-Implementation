from django.conf.urls import url
from . import views


urlpatterns = [
    # Home Page
    url(r'^$', views.index, name="walletindex" ),
    
    # Account Handling
    url(r'new/', views.signup, name='walletnew'),
    url(r'login/', views.loginpage, name='walletlogin'),
    url(r'logout/', views.logoutpage, name='walletlogout'),
    url(r'changepass/', views.change_pass, name='walletchange'),
    
    # Blockchain Handling
    url(r'^chain/$', views.get_chain, name='chain'),
    url(r'^start/$', views.minefirstblock, name='startchain'),
    url(r'createtrans/', views.createtransection, name='wallettransrequest'),
    url(r'walletinfo/', views.walletinfo, name='walletinfo'),

    # BLockchain Account Informations (Public)
    url(r'showaddress/', views.detailsaccounts, name='detailaddress'),
    url(r'about/', views.about, name = 'about'),
    url(r'rtxn/', views.receving_transection, name = 'rtxn'),
    url(r'stxn/', views.sent_transections, name = 'stxn')
,
]