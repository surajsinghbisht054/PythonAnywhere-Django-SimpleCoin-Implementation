from django import forms

input_css_class_global = "form-control"


class login(forms.Form):
    username = forms.CharField(min_length=5, max_length=20)
    username.widget.attrs['class'] = input_css_class_global
    password = forms.CharField(widget=forms.PasswordInput)
    password.widget.attrs['class'] = input_css_class_global

# Signup form
class SignUpForm(login):
    conform_password = forms.CharField(widget=forms.PasswordInput)
    email = forms.EmailField()
    first_name = forms.CharField(max_length=60, min_length=3)
    last_name = forms.CharField(max_length=60, min_length=3)
    conform_password.widget.attrs['class'] = input_css_class_global
    email.widget.attrs['class'] = input_css_class_global
    first_name.widget.attrs['class'] = input_css_class_global
    last_name.widget.attrs['class'] = input_css_class_global
    
class MoneySent(forms.Form):
    receiver_address = forms.CharField(min_length=20, max_length=66)
    sent_coin = forms.IntegerField()
    receiver_address.widget.attrs['class'] = input_css_class_global
    sent_coin.widget.attrs['class'] = input_css_class_global
    



#    
class change_password(forms.Form):
    email = forms.EmailField()
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    conform_password = forms.CharField(widget=forms.PasswordInput)
    conform_password.widget.attrs['class'] = input_css_class_global
    email.widget.attrs['class'] = input_css_class_global
    new_password.widget.attrs['class'] = input_css_class_global
    old_password.widget.attrs['class'] = input_css_class_global   
