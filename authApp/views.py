import re
from urllib import response
from django.shortcuts import render,redirect
from .forms import UserRegistrationForm,UserProfileForm
from .models import Profile
import requests
from django.contrib.auth.hashers import make_password
import random
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login 
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
import json
from django.contrib.auth.decorators import login_required
# Create your views here.

SEND_TOKEN_URL = 'https://api.ng.termii.com/api/sms/otp/send'
SEND_TOKEN_VERIFYTOKEN_URL = "https://api.ng.termii.com/api/sms/otp/verify"

def send_otp(number,message, otp):
    payload = {
            "api_key" : "TL3tMLT5JqmnilpaxaN47tt0ACnHzqrDNYTxjkoDDMTqzmKPJMXMjjfLRJGEC7",
            "message_type" : "NUMERIC",
            "to" : number,
            "from" : "Yct Verify",
            "channel" : "generic",
            "pin_attempts" : 10,
            "pin_time_to_live" :  5,
            "pin_length" : 6,
            "pin_placeholder" : "< 1234 >",
            "message_text" : message,
            "pin_type" : "NUMERIC"
        }
    headers = {
    'Content-Type': 'application/json',
    }
    response = requests.request("POST", SEND_TOKEN_URL, headers=headers, json=payload)
    print(response.text)

    payload = {
        'api_key' : "TL3tMLT5JqmnilpaxaN47tt0ACnHzqrDNYTxjkoDDMTqzmKPJMXMjjfLRJGEC7",
        'pin_id' : "0c6fcfd0-0299-4196-acc3-d788fb8526dc",
        'pin' : otp,
    }

    headers = {
        'Content-Type' : 'application/json',
    }

    response = requests.post(SEND_TOKEN_VERIFYTOKEN_URL, headers=headers, json=payload)
    #response = json.loads(response.content)
    # print(response.text) 





def Registration(request):
    if request.method == "POST":
        fm = UserRegistrationForm(request.POST)
        up = UserProfileForm(request.POST)
        if fm.is_valid() and up.is_valid():
            e = fm.cleaned_data['email']
            u = fm.cleaned_data['username']
            p = fm.cleaned_data['password1']
            request.session['email'] = e
            request.session['username'] = u
            request.session['password'] = p
            p_number = up.cleaned_data['phone_number']
            request.session['number'] = p_number
            otp = random.randint(1000,9999)
            request.session['otp'] = otp
            message = f'your registration one time password  is {otp}, valid for 5 minutes'
            send_otp(p_number,message,otp)
            return redirect('/registration/otp/')

    else:
        fm  = UserRegistrationForm()
        up = UserProfileForm()
    context = {'fm':fm,'up':up}
    return render(request,'registration.html',context)


def otpRegistration(request):
    if request.method == "POST":
        u_otp = request.POST['otp']
        otp = request.session.get('otp')
        user = request.session['username']
        hash_pwd = make_password(request.session.get('password'))
        p_number = request.session.get('number')
        email_address = request.session.get('email') 

        if int(u_otp) == otp:
            User.objects.create(
                            username = user,
                            email=email_address,
                            password=hash_pwd
            )
            user_instance = User.objects.get(username=user)
            Profile.objects.create(
                            user = user_instance,phone_number=p_number
            )
            request.session.delete('otp')
            request.session.delete('user')
            request.session.delete('email')
            request.session.delete('password')
            request.session.delete('phone_number')

            messages.success(request,'Registration Successfully Done !!')

            return redirect('/login/')
        
        else:
            messages.error(request,'Wrong OTP')


    return render(request,'registration-otp.html')


def userLogin(request):

    try :
        if request.session.get('failed') > 2:
            return HttpResponse('<h1> You have to wait for 5 minutes to login again</h1>')
    except:
        request.session['failed'] = 0
        request.session.set_expiry(100)



    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request,username=username,password=password)
        if user is not None:
            request.session['username'] = username
            request.session['password'] = password
            u = User.objects.get(username=username)
            p = Profile.objects.get(user=u)
            p_number = p.phone_number
            otp = random.randint(1000,9999)
            #pin_id = p.uuid
            request.session['login_otp'] = otp
            message = f'your one time password for login is {otp} valid for 5 minutes'
            send_otp(p_number,message,otp)
            return redirect('/login/otp/')
        else:
            messages.error(request,'username or password is wrong')
    return render(request,'login.html')

def otpLogin(request):
    if request.method == "POST":
        username = request.session.get('username')
        password = request.session.get('password')
        otp = request.session.get('login_otp')
        u_otp = request.POST['otp']
        if int(u_otp) == otp:
            user = authenticate(request,username=username,password=password)
            if user is not None:
                login(request,user)
                request.session.delete('login_otp')
                messages.success(request,'login successfully')
                return redirect('/dashboard/')
        else:
            messages.error(request,'Wrong OTP')
    return render(request,'login-otp.html')



def home(request):
    # if request.method == "POST":
    #     otp = random.randint(1000,9999)
    #     request.session['email_otp'] = otp
    #     message = f'your otp is {otp}'
    #     user_email = request.user.email

    #     send_mail(
    #         'Email Verification OTP',
    #         message,
    #         settings.EMAIL_HOST_USER,
    #         [user_email],
    #         fail_silently=False,
    #     )
    #     return redirect('/email-verify/')

    return render(request,'home.html')

def dashboard(request):


    return render(request,'dashboard.html')

def email_verification(request):
    if request.method == "POST":
        u_otp = request.POST['otp']
        otp = request.session['email_otp']
        if int(u_otp) == otp:
           p =  Profile.objects.get(user=request.user)
           p.email_verified = True
           p.save()
           messages.success(request,f'Your email {request.user.email} is verified now')
           return redirect('/')
        else:
            messages.error(request,'Wrong OTP')


    return render(request,'email-verified.html')

def forget_password(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            uid = User.objects.get(email=email)
            url = f'http://127.0.0.1:8000/change-password/{uid.profile.uuid}'
            send_mail(
            'Reset Password',
            url,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
            return redirect('/forget-password/done/')
        else:
            messages.error(request,'email address is not exist')
    return render(request,'forget-password.html')

def change_password(request,uid):
    try:
        if Profile.objects.filter(uuid = uid).exists():
            if request.method == "POST":
                pass1 = 'password1'in request.POST and request.POST['password1']
                pass2 =  'password2'in request.POST and request.POST['password2']
                if pass1 == pass2:
                    p = Profile.objects.get(uuid=uid)
                    u = p.user
                    user = User.objects.get(username=u)
                    user.password = make_password(pass1)
                    user.save()
                    messages.success(request,'Password has been reset successfully')
                    return redirect('/login/')
                else:
                    return HttpResponse('Two Password did not match')
                
        else:
            return HttpResponse('Wrong URL')
    except:
        return HttpResponse('Wrong URL')
    return render(request,'change-password.html')