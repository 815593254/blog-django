from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import (
    authenticate, login, logout, update_session_auth_hash
)
from .forms import UserLoginForm, UserRegisterForm, PasswordChageForm


def login_view(request):
    form = UserLoginForm(request.POST or None)
    next_url = request.GET.get("next")
    if form.is_valid():
        username = form.cleaned_data.get("username")
        password = form.cleaned_data.get("password")
        user = authenticate(username=username, password=password)
        login(request, user)
        messages.success(
            request, "Successfully logged in as: {}".format(username))
        if next_url:
            return redirect(next_url)
        return redirect("posts:list")

    context = {
        "form": form,
        "title": "Login"
    }
    return render(request, "login.html", context)


def logout_view(request):
    logout(request)
    messages.success(request, "Successfully logged out")
    return redirect("accounts:login")


def register_view(request):
    form = UserRegisterForm(request.POST or None)
    if form.is_valid():
        user = form.save(commit=False)
        user.set_password(form.cleaned_data.get("password"))
        user.save()

        new_user = authenticate(username=user.username,
                                password=form.cleaned_data.get("password"))
        login(request, new_user)
        messages.success(
            request, "Successfully registered user: {}".format(user.username))
        return redirect("posts:list")

    context = {
        "form": form,
        "title": "Register"
    }
    return render(request, "register.html", context)


def passwordchange(request):
    form = PasswordChageForm(request.POST or None)
    if form.is_valid():
            #user = form.save(commit=False)
        username = request.user.username

        oldpassword = request.POST.get("oldpassword")
        #oldpassword = request.user.password

        user = authenticate(username=username, password=oldpassword)

        if user is not None:
            newpassword = request.POST.get('new_password')
            user.set_password(newpassword)
            user.save()

            #new_user = authenticate(username=user.username, password=form.cleaned_data.get("new_password"))
            messages.success(request, "SS")
            return redirect("accounts:login")
        else:
            messages.error(request, "WW")

    context = {
        "form": form,
        "title": "changepassword"
    }
    return render(request, "form.html", context)
