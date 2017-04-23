from django import forms
from django.contrib.auth import (
    authenticate, get_user_model, login, logout
)


User = get_user_model()


class UserLoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise forms.ValidationError("This user does not exists")

            if not user.check_password(password):
                raise forms.ValidationError("Incorrect password")

            if not user.is_active:
                raise forms.ValidationError("This user is no longer active")

        return super(UserLoginForm, self).clean()


# class UserRegisterForm(forms.ModelForm):
#     email = forms.EmailField(label="Email Address")
#     # confirm_email = forms.EmailField(label="Confirm Email")
#     confirm_password = forms.CharField(widget=forms.PasswordInput)
#     password = forms.CharField(widget=forms.PasswordInput)

#     class Meta:
#         model = User
#         fields = [
#             "username",
#             "email",
#             # "confirm_email",
#             "confirm_password",
#             "password"
#         ]


#     def clean_confirm_password(self):
#         password = self.cleaned_data.get("password")
#         # confirm_email = self.cleaned_data.get("confirm_email")
#         confirm_password = self.cleaned_data.get("confirm_password")
#         # if email != confirm_email:
#         if password != confirm_password:
#             raise forms.ValidationError("Emails must match")

#         password_qs = User.objects.filter(password=password)
#         if password_qs.exists():
#             raise forms.ValidationError(
#                 "This password has already been registered")

#         # return confirm_email
#         return confirm_password


class UserRegisterForm(forms.ModelForm):
    email = forms.EmailField(label="Email Address")
    confirm_email = forms.EmailField(label="Confirm Email")
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "confirm_email",
            "password"
        ]

    # Clean methods like clean_...() work on the field.
    # If you don't want to specify the field just use the method clean() (see UserLoginForm)
    # def clean_confirm_email(self):
    #     email = self.cleaned_data.get("email")
    #     confirm_email = self.cleaned_data.get("confirm_email")

    #     if email != confirm_email:
    #         raise forms.ValidationError("Emails must match")

    #     email_qs = User.objects.filter(email=email)
    #     if email_qs.exists():
    #         raise forms.ValidationError("This email has already been registered")

    #     return confirm_email

class PasswordChageForm(forms.Form):

    #username = forms.CharField()
    oldpassword = forms.CharField(
        label="oldpassword", widget=forms.PasswordInput)
    new_password = forms.CharField(
        label="newpassword", widget=forms.PasswordInput)
    new_password2 = forms.CharField(
        label="Confirm newpassword", widget=forms.PasswordInput)

    def clean(self):

        #username = self.cleaned_data.get("username")
        #password = self.cleaned_data.get("password")
        # username and password:

            #user = authenticate(username=username, password=password)

            # if not user.check_password(password):
                #raise forms.ValidationError("Incorrect password")
        new_password = self.cleaned_data.get("new_password")
        new_password2 = self.cleaned_data.get("new_password2")

        if new_password != new_password2:

            raise forms.ValidationError("newpassword must match")
        else:
            cleaned_data = super(PasswordChageForm, self).clean()

        return cleaned_data
