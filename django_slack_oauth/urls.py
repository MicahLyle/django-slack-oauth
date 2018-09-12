# -*- coding: utf-8 -*-

from django.conf.urls import url

from .views import SlackAuthView, DefaultAddSuccessView, DefaultSigninSuccessView


urlpatterns = [
    url('add/', SlackAuthView.as_view(auth_type="add"), name='slack_add'),
    url('signin/', SlackAuthView.as_view(auth_type="signin"), name='slack_signin'),
    url('add-success/', DefaultAddSuccessView.as_view(), name='slack_add_success'),
    url('signin-success/', DefaultSigninSuccessView.as_view(), name='slack_signin_success')
]
