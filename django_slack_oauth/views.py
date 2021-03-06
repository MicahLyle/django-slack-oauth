# -*- coding: utf-8 -*-

import uuid
import re
from importlib import import_module

import requests

import django
from django.contrib.auth import get_user_model
from django.contrib import messages

DJANGO_MAJOR_VERSION =  int(django.__version__.split('.')[0])
if DJANGO_MAJOR_VERSION < 2:
    from django.core.urlresolvers import reverse
else:
    from django.urls import reverse

from django.http.response import HttpResponseRedirect, HttpResponse
from django.views.generic import RedirectView, View

from . import settings

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

__all__ = (
    'SlackAuthView',
    'DefaultSuccessView'
)


class StateMismatch(Exception):
    pass


class SlackSessionKeyError(KeyError):
    def __init__(self, request, last_got, message):
        self.request = request
        self.last_got = last_got
        self.message = message


def slack_session_key_error_handler(error):
    settings_handler_value = settings.SLACK_OAUTH_SESSION_KEY_NOT_FOUND_HANDLER
    if callable(settings_handler_value):
        return settings_handler_value(error)
    elif isinstance(settings_handler_value, str):
        *module_path_list, function_name =  settings_handler_value.split('.')
        module = import_module('.'.join(module_path_list))
        return getattr(module, function_name)(error)
    raise TypeError(
        'settings.SLACK_OAUTH_SESSION_KEY_NOT_FOUND_HANDLER should be a callable ' +
        'or path dotted string to a callable.'
    )


class DefaultAddSuccessView(View):
    def get(self, request):
        messages.success(request, "You've successfully added to slack.")
        return HttpResponse("Slack OAuth login successful with add to slack.")


class DefaultSigninSuccessView(View):
    def get(self, request):
        messages.success(request, "You've been successfully authenticated by signing in with slack.")
        return HttpResponse("Slack OAuth login successful with signin with slack.")


class SlackAuthView(RedirectView):
    permanent = True

    text_error = 'Attempt to update has failed. Please try again.'

    # This gets set by as_view
    auth_type = None

    @property
    def last_got_key(self):
        """
        The URL of the last GET request made to some sort of Slack OAuth
        for the session. Useful if the back button goes back to a Slack
        OAuth sort of flow.
        """
        return 'slack:last-got'

    @property
    def state_key(self):
        # NOTE, IMPORTANT: Do not change this in production without considering
        # existing sessions and users with existing sessions, etc.
        return 'slack:state'

    @property
    def custom_scope(self):
        """
        Should return a space separated list (string) of custom scopes requested
        for authentication or an empty string.
        """
        user_model = get_user_model()
        if hasattr(user_model, "custom_slack_auth_scope"):
            return user_model.custom_slack_auth_scope(self.auth_type, self.request)
        return ''

    @property
    def extra_state(self):
        """
        Should return a comma separated list of characters that represent extra state
        for authentication or an empty string.
        """
        user_model = get_user_model()
        if hasattr(user_model, "extra_slack_auth_state"):
            return user_model.extra_slack_auth_state(self.auth_type, self.request)
        return ''

    def get(self, request, *args, **kwargs):
        code = request.GET.get('code')
        if not code:
            return self.auth_request()

        try:
            self.validate_state(request.GET.get('state'))
        except SlackSessionKeyError as e:
            return slack_session_key_error_handler(e)

        access_content = self.oauth_access(code)
        if not access_content.status_code == 200:
            return self.error_message()

        api_data = access_content.json()
        if not api_data['ok']:
            return self.error_message(api_data['error'])

        pipelines = settings.SLACK_PIPELINES

        # pipelines is a list of the callables to be executed
        pipelines = [getattr(import_module('.'.join(p.split('.')[:-1])), p.split('.')[-1]) for p in pipelines]
        return self.execute_pipelines(request, api_data, pipelines)

    def execute_pipelines(self, request, api_data, pipelines):
        if len(pipelines) == 0:
            # Terminate at the successful redirect
            return self.response()
        else:
            # Call the next function in the queue
            request, api_data = pipelines.pop(0)(request, api_data)
            if "redirect_to_here" in api_data:
                self.redirect_from_pipeline = api_data["redirect_to_here"]
            return self.execute_pipelines(request, api_data, pipelines)

    def auth_request(self):
        state = self.store_state()
        scope = self.custom_scope
        if not scope:
            scope = getattr(settings, "SLACK_ADD_SCOPE" if self.auth_type == "add" else "SLACK_SIGNIN_SCOPE")

        params = urlencode({
            'client_id': settings.SLACK_CLIENT_ID,
            'redirect_uri': self.request.build_absolute_uri(reverse('slack_add' if self.auth_type == "add" else 'slack_signin')),
            'scope': scope,
            'state': state
        })

        return self.response(settings.SLACK_AUTHORIZATION_URL + '?' + params)

    def oauth_access(self, code):
        params = {
            'client_id': settings.SLACK_CLIENT_ID,
            'client_secret': settings.SLACK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': self.request.build_absolute_uri(reverse('slack_add' if self.auth_type == "add" else 'slack_signin'))
        }

        return requests.get(settings.SLACK_OAUTH_ACCESS_URL, params=params)

    def validate_state(self, state):
        # Explicitly split on the space here, not () for any whitespace.
        uuid4_part = (state or '').split(' ')[0]
        try:
            state_before = self.request.session.pop(self.state_key)
        except KeyError as e:
            raise SlackSessionKeyError(
                self.request,
                self.request.session.get(self.last_got_key),
                f'Slack oauth session key not found in the request session.'
            ) from e
        if isinstance(state_before, str) and isinstance(state, str) and state_before[:17] == state[:17]:
            # Add the state before and now to the request so that if we need to do
            # something with that information we can.
            self.request.slack_state_before = state_before
            self.request.slack_state_now = state
            return True
        else:
            raise StateMismatch('State mismatch upon authorization completion. Try a new request.')

    def store_state(self):
        extra_state = self.extra_state
        # Prepend a space to extra state if it's there.
        if extra_state != '':
            extra_state = ' ' + extra_state
        uuid4_part = str(uuid.uuid4())[:17]
        state = uuid4_part + extra_state
        # Put the absolute uri, including the query string, in the key that
        # stores the last GET request (in case someone navigates back, etc.).
        self.request.session[self.last_got_key] = self.request.build_absolute_uri()
        self.request.session[self.state_key] = state
        return state

    def check_for_redirect_in_state(self):
        """
        If the extra state from the user previously contained a specific
        string, redirect back into the slack application as specified
        (by deep linking back into the slack application).
        """
        if not hasattr(self.request, "slack_state_before"):
            return None
        extra_state = self.request.slack_state_before.split()[-1].split(",")
        # redirect slack [open/team/channel/message/file]
        deep_link_pattern = re.compile(r"^rs[otcmf]")
        redirect_to = None
        for state_string in extra_state:
            # redirect to here (rth)
            if state_string.startswith("rth"):
                redirect_to = state_string.split(":")[-1]
                break
            elif deep_link_pattern.match(state_string):
                deep_link = "slack://"
                type_char = state_string[2]
                values = state_string.split(":")
                if type_char == "o" or type_char == "t":
                    deep_link += "open"
                if type_char == "t":
                    deep_link += "?team=" + values[-1]
                if type_char == "c":
                    deep_link += "channel?team=" + values[-2] + "&id=" + values[-1]
                if type_char == "m":
                    deep_link += "user?team=" + values[-2] + "&id=" + values[-1]
                if type_char == "f":
                    deep_link += "file?team=" + values[-2] + "&id=" + values[-1]
                redirect_to = deep_link
        return redirect_to

    def error_message(self, msg=text_error):
        messages.add_message(self.request, messages.ERROR, '%s' % msg)
        if self.auth_type == "add":
            redirect = settings.SLACK_ADD_ERROR_REDIRECT_URL
        elif self.auth_type == "signin":
            redirect = settings.SLACK_SIGNIN_ERROR_REDIRECT_URL
        return self.response(redirect=redirect)

    def response(self, redirect=None):
        if redirect is None:
            if self.auth_type == "add":
                redirect = settings.SLACK_ADD_SUCCESS_REDIRECT_URL
            elif self.auth_type == "signin":
                redirect = settings.SLACK_SIGNIN_SUCCESS_REDIRECT_URL
            redirect_from_state = self.check_for_redirect_in_state()
            redirect_from_pipeline = getattr(self, "redirect_from_pipeline", None)
            # Use slack-redir.net to do slack:// redirects (deep linking)
            # to avoid Django throwing an error because HttpResponseRedirect
            # can't redirect to slack://...
            if redirect_from_state and "slack://" in redirect_from_state:
                redirect = f"https://slack-redir.net/link?url={redirect_from_state}"
            else:
                redirect = redirect_from_state or redirect_from_pipeline or redirect
        return HttpResponseRedirect(redirect)
