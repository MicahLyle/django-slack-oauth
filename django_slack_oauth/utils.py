from django.http import Http404

def session_key_not_found_handler(slack_session_key_error):
    """
    For now, if the session key isn't found, just redirect back to the
    auth flow with a GET request since they probably tried to go back
    or something like that. Could also render a helpful template
    or do something else by overriding this handler from the
    Django settings.
    """
    request = slack_session_key_error.request
    # If it's in the session, redirect to the last add/sign in
    # attempt that the user had. Otherwise, redirect to the path
    # from the request (which shouldn't have the code, other params).
    if slack_session_key_error.last_got and isinstance(slack_session_key_error.last_got, str):
        return HttpResponseRedirect(slack_session_key_error.last_got)
    return HttpResponseRedirect(request.path)
