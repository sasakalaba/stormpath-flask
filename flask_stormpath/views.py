"""Our pluggable views."""


import sys
import json
from flask import (
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    make_response
)
from flask.ext.login import login_user, login_required, current_user
from six import string_types
from stormpath.resources.provider import Provider
from stormpath.resources import Expansion

from . import StormpathError, logout_user
from .forms import StormpathForm
from .models import User

if sys.version_info.major == 3:
    FACEBOOK = False
else:
    from facebook import get_user_from_cookie
    FACEBOOK = True


""" Helper functions. """


def make_stormpath_response(
        data, template=None, return_json=True, status_code=200):
    if return_json:
        stormpath_response = make_response(data, status_code)
        stormpath_response.mimetype = 'application/json'
    else:
        stormpath_response = render_template(template, **data)
    return stormpath_response


def request_wants_json():
    best = request.accept_mimetypes.best_match(current_app.config[
        'stormpath']['web']['produces'])
    if best is None and current_app.config['stormpath']['web']['produces']:
        best = current_app.config['stormpath']['web']['produces'][0]
    return best == 'application/json'

""" View functions. """


def register():
    """
    Register a new user with Stormpath.

    This view will render a registration template, and attempt to create a new
    user account with Stormpath.

    The fields that are asked for, the URL this view is bound to, and the
    template that is used to render this page can all be controlled via
    Flask-Stormpath settings.
    """
    register_config = current_app.config['stormpath']['web']['register']

    # We cannot set fields dynamically in the __init__ method, so we'll
    # create our class first, and then create the instance
    form = StormpathForm.specialize_form(register_config['form'])()
    data = form.data

    if request.method == 'POST':
        # If we received a POST request with valid information, we'll continue
        # processing.

        if not form.validate_on_submit():
            # If form.data is not valid, return error messages.
            if request_wants_json():
                return make_stormpath_response(
                    data=json.dumps({
                        'status': 400,
                        'message': form.errors}),
                    status_code=400)

            for field_error in form.errors.keys():
                flash(form.errors[field_error][0])

        else:
            # We'll just set the field values to 'Anonymous' if the user
            # has explicitly said they don't want to collect those fields.
            for field in ['given_name', 'surname']:
                if not data.get(field):
                    data[field] = 'Anonymous'

            # Remove the confirmation password so it won't cause an error
                if 'confirm_password' in data:
                    data.pop('confirm_password')

            # Attempt to create the user's account on Stormpath.
            try:
                # Create the user account on Stormpath.  If this fails, an
                # exception will be raised.

                account = User.create(**data)
                # If we're able to successfully create the user's account,
                # we'll log the user in (creating a secure session using
                # Flask-Login), then redirect the user to the
                # Stormpath login nextUri setting but only if autoLogin.
                if (register_config['autoLogin'] and not current_app.config[
                        'stormpath']['web']['verifyEmail']['enabled']):
                    login_user(account, remember=True)

                if request_wants_json():
                    return make_stormpath_response(data=account.to_json())

                # Set redirect priority
                redirect_url = register_config['nextUri']
                if not redirect_url:
                    redirect_url = current_app.config['stormpath'][
                        'web']['login']['nextUri']
                    if not redirect_url:
                        redirect_url = '/'
                return redirect(redirect_url)

            except StormpathError as err:
                if request_wants_json():
                    status_code = err.status if err.status else 400
                    return make_stormpath_response(
                        json.dumps({
                            'error': status_code,
                            'message': err.message.get('message')}),
                        status_code=status_code)
                flash(err.message.get('message'))

    if request_wants_json():
        return make_stormpath_response(data=form.json)

    return make_stormpath_response(
        template=register_config['template'], data={'form': form},
        return_json=False)


def login():
    """
    Log in an existing Stormpath user.

    This view will render a login template, then redirect the user to the next
    page (if authentication is successful).

    The fields that are asked for, the URL this view is bound to, and the
    template that is used to render this page can all be controlled via
    Flask-Stormpath settings.
    """
    login_config = current_app.config['stormpath']['web']['login']

    # We cannot set fields dynamically in the __init__ method, so we'll
    # create our class first, and then create the instance
    form = StormpathForm.specialize_form(login_config['form'])()

    if request.method == 'POST':
        # If we received a POST request with valid information, we'll continue
        # processing.

        if not form.validate_on_submit():
            # If form.data is not valid, return error messages.
            if request_wants_json():
                return make_stormpath_response(
                    data=json.dumps({
                        'status': 400,
                        'message': form.errors}),
                    status_code=400)

            for field_error in form.errors.keys():
                flash(form.errors[field_error][0])

        else:
            try:
                # Try to fetch the user's account from Stormpath.  If this
                # fails, an exception will be raised.
                account = User.from_login(form.login.data, form.password.data)

                # If we're able to successfully retrieve the user's account,
                # we'll log the user in (creating a secure session using
                # Flask-Login), then redirect the user to the ?next=<url>
                # query parameter, or the Stormpath login nextUri setting.
                login_user(account, remember=True)

                if request_wants_json():
                    return make_stormpath_response(data=current_user.to_json())

                return redirect(request.args.get('next') or login_config[
                    'nextUri'])

            except StormpathError as err:
                if request_wants_json():
                    status_code = err.status if err.status else 400
                    return make_stormpath_response(
                        json.dumps({
                            'error': status_code,
                            'message': err.message.get('message')}),
                        status_code=status_code)
                flash(err.message.get('message'))

    if request_wants_json():
        return make_stormpath_response(data=form.json)

    return make_stormpath_response(
        template=login_config['template'], data={'form': form},
        return_json=False)


def forgot():
    """
    Initialize 'password reset' functionality for a user who has forgotten his
    password.

    This view will render a forgot template, which prompts a user for their
    email address, then sends a password reset email.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """
    forgot_config = current_app.config['stormpath']['web']['forgotPassword']
    form = StormpathForm.specialize_form(forgot_config['form'])()

    if request.method == 'POST':
        # If we received a POST request with valid information, we'll continue
        # processing.
        if not form.validate_on_submit():
            # If form.data is not valid, return error messages.
            if request_wants_json():
                return make_stormpath_response(
                    data=json.dumps({
                        'status': 400,
                        'message': form.errors}),
                    status_code=400)

            for field_error in form.errors.keys():
                flash(form.errors[field_error][0])

        else:
            try:
                # Try to fetch the user's account from Stormpath.  If this
                # fails, an exception will be raised.
                account = (
                    current_app.stormpath_manager.application.
                    send_password_reset_email(form.email.data))
                account.__class__ = User

                # If we're able to successfully send a password reset email to
                # this user, we'll display a success page prompting the user
                # to check their inbox to complete the password reset process.

                if request_wants_json():
                    return make_stormpath_response(
                        data=json.dumps({
                            'status': 200,
                            'message': {'email': form.data.get('email')}}),
                        status_code=200)

                return make_stormpath_response(
                    template='flask_stormpath/forgot_email_sent.html',
                    data={'user': account}, return_json=False)

            except StormpathError as err:
                # If the error message contains 'https', it means something
                # failed on the network (network connectivity, most likely).
                if (isinstance(err.message, string_types) and
                        'https' in err.message.lower()):
                    error_msg = 'Something went wrong! Please try again.'

                # Otherwise, it means the user is trying to reset an invalid
                # email address.
                else:
                    error_msg = 'Invalid email address.'

                if request_wants_json():
                    status_code = err.status if err.status else 400
                    return make_stormpath_response(
                        json.dumps({
                            'status': status_code,
                            'message': error_msg}),
                        status_code=status_code)
                flash(error_msg)

    if request_wants_json():
        return make_stormpath_response(data=form.json)

    return make_stormpath_response(
         template=forgot_config['template'], data={'form': form},
         return_json=False)


def forgot_change():
    """
    Allow a user to change his password.

    This can only happen if a use has reset their password, received the
    password reset email, then clicked the link in the email which redirects
    them to this view.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """
    try:
        account = (
            current_app.stormpath_manager.application.
            verify_password_reset_token(request.args.get('sptoken')))
    except StormpathError as err:
        abort(400)

    change_config = current_app.config['stormpath']['web']['changePassword']
    form = StormpathForm.specialize_form(change_config['form'])()

    if request.method == 'POST':
        # If we received a POST request with valid information, we'll continue
        # processing.
        if not form.validate_on_submit():
            # If form.data is not valid, return error messages.
            if request_wants_json():
                return make_stormpath_response(
                    data=json.dumps({
                        'status': 400,
                        'message': form.errors}),
                    status_code=400)

            for field_error in form.errors.keys():
                flash(form.errors[field_error][0])

        else:
            try:
                # Update this user's passsword.
                account.password = form.password.data
                account.save()

                # Log this user into their account.
                account = User.from_login(account.email, form.password.data)
                login_user(account, remember=True)

                if request_wants_json():
                    return make_stormpath_response(data=current_user.to_json())

                return make_stormpath_response(
                    template='flask_stormpath/forgot_complete.html',
                    data={'form': form}, return_json=False)

            except StormpathError as err:
                if (isinstance(err.message, string_types) and
                        'https' in err.message.lower()):
                    error_msg = 'Something went wrong! Please try again.'
                else:
                    error_msg = err.message.get('message')

                if request_wants_json():
                    status_code = err.status if err.status else 400
                    return make_stormpath_response(
                        json.dumps({
                            'status': status_code,
                            'message': error_msg}),
                        status_code=status_code)
                flash(error_msg)

    if request_wants_json():
        return make_stormpath_response(data=form.json)

    return make_stormpath_response(
        template=change_config['template'], data={'form': form},
        return_json=False)


def facebook_login():
    """
    Handle Facebook login.

    When a user logs in with Facebook, all of the authentication happens on the
    client side with Javascript.  Since all authentication happens with
    Javascript, we *need* to force a newly created and / or logged in Facebook
    user to redirect to this view.

    What this view does is:

        - Read the user's session using the Facebook SDK, extracting the user's
          Facebook access token.
        - Once we have the user's access token, we send it to Stormpath, so
          that we can either create (or update) the user on Stormpath's side.
        - Then we retrieve the Stormpath account object for the user, and log
          them in using our normal session support (powered by Flask-Login).

    Although this is slighly complicated, this gives us the power to then treat
    Facebook users like any other normal Stormpath user -- we can assert group
    permissions, authentication, etc.

    The location this view redirects users to can be configured via
    Flask-Stormpath settings.
    """
    if not FACEBOOK:
        raise StormpathError({
            'developerMessage': 'Facebook does not support python 3'
        })
    # First, we'll try to grab the Facebook user's data by accessing their
    # session data.
    facebook_user = get_user_from_cookie(
        request.cookies,
        current_app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_id'],
        current_app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_secret'],
    )

    # Now, we'll try to have Stormpath either create or update this user's
    # Stormpath account, by automatically handling the Facebook Graph API stuff
    # for us.
    try:
        account = User.from_facebook(facebook_user['access_token'])
    except StormpathError as err:
        social_directory_exists = False

        # If we failed here, it usually means that this application doesn't
        # have a Facebook directory -- so we'll create one!
        for asm in (
                current_app.stormpath_manager.application.
                account_store_mappings):

            # If there is a Facebook directory, we know this isn't the problem.
            if (
                getattr(asm.account_store, 'provider') and
                asm.account_store.provider.provider_id == Provider.FACEBOOK
            ):
                social_directory_exists = True
                break

        # If there is a Facebook directory already, we'll just pass on the
        # exception we got.
        if social_directory_exists:
            raise err

        # Otherwise, we'll try to create a Facebook directory on the user's
        # behalf (magic!).
        dir = current_app.stormpath_manager.client.directories.create({
            'name': (
                current_app.stormpath_manager.application.name + '-facebook'),
            'provider': {
                'client_id': current_app.config['STORMPATH_SOCIAL'][
                    'FACEBOOK']['app_id'],
                'client_secret': current_app.config['STORMPATH_SOCIAL'][
                    'FACEBOOK']['app_secret'],
                'provider_id': Provider.FACEBOOK,
            },
        })

        # Now that we have a Facebook directory, we'll map it to our
        # application so it is active.
        asm = (
            current_app.stormpath_manager.application.account_store_mappings.
            create({
                'application': current_app.stormpath_manager.application,
                'account_store': dir,
                'list_index': 99,
                'is_default_account_store': False,
                'is_default_group_store': False,
            }))

        # Lastly, let's retry the Facebook login one more time.
        account = User.from_facebook(facebook_user['access_token'])

    # Now we'll log the new user into their account.  From this point on, this
    # Facebook user will be treated exactly like a normal Stormpath user!
    login_user(account, remember=True)

    return redirect(request.args.get('next') or
                    current_app.config['stormpath']['web']['login']['nextUri'])


def google_login():
    """
    Handle Google login.

    When a user logs in with Google (using Javascript), Google will redirect
    the user to this view, along with an access code for the user.

    What we do here is grab this access code and send it to Stormpath to handle
    the OAuth negotiation.  Once this is done, we log this user in using normal
    sessions, and from this point on -- this user is treated like a normal
    system user!

    The location this view redirects users to can be configured via
    Flask-Stormpath settings.
    """
    # First, we'll try to grab the 'code' query string that Google should be
    # passing to us.  If this doesn't exist, we'll abort with a 400 BAD REQUEST
    # (since something horrible must have happened).
    code = request.args.get('code')
    if not code:
        abort(400)

    # Next, we'll try to have Stormpath either create or update this user's
    # Stormpath account, by automatically handling the Google API stuff for us.
    try:
        account = User.from_google(code)
    except StormpathError as err:
        social_directory_exists = False

        # If we failed here, it usually means that this application doesn't
        # have a Google directory -- so we'll create one!
        for asm in (
                current_app.stormpath_manager.application.
                account_store_mappings):

            # If there is a Google directory, we know this isn't the problem.
            if (
                getattr(asm.account_store, 'provider') and
                asm.account_store.provider.provider_id == Provider.GOOGLE
            ):
                social_directory_exists = True
                break

        # If there is a Google directory already, we'll just pass on the
        # exception we got.
        if social_directory_exists:
            raise err

        # Otherwise, we'll try to create a Google directory on the user's
        # behalf (magic!).
        dir = current_app.stormpath_manager.client.directories.create({
            'name': current_app.stormpath_manager.application.name + '-google',
            'provider': {
                'client_id': current_app.config['STORMPATH_SOCIAL']['GOOGLE'][
                    'client_id'],
                'client_secret': current_app.config['STORMPATH_SOCIAL'][
                    'GOOGLE']['client_secret'],
                'redirect_uri': request.url_root[:-1] + current_app.config[
                    'STORMPATH_GOOGLE_LOGIN_URL'],
                'provider_id': Provider.GOOGLE,
            },
        })

        # Now that we have a Google directory, we'll map it to our application
        # so it is active.
        asm = (
            current_app.stormpath_manager.application.account_store_mappings.
            create({
                'application': current_app.stormpath_manager.application,
                'account_store': dir,
                'list_index': 99,
                'is_default_account_store': False,
                'is_default_group_store': False,
            }))

        # Lastly, let's retry the Facebook login one more time.
        account = User.from_google(code)

    # Now we'll log the new user into their account.  From this point on, this
    # Google user will be treated exactly like a normal Stormpath user!
    login_user(account, remember=True)

    return redirect(request.args.get('next') or
                    current_app.config['stormpath']['web']['login']['nextUri'])


def logout():
    """
    Log a user out of their account.

    This view will log a user out of their account (destroying their session),
    then redirect the user to the home page of the site.
    """
    logout_user()
    return redirect(
        current_app.config['stormpath']['web']['logout']['nextUri'])


@login_required
def me():
    expansion = Expansion()
    for attr, flag in current_app.config['stormpath']['web']['me'][
            'expand'].items():
        if flag:
            expansion.add_property(attr)
    if expansion.items:
        current_user._expand = expansion
    current_user.refresh()

    return make_stormpath_response(current_user.to_json())
