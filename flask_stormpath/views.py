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
from flask.views import View
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


""" Views parent class. """


class StormpathView(View):
    """
    Class for Stormpath views.

    This class initializes form building through config specs and handles
    both html and json responses.
    Specialized logic for each view is handled in the process_request method
    and should be specified on each child class.
    """

    def __init__(self, config, *args, **kwargs):
        self.config = config
        self.form = (
            StormpathForm.specialize_form(config['form'])()
            if config else None)
        self.allowed_types = current_app.config['stormpath']['web']['produces']
        self.accept_header = request.accept_mimetypes.best_match(
            self.allowed_types)

    def make_stormpath_response(
            self, data, template=None, return_json=True, status_code=200):
        """ Create a response based on request type (html or json). """
        if return_json:
            stormpath_response = make_response(data, status_code)
            stormpath_response.mimetype = 'application/json'
        else:
            stormpath_response = render_template(template, **data)
        return stormpath_response

    def request_wants_json(self):
        """ Check if request wants json. """
        return self.accept_header == 'application/json'

    def validate_request(self):
        """ If the request type is not html or json, return 406. """
        if self.accept_header not in self.allowed_types:
            abort(406)

    def process_request(self):
        """ Custom logic specialized for each view. Must be implemented in
            the subclass. """
        raise StormpathForm('You must implement process_request on your view.')

    def process_stormpath_error(self, error):
        """ Check for StormpathErrors. """
        if self.request_wants_json():
            status_code = error.status if error.status else 400
            return self.make_stormpath_response(
                json.dumps({
                    'status': status_code,
                    'message': error.message.get('message')}),
                status_code=status_code)
        flash(error.message.get('message'))
        return None

    def dispatch_request(self):
        """ Basic view skeleton. """

        # Ensure the request is either html or json.
        self.validate_request()

        if request.method == 'POST':
            # If we received a POST request with valid information, we'll
            # continue processing.

            if not self.form.validate_on_submit():
                # If form.data is not valid, return error messages.
                if self.request_wants_json():
                    return self.make_stormpath_response(
                        data=json.dumps({
                            'status': 400,
                            'message': self.form.errors}),
                        status_code=400)
                for field_error in self.form.errors.keys():
                    flash(self.form.errors[field_error][0])

            else:
                try:
                    return self.process_request()
                except StormpathError as error:
                    stormpath_error = self.process_stormpath_error(error)
                    if stormpath_error:
                        return stormpath_error

        if self.request_wants_json():
            return self.make_stormpath_response(data=self.form.json)

        return self.make_stormpath_response(
            template=self.config['template'], data={'form': self.form},
            return_json=False)


""" Child views. """


class RegisterView(StormpathView):
    """
    Register a new user with Stormpath.

    This view will render a registration template, and attempt to create a new
    user account with Stormpath.

    The fields that are asked for, the URL this view is bound to, and the
    template that is used to render this page can all be controlled via
    Flask-Stormpath settings.
    """

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['register']
        super(RegisterView, self).__init__(config, *args, **kwargs)
        self.data = self.form.data

    def process_request(self):
        # We'll just set the field values to 'Anonymous' if the user
        # has explicitly said they don't want to collect those fields.
        for field in ['given_name', 'surname']:
            if not self.data.get(field):
                self.data[field] = 'Anonymous'
        # Remove the confirmation password so it won't cause an error
        if 'confirm_password' in self.data:
            self.data.pop('confirm_password')

        # Create the user account on Stormpath.  If this fails, an
        # exception will be raised.

        account = User.create(**self.data)
        # If we're able to successfully create the user's account,
        # we'll log the user in (creating a secure session using
        # Flask-Login), then redirect the user to the
        # Stormpath login nextUri setting but only if autoLogin.
        if (self.config['autoLogin'] and not current_app.config[
                'stormpath']['web']['verifyEmail']['enabled']):
            login_user(account, remember=True)

        if self.request_wants_json():
            return self.make_stormpath_response(data=account.to_json())

        # Set redirect priority
        redirect_url = self.config['nextUri']
        if not redirect_url:
            redirect_url = current_app.config['stormpath'][
                'web']['login']['nextUri']
            if not redirect_url:
                redirect_url = '/'
        return redirect(redirect_url)


class LoginView(StormpathView):
    """
    Log in an existing Stormpath user.

    This view will render a login template, then redirect the user to the next
    page (if authentication is successful).

    The fields that are asked for, the URL this view is bound to, and the
    template that is used to render this page can all be controlled via
    Flask-Stormpath settings.
    """

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['login']
        super(LoginView, self).__init__(config, *args, **kwargs)

    def process_request(self):
        # Try to fetch the user's account from Stormpath.  If this
        # fails, an exception will be raised.
        account = User.from_login(
            self.form.login.data, self.form.password.data)

        # If we're able to successfully retrieve the user's account,
        # we'll log the user in (creating a secure session using
        # Flask-Login), then redirect the user to the ?next=<url>
        # query parameter, or the Stormpath login nextUri setting.
        login_user(account, remember=True)

        if self.request_wants_json():
            return self.make_stormpath_response(data=current_user.to_json())

        return redirect(request.args.get('next') or self.config['nextUri'])


class ForgotView(StormpathView):
    """
    Initialize 'password reset' functionality for a user who has forgotten his
    password.

    This view will render a forgot template, which prompts a user for their
    email address, then sends a password reset email.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['forgotPassword']
        super(ForgotView, self).__init__(config, *args, **kwargs)

    def process_stormpath_error(self, error):
        # If the error message contains 'https', it means something
        # failed on the network (network connectivity, most likely).
        if (isinstance(error.message, string_types) and
                'https' in error.message.lower()):
            error.message['message'] = (
                'Something went wrong! Please try again.')

        # Otherwise, it means the user is trying to reset an invalid
        # email address.
        else:
            error.message['message'] = 'Invalid email address.'
        return super(ForgotView, self).process_stormpath_error(error)

    def process_request(self):
        # Try to fetch the user's account from Stormpath.  If this
        # fails, an exception will be raised.
        account = (
            current_app.stormpath_manager.application.
            send_password_reset_email(self.form.email.data))
        account.__class__ = User

        # If we're able to successfully send a password reset email to
        # this user, we'll display a success page prompting the user
        # to check their inbox to complete the password reset process.

        if self.request_wants_json():
            return self.make_stormpath_response(
                data=json.dumps({
                    'status': 200,
                    'message': {'email': self.form.data.get('email')}}),
                status_code=200)

        return self.make_stormpath_response(
            template=self.config['templateSuccess'],
            data={'user': account}, return_json=False)


class ChangeView(StormpathView):
    """
    Allow a user to change his password.

    This can only happen if a use has reset their password, received the
    password reset email, then clicked the link in the email which redirects
    them to this view.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['changePassword']
        super(ChangeView, self).__init__(config, *args, **kwargs)
        try:
            self.account = (
                current_app.stormpath_manager.application.
                verify_password_reset_token(request.args.get('sptoken')))
        except StormpathError:
            abort(400)

    def process_stormpath_error(self, error):
        # If the error message contains 'https', it means something
        # failed on the network (network connectivity, most likely).
        if (isinstance(error.message, string_types) and
                'https' in error.message.lower()):
            error.message['message'] = (
                'Something went wrong! Please try again.')
        return super(ChangeView, self).process_stormpath_error(error)

    def process_request(self):
        # Update this user's passsword.
        self.account.password = self.form.password.data
        self.account.save()

        # Log this user into their account.
        account = User.from_login(self.account.email, self.form.password.data)
        login_user(account, remember=True)

        if self.request_wants_json():
            return self.make_stormpath_response(data=current_user.to_json())

        return self.make_stormpath_response(
            template=self.config['templateSuccess'],
            data={'form': self.form}, return_json=False)


class LogoutView(StormpathView):
    """
    Log a user out of their account.

    This view will log a user out of their account (destroying their session),
    then redirect the user to the home page of the site.

    .. note::
        We'll override the default StormpathView logic, since we don't need
        form and api request validation.
    """

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['logout'].copy()

        # We'll pass login form here since logout needs the form for the json
        # response. (Successful logout redirects to login view.)
        config['form'] = current_app.config['stormpath']['web']['login'][
            'form']
        super(LogoutView, self).__init__(config, *args, **kwargs)

    def dispatch_request(self):
        logout_user()

        if self.request_wants_json():
            return self.make_stormpath_response(data=self.form.json)

        return redirect(self.config['nextUri'])


class MeView(StormpathView):
    """
    Get a JSON object with the current user information.

    .. note::
        We'll override the default StormpathView logic, since we don't need
        json support or form and api request validation.
    """
    decorators = [login_required]

    def __init__(self, *args, **kwargs):
        pass

    def dispatch_request(self):
        expansion = Expansion()
        for attr, flag in current_app.config['stormpath']['web']['me'][
                'expand'].items():
            if flag:
                expansion.add_property(attr)
        if expansion.items:
            current_user._expand = expansion
        current_user.refresh()

        return self.make_stormpath_response(current_user.to_json())


""" Social views. """


class FacebookLoginView(StormpathView):
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

    def __init__(self, *args, **kwargs):
        super(FacebookLoginView, self).__init__({})

    def dispatch_request(self):
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
        # Stormpath account, by automatically handling the Facebook Graph API
        # stuff for us.
        try:
            account = User.from_facebook(facebook_user.get('access_token'))
        except StormpathError as err:
            social_directory_exists = False

            # If we failed here, it usually means that this application doesn't
            # have a Facebook directory -- so we'll create one!
            for asm in (
                    current_app.stormpath_manager.application.
                    account_store_mappings):

                # If there is a Facebook directory, we know this isn't the
                # problem.
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
                    current_app.stormpath_manager.application.name +
                    '-facebook'),
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
                current_app.stormpath_manager.application.
                account_store_mappings.create({
                    'application': current_app.stormpath_manager.application,
                    'account_store': dir,
                    'list_index': 99,
                    'is_default_account_store': False,
                    'is_default_group_store': False,
                }))

            # Lastly, let's retry the Facebook login one more time.
            account = User.from_facebook(facebook_user['access_token'])

        # Now we'll log the new user into their account.  From this point on,
        # this Facebook user will be treated exactly like a normal Stormpath
        # user!
        login_user(account, remember=True)

        return redirect(
            request.args.get('next') or
            current_app.config['stormpath']['web']['login']['nextUri'])


class GoogleLoginView(StormpathView):
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
    def __init__(self, *args, **kwargs):
        super(GoogleLoginView, self).__init__({})

    def dispatch_request(self):
        # First, we'll try to grab the 'code' query string that Google should
        # be passing to us.  If this doesn't exist, we'll abort with a
        # 400 BAD REQUEST (since something horrible must have happened).
        code = request.args.get('code')
        if not code:
            abort(400)

        # Next, we'll try to have Stormpath either create or update this user's
        # Stormpath account, by automatically handling the Google API stuff
        # for us.
        try:
            account = User.from_google(code)
        except StormpathError as err:
            social_directory_exists = False

            # If we failed here, it usually means that this application doesn't
            # have a Google directory -- so we'll create one!
            for asm in (
                    current_app.stormpath_manager.application.
                    account_store_mappings):

                # If there is a Google directory, we know this isn't the
                # problem.
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
                'name': (
                    current_app.stormpath_manager.application.name +
                    '-google'),
                'provider': {
                    'client_id': current_app.config['STORMPATH_SOCIAL'][
                        'GOOGLE']['client_id'],
                    'client_secret': current_app.config['STORMPATH_SOCIAL'][
                        'GOOGLE']['client_secret'],
                    'redirect_uri': request.url_root[:-1] + current_app.config[
                        'STORMPATH_GOOGLE_LOGIN_URL'],
                    'provider_id': Provider.GOOGLE,
                },
            })

            # Now that we have a Google directory, we'll map it to our
            # application so it is active.
            asm = (
                current_app.stormpath_manager.application.
                account_store_mappings.create({
                    'application': current_app.stormpath_manager.application,
                    'account_store': dir,
                    'list_index': 99,
                    'is_default_account_store': False,
                    'is_default_group_store': False,
                }))

            # Lastly, let's retry the Facebook login one more time.
            account = User.from_google(code)

        # Now we'll log the new user into their account.  From this point on,
        # this Google user will be treated exactly like a normal Stormpath
        # user!
        login_user(account, remember=True)

        return redirect(
            request.args.get('next') or
            current_app.config['stormpath']['web']['login']['nextUri'])
