"""Our pluggable views."""


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
from flask_login import (
    login_user, logout_user, login_required, current_user)
from six import string_types
from stormpath.resources.provider import Provider
from stormpath.resources import Expansion
from . import StormpathError
from .forms import StormpathForm
from .models import User
from facebook import get_user_from_cookie


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

        # Fetch the request type and match it against our allowed types.
        self.allowed_types = current_app.config['stormpath']['web']['produces']
        self.request_accept_types = request.accept_mimetypes
        self.accept_header = self.request_accept_types.best_match(
            self.allowed_types)

        # If no accept types are specified, or the preferred accept type is
        # */*, response type will be the first element of self.allowed_types.
        if (not self.request_accept_types or
                self.request_accept_types[0][0] == '*/*'):
            self.accept_header = self.allowed_types[0]

        # If the request type is specified, but not html or json, mark the
        # invalid_request flag.
        if self.accept_header not in self.allowed_types:
            self.invalid_request = True
        else:
            self.invalid_request = False

        # Build the form
        if self.request_wants_json:
            form_kwargs = {'meta': {'csrf': False}}
        else:
            form_kwargs = {'meta': {'csrf': True}}
        self.form = StormpathForm.specialize_form(
            config.get('form'))(**form_kwargs)

    def make_stormpath_response(
            self, data, template=None, return_json=True, status_code=200):
        """ Create a response based on request type (html or json). """
        if return_json:
            stormpath_response = make_response(data, status_code)
            stormpath_response.mimetype = 'application/json'
        else:
            stormpath_response = render_template(template, **data)
        return stormpath_response

    @property
    def request_wants_json(self):
        """ Check if request wants json. """
        return self.accept_header == 'application/json'

    def process_request(self):
        """ Custom logic specialized for each view. Must be implemented in
            the subclass. """
        raise NotImplementedError('Subclasses must implement this method.')

    def process_stormpath_error(self, error):
        """ Check for StormpathErrors. """

        # Sets an error message.
        error_message = (
            error.user_message if error.user_message else error.message)

        if self.request_wants_json:
            status_code = error.status if error.status else 400
            return self.make_stormpath_response(
                data=json.dumps({
                    'status': status_code,
                    'message': error_message}),
                status_code=status_code)
        flash(error_message)
        return None

    def dispatch_request(self):
        """ Basic view skeleton. """

        # If the request is not valid, pass the response to the
        # 'invalid_request' view.
        if self.invalid_request:
            invalid_request_uri = current_app.config[
                'stormpath']['web']['invalidRequest']['uri']
            endpoints = [
                rule.rule for rule in current_app.url_map.iter_rules()]

            # Redirect to a flask view for invalid requests (if implemented).
            # If not, return a 501.
            if invalid_request_uri in endpoints:
                return redirect(invalid_request_uri)
            else:
                abort(501)

        if request.method == 'POST':
            # If we received a POST request with valid information, we'll
            # continue processing.

            if not self.form.validate_on_submit():
                # If form.data is not valid, return error messages.
                if self.request_wants_json:
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

        if self.request_wants_json:
            return self.make_stormpath_response(data=self.form.json)

        return self.make_stormpath_response(
            template=self.template, data={'form': self.form},
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
    template = 'flask_stormpath/register.html'

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

        # If verifyEmail is enabled, send a verification email.
        # FIXME: Edit templates to show a verification email has been sent.
        # FIXME: error message is None
        pass

        # If we're able to successfully create the user's account,
        # we'll log the user in (creating a secure session using
        # Flask-Login), then redirect the user to the
        # Stormpath login nextUri setting but only if autoLogin is enabled.
        if (self.config['autoLogin'] and not current_app.config[
                'stormpath']['web']['verifyEmail']['enabled']):
            login_user(account, remember=True)

        if self.request_wants_json:
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
    template = 'flask_stormpath/login.html'

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

        if self.request_wants_json:
            return self.make_stormpath_response(data=current_user.to_json())

        # Set redirect priority
        redirect_url = request.args.get('next')
        if not redirect_url:
            redirect_url = self.config['nextUri']
            if not redirect_url:
                redirect_url = '/'
        return redirect(redirect_url)


class ForgotPasswordView(StormpathView):
    """
    Initialize 'password reset' functionality for a user who has forgotten his
    password.

    This view will render a forgot template, which prompts a user for their
    email address, then sends a password reset email.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """
    template = 'flask_stormpath/forgot_password.html'
    template_success = 'flask_stormpath/forgot_password_success.html'

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['forgotPassword']
        super(ForgotPasswordView, self).__init__(config, *args, **kwargs)

    def process_stormpath_error(self, error):
        # If the error message contains 'https', it means something
        # failed on the network (network connectivity, most likely).
        if (isinstance(error.message, string_types) and
                'https' in error.message.lower()):
            error.user_message = 'Something went wrong! Please try again.'

        # Otherwise, it means the user is trying to reset an invalid
        # email address.
        else:
            error.user_message = 'Invalid email address.'
        return super(ForgotPasswordView, self).process_stormpath_error(error)

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

        if self.request_wants_json:
            return self.make_stormpath_response(
                data=json.dumps({
                    'status': 200,
                    'message': {'email': self.form.data.get('email')}}),
                status_code=200)

        return self.make_stormpath_response(
            template=self.template_success, data={'user': account},
            return_json=False)


class ChangePasswordView(StormpathView):
    """
    Allow a user to change his password.

    This can only happen if a use has reset their password, received the
    password reset email, then clicked the link in the email which redirects
    them to this view.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """
    template = "flask_stormpath/change_password.html"
    template_success = "flask_stormpath/change_password_success.html"

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['changePassword']
        super(ChangePasswordView, self).__init__(config, *args, **kwargs)
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
            error.user_message = 'Something went wrong! Please try again.'
        return super(ChangePasswordView, self).process_stormpath_error(error)

    def process_request(self):
        # Update this user's passsword.
        self.account.password = self.form.password.data
        self.account.save()

        # Log this user into their account.
        account = User.from_login(self.account.email, self.form.password.data)
        login_user(account, remember=True)

        if self.request_wants_json:
            return self.make_stormpath_response(data=current_user.to_json())

        return self.make_stormpath_response(
            template=self.template_success, data={'form': self.form},
            return_json=False)


class VerifyEmailView(StormpathView):
    """
    Verify a newly created Stormpath user.

    This view will activate a user's account with the token specified in the
    activation link the user received via email. If the token is invalid or
    missing, the user can request a new activation link.

    The URL this view is bound to, and the template that is used to render
    this page can all be controlled via Flask-Stormpath settings.
    """
    template = "flask_stormpath/verify_email.html"

    def __init__(self, *args, **kwargs):
        config = current_app.config['stormpath']['web']['verifyEmail']
        super(VerifyEmailView, self).__init__(config, *args, **kwargs)

    def process_stormpath_error(self, error):
        # If the error message contains 'https', it means something
        # failed on the network (network connectivity, most likely).
        if (isinstance(error.message, string_types) and
                'https' in error.message.lower()):
            error.user_message = 'Something went wrong! Please try again.'
        return super(VerifyEmailView, self).process_stormpath_error(error)

    def dispatch_request(self):
        # If the request is POST, resend the confirmation email.
        if request.method == 'POST':
            # If form.data is not valid, return error messages.
            if not self.form.validate_on_submit():
                if self.request_wants_json:
                    return self.make_stormpath_response(
                        data=json.dumps({
                            'status': 400,
                            'message': self.form.errors}),
                        status_code=400)
                for field_error in self.form.errors.keys():
                    flash(self.form.errors[field_error][0])
                redirect_url = request.url
            else:
                # Try to retrieve an account associated with the email.
                search_query = (
                    current_app.stormpath_manager.client.tenant.accounts.
                    search(self.form.data.get('email')))

                if search_query.items:
                    account = search_query.items[0]

                    # Resend the activation token
                    (current_app.stormpath_manager.application.
                        verification_emails.resend(account, account.directory))

                if self.request_wants_json:
                        return self.make_stormpath_response(
                            data=json.dumps({}))
                redirect_url = self.config['errorUri']

        # If the request is GET, try to parse and verify the authorization
        # token.
        else:
            verification_token = request.args.get('sptoken', '')
            try:
                # Try to verify the sptoken.
                account = (
                    current_app.stormpath_manager.client.accounts.
                    verify_email_token(verification_token)
                )
                account.__class__ = User

                # If autologin is enabled, log the user in and redirect him
                # to login nextUri. If not, redirect to verifyEmail nextUri.
                if current_app.config[
                        'stormpath']['web']['register']['autoLogin']:
                    login_user(account, remember=True)
                    account.refresh()
                    if self.request_wants_json:
                        return self.make_stormpath_response(
                            data=account.to_json())
                    redirect_url = current_app.config[
                        'stormpath']['web']['login']['nextUri']
                else:
                    if self.request_wants_json:
                        return self.make_stormpath_response(
                            data=json.dumps({}))
                    redirect_url = self.config['nextUri']

            except StormpathError as error:
                # If the sptoken is invalid or missing, render an email
                # form that will resend an sptoken to the new email provided.

                # Sets an error message.
                if self.request_wants_json:
                    if error.status == 400:
                        error_message = 'sptoken parameter not provided.'
                    else:
                        error_message = (
                            error.user_message if error.user_message
                            else error.message)

                    return self.make_stormpath_response(
                        data=json.dumps({
                            'status': error.status,
                            'message': error_message}),
                        status_code=error.status)

                return self.make_stormpath_response(
                    template=self.template, data={'form': self.form},
                    return_json=False)

        # Set redirect priority
        if not redirect_url:
            redirect_url = '/'
        return redirect(redirect_url)


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

        # Set redirect priority
        redirect_url = self.config['nextUri']
        if not redirect_url:
            redirect_url = '/'
        return redirect(redirect_url)


class MeView(View):
    """
    Get a JSON object with the current user information.

    .. note::
        We'll override the default StormpathView logic, since we don't need
        json support or form and api request validation.
    """
    decorators = [login_required]

    def dispatch_request(self):
        expansion = Expansion()
        for attr, flag in current_app.config['stormpath']['web']['me'][
                'expand'].items():
            if flag:
                expansion.add_property(attr)
        if expansion.items:
            current_user._expand = expansion
        current_user.refresh()

        response = make_response(current_user.to_json(), 200)
        response.mimetype = 'application/json'
        return response


""" Social views. """


class SocialView(View):
    """ Parent class for social login views. """
    def __init__(self, *args, **kwargs):
        # First validate social view call
        social_name = kwargs.pop('social_name')
        if social_name not in ['facebook', 'google']:
            raise ValueError('Social service is not supported.')
        self.social_name = social_name

        # Then set the access token and the provider
        self.access_token = kwargs.pop('access_token')
        self.provider_social = getattr(Provider, self.social_name.upper())

        # Set a user error message in case the login fails.
        self.error_message = (
            'Oops! We encountered an unexpected error.  Please contact ' +
            'support and explain what you were doing at the time this ' +
            'error occurred.'
        )

    def get_account(self):
        return getattr(
            User, 'from_%s' % self.social_name)(self.access_token)

    def dispatch_request(self):
        """ Basic social view skeleton. """
        # We'll try to have Stormpath either create or update this user's
        # Stormpath account, by automatically handling the social API stuff
        # for us.
        try:
            account = self.get_account()
        except StormpathError:
            flash(self.error_message)
            redirect_url = current_app.config[
                'stormpath']['web']['login']['uri']
            return redirect(redirect_url if redirect_url else '/')

        # Now we'll log the new user into their account.  From this point on,
        # this social user will be treated exactly like a normal Stormpath
        # user!
        login_user(account, remember=True)

        return redirect(
            request.args.get('next') or
            current_app.config['stormpath']['web']['login']['nextUri'])


class FacebookLoginView(SocialView):
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
        # We'll try to grab the Facebook user's data by accessing their
        # session data. If this doesn't exist, we'll abort with a
        # 400 BAD REQUEST (since something horrible must have happened).
        facebook_user = get_user_from_cookie(
            request.cookies,
            current_app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_id'],
            current_app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_secret'],
        )
        if facebook_user:
            access_token = facebook_user.get('access_token')
        else:
            abort(400)

        super(FacebookLoginView, self).__init__(
            social_name='facebook', access_token=access_token)


class GoogleLoginView(SocialView):
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
        # We'll try to grab the 'code' query string that Google should
        # be passing to us.  If this doesn't exist, we'll abort with a
        # 400 BAD REQUEST (since something horrible must have happened).
        code = request.args.get('code')
        if not code:
            abort(400)

        super(GoogleLoginView, self).__init__(
            social_name='google', access_token=code)
