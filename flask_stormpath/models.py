"""Custom data models."""


from flask import current_app, request
from six import text_type

from blinker import Namespace

from stormpath.resources.account import Account
from stormpath.resources.provider import Provider
from . import StormpathError
from datetime import datetime
import json


stormpath_signals = Namespace()
user_created = stormpath_signals.signal('user-created')
user_updated = stormpath_signals.signal('user-updated')
user_deleted = stormpath_signals.signal('user-deleted')


class User(Account):
    """
    The base User object.

    This can be used as described in the Stormpath Python SDK documentation:
    https://github.com/stormpath/stormpath-sdk-python
    """
    def __repr__(self):
        return u'User <"%s" ("%s")>' % (self.username or self.email, self.href)

    def get_id(self):
        """
        Return the unique user identifier (in our case, the Stormpath resource
        href).
        """
        return text_type(self.href)

    @property
    def is_active(self):
        """
        A user account is active if, and only if, their account status is
        'ENABLED'.
        """
        return self.status == 'ENABLED'

    @property
    def is_anonymous(self):
        """
        We don't support anonymous users, so this is always False.
        """
        return False

    @property
    def is_authenticated(self):
        """
        All users will always be authenticated, so this will always return
        True.
        """
        return True

    def save(self):
        """
        Send signal after user is updated.
        """
        super(User, self).save()
        user_updated.send(self, user=dict(self))
        return self

    def delete(self):
        """
        Send signal after user is deleted.
        """
        user_dict = dict(self)
        return_value = super(User, self).delete()
        user_deleted.send(None, user=user_dict)
        return return_value

    def to_json(self):
        def datetime_handler(obj):
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            else:
                raise TypeError

        attrs = (
            'href',
            'modified_at',
            'created_at',
            'status',
            'username',
            'email',
            'given_name',
            'middle_name',
            'surname',
            'full_name'
        )
        json_data = {
            'account': {attr: getattr(self, attr, None) for attr in attrs}}

        # In case me view was called with expanded options enabled.
        if hasattr(self._expand, 'items'):
            json_data['account'].update(self._expand.items)

        return json.dumps(json_data, default=datetime_handler)

    @classmethod
    def create(
            self, email=None, password=None, given_name=None, surname=None,
            username=None, middle_name=None, custom_data=None,
            status='ENABLED'):
        """
        Create a new User.

        Required Parameters
        -------------------

        :param str email: This user's unique email address.
        :param str password: This user's password, in plain text.
        :param str given_name: This user's first name (Randall).
        :param str surname: This user's last name (Degges).

        Optional Parameters
        -------------------

        :param str username: If no `username` is supplied, the `username` field
            will be set to the user's email address automatically.  Stormpath
            users can log in with either an `email` or `username` (both are
            interchangeable).
        :param str middle_name: This user's middle name ('Clark').
        :param dict custom_data: Any custom JSON data you'd like stored with
            this user.  Must be <= 10MB.
        :param str status: The user's status (*defaults to 'ENABLED'*). Can be
            either 'ENABLED', 'DISABLED', or 'UNVERIFIED'.

        If something goes wrong we'll raise an exception -- most likely -- a
        `StormpathError` (flask_stormpath.StormpathError).
        """
        _user = current_app.stormpath_manager.application.accounts.create({
            'email': email,
            'password': password,
            'given_name': given_name,
            'surname': surname,
            'username': username,
            'middle_name': middle_name,
            'custom_data': custom_data,
            'status': status,
        })
        _user.__class__ = User
        user_created.send(self, user=dict(_user))

        return _user

    @classmethod
    def from_login(self, login, password):
        """
        Create a new User class given a login (`email` or `username`), and
        password.

        If something goes wrong, this will raise an exception -- most likely --
        a `StormpathError` (flask_stormpath.StormpathError).
        """
        _user = current_app.stormpath_manager.application.authenticate_account(
            login, password).account
        _user.refresh()
        _user.__class__ = User

        return _user

    @staticmethod
    def from_social(social_name, access_token, provider):
        """
        Helper method for our social methods.
        """

        kwargs = {'provider': provider.get('provider_id')}
        if social_name == 'facebook':
            kwargs['access_token'] = access_token
        elif social_name == 'google':
            kwargs['code'] = access_token
        else:
            raise ValueError('Social service is not supported.')

        try:
            _user = (
                current_app.stormpath_manager.
                application.get_provider_account(**kwargs))
        except StormpathError as err:
            social_directory_exists = False

            # If we failed here, it usually means that this application doesn't
            # have a social directory -- so we'll create one!
            for asm in (
                    current_app.stormpath_manager.application.
                    account_store_mappings):

                # If there is a social directory, we know this isn't the
                # problem.
                if (
                    getattr(asm.account_store, 'provider') and
                    asm.account_store.provider.provider_id == provider.get(
                        'provider_id')
                ):
                    social_directory_exists = True
                    break

            # If there is a social directory already, we'll just pass on the
            # exception we got.
            if social_directory_exists:
                raise err

            # Otherwise, we'll try to create a social directory on the user's
            # behalf (magic!).
            dir = current_app.stormpath_manager.client.directories.create({
                'name': (
                    current_app.stormpath_manager.application.name +
                    '-' + social_name),
                'provider': provider
            })

            # Now that we have a social directory, we'll map it to our
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

            # Lastly, let's retry the social login one more time.
            _user = (
                current_app.stormpath_manager.
                application.get_provider_account(**kwargs))

        _user.__class__ = User
        return _user

    @classmethod
    def from_google(self, code):
        """
        Create a new User class given a Google access code.

        Access codes must be retrieved from Google's OAuth service (Google
        Login).

        If something goes wrong, this will raise an exception -- most likely --
        a `StormpathError` (flask_stormpath.StormpathError).
        """
        provider = {
            'client_id': current_app.config[
                'stormpath']['web']['social']['google']['clientId'],
            'client_secret': current_app.config[
                'stormpath']['web']['social']['google']['clientSecret'],
            'redirect_uri': request.url_root[:-1] + current_app.config[
                'stormpath']['web']['social']['google']['login_url'],
            'provider_id': Provider.GOOGLE,
        }
        return self.from_social('google', code, provider)

    @classmethod
    def from_facebook(self, access_token):
        """
        Create a new User class given a Facebook user's access token.

        Access tokens must be retrieved from Facebooks's OAuth service
        (Facebook Login).

        If something goes wrong, this will raise an exception -- most likely --
        a `StormpathError` (flask_stormpath.StormpathError).
        """
        provider = {
            'client_id': current_app.config[
                'stormpath']['web']['social']['facebook']['clientId'],
            'client_secret': current_app.config[
                'stormpath']['web']['social']['facebook']['clientId'],
            'provider_id': Provider.FACEBOOK,
        }
        return self.from_social('facebook', access_token, provider)
