"""Tests for our data models."""


from flask_stormpath.models import User
from flask_stormpath import StormpathError
from stormpath.resources.account import Account
from stormpath.resources.provider import Provider
from .helpers import StormpathTestCase
from os import environ
from mock import patch
import json


class TestUser(StormpathTestCase):
    """Our User test suite."""

    def test_subclass(self):
        # Ensure that our lazy construction of the subclass works as
        # expected for users (a `User` should be a valid Stormpath
        # `Account`.
        self.assertTrue(self.user.writable_attrs)
        self.assertIsInstance(self.user, Account)
        self.assertIsInstance(self.user, User)

    def test_repr(self):
        # Ensure `username` is shown in the output if specified.
        self.assertTrue(self.user.username in self.user.__repr__())

        # Ensure Stormpath `href` is shown in the output.
        self.assertTrue(self.user.href in self.user.__repr__())

        # Delete this user.
        self.user.delete()

        with self.app.app_context():
            self.user = User.create(
                given_name='Randall',
                surname='Degges',
                email='r@rdegges.com',
                password='woot1LoveCookies!',
            )

        # Ensure `email` is shown in the output if no `username` is
        # specified.
        self.assertTrue(self.user.email in self.user.__repr__())

    def test_get_id(self):
        self.assertEqual(self.user.get_id(), self.user.href)

    def test_is_active(self):
        # Ensure users are active by default.
        self.assertEqual(self.user.is_active(), True)

        # Ensure users who have their accounts explicitly disabled actually
        # return a proper status when `is_active` is called.
        self.user.status = User.STATUS_DISABLED
        self.assertEqual(self.user.is_active(), False)

        # Ensure users who have not verified their accounts return a proper
        # status when `is_active` is called.
        self.user.status = User.STATUS_UNVERIFIED
        self.assertEqual(self.user.is_active(), False)

    def test_is_anonymous(self):
        # There is no way we can be anonymous, as Stormpath doesn't support
        # anonymous users (that is a job better suited for a cache or
        # something).
        self.assertEqual(self.user.is_anonymous(), False)

    def test_is_authenticated(self):
        # This should always return true.  If a user account can be
        # fetched, that means it must be authenticated.
        self.assertEqual(self.user.is_authenticated(), True)

    def test_create(self):

        # Ensure all requied fields are properly set.
        self.assertEqual(self.user.email, 'r@rdegges.com')
        self.assertEqual(self.user.given_name, 'Randall')
        self.assertEqual(self.user.surname, 'Degges')
        self.assertEqual(self.user.username, 'rdegges')
        self.assertEqual(self.user.middle_name, None)
        self.assertEqual(
            dict(self.user.custom_data),
            {
                'created_at': self.user.custom_data.created_at,
                'modified_at': self.user.custom_data.modified_at,
            })

        # Delete this user.
        self.user.delete()

        # Ensure all optional parameters are properly set.
        with self.app.app_context():
            user = User.create(
                email='r@rdegges.com',
                password='woot1LoveCookies!',
                given_name='Randall',
                surname='Degges',
                username='rdegges',
                middle_name='Clark',
                custom_data={
                    'favorite_shows': ['Code Monkeys', 'The IT Crowd'],
                    'friends': ['Sami', 'Alven'],
                    'favorite_place': {
                        'city': 'Santa Cruz',
                        'state': 'California',
                        'reason': 'Beautiful landscape.',
                        'amount_of_likage': 99.9999,
                    },
                },
            )
            self.assertEqual(user.username, 'rdegges')
            self.assertEqual(user.middle_name, 'Clark')
            self.assertEqual(dict(user.custom_data), {
                'favorite_shows': ['Code Monkeys', 'The IT Crowd'],
                'friends': ['Sami', 'Alven'],
                'favorite_place': {
                    'city': 'Santa Cruz',
                    'state': 'California',
                    'reason': 'Beautiful landscape.',
                    'amount_of_likage': 99.9999,
                },
                'created_at': user.custom_data.created_at,
                'modified_at': user.custom_data.modified_at,
            })

    def test_save(self):
        # Ensure that save will save the new instance.
        self.assertEqual(self.user.username, 'rdegges')
        self.user.username = 'something else'
        self.user.save()
        self.assertEqual(self.user.username, 'something else')

        # Ensure that save will return a user instance. (Signal sent during
        # save is tested in test_signals.py)
        self.assertTrue(isinstance(self.user.save(), User))

    def test_from_login(self):
        with self.app.app_context():
            # Create a user (we need a new user instance, one with a specific
            # username).
            user = User.create(
                username='rdegges2',
                email='r2@rdegges.com',
                password='woot1LoveCookies2!',
                given_name='Randall2',
                surname='Degges2')

            # Get user href
            original_href = user.href

            # Now we'll try to retrieve that user by specifing the user's
            # `email` and `password`.
            user = User.from_login(
                'r2@rdegges.com',
                'woot1LoveCookies2!',
            )
            self.assertEqual(user.href, original_href)
            # Now we'll try to retrieve that user by specifying the user's
            # `username` and `password`.
            user = User.from_login(
                'rdegges2',
                'woot1LoveCookies2!',
            )
            self.assertEqual(user.href, original_href)

    def test_to_json(self):
        # Ensure that to_json method returns user json representation.
        self.assertTrue(isinstance(self.user.to_json(), str))
        json_data = json.loads(self.user.to_json())
        expected_json_data = {'account': {
            'href': self.user.href,
            'modified_at': self.user.modified_at.isoformat(),
            'created_at': self.user.created_at.isoformat(),
            'status': 'ENABLED',
            'username': 'rdegges',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'full_name': 'Randall Degges'
        }}
        self.assertEqual(json_data, expected_json_data)


class SocialMethodsTestMixin(object):
    """Our mixin for testing User social methods."""

    def __init__(self, social_name, *args, **kwargs):
        # Validate social_name
        if social_name == 'facebook' or social_name == 'google':
            self.social_name = social_name
        else:
            raise ValueError('Wrong social name.')

        # Set our error message
        self.error_message = (
            'Stormpath was not able to complete the request to ' +
            '{0}: this can be caused by either a bad {0} ' +
            'Directory configuration, or the provided Account ' +
            'credentials are not valid').format(self.social_name.title())

    @property
    def social_dir_name(self):
        # Get directory name
        with self.app.app_context():
            return (
                self.app.stormpath_manager.application.name + '-' +
                self.social_name)

    @property
    def search_query(self):
        return self.app.stormpath_manager.client.tenant.directories.query(
            name=self.social_dir_name)

    def user_from_social(self, access_token):
        return getattr(
                User, 'from_%s' % self.social_name)(access_token)

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_social_supported_service(self, user_mock):
        # Ensure that the proper social_name will continue processing the
        # social login.
        with self.app.app_context():
            self.assertTrue(
                isinstance(self.user.from_social(
                    self.social_name,
                    'mocked access token', self.provider), User))

            # Ensure that the wrong social name will raise an error.
            with self.assertRaises(ValueError) as error:
                self.user.from_social(
                    'foobar', 'mocked access token', self.provider)

            self.assertEqual(
                error.exception.message, 'Social service is not supported.')

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_social_valid(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for social login.
        user_mock.return_value = self.user

        # Ensure that from_<social> will return a User instance if access token
        # is valid.
        with self.app.app_context() and self.app.test_request_context(
                ':%s' % environ.get('PORT')):
            user = self.user_from_social('mocked access token')
            self.assertTrue(isinstance(user, User))

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_social_create_directory(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for social login.
        user_mock.return_value = self.user
        user_mock.side_effect = StormpathError(
            {'developerMessage': 'Mocked message.'})

        # Ensure that from_<social> will create a directory if the
        # access token is valid but a directory doesn't exist.
        with self.app.app_context():
            # Ensure that a social directory is not present.
            if self.search_query.items:
                self.search_query.items[0].delete()

            # We have to catch our exception since we're the one raising it
            # with our mocking.
            with self.assertRaises(StormpathError):
                # Create a directory by creating the user for the first time.
                with self.app.test_request_context(
                        ':%s' % environ.get('PORT')):
                    user = self.user_from_social('mocked access token')
                    self.assertTrue(isinstance(user, User))

                # To ensure that this error is caught at the right time
                # however, we will assert the number of mock calls.
                self.assertEqual(user_mock.call_count, 2)

            # Ensure that the social directory is now present.
            self.assertEqual(len(self.search_query.items), 1)
            self.assertEqual(
                self.search_query.items[0].name, self.social_dir_name)

    def test_from_social_invalid_access_token(self):
        # Ensure that from_<social> will raise a StormpathError if access
        # token is invalid.
        with self.app.app_context() and self.app.test_request_context(
                ':%s' % environ.get('PORT')):
            with self.assertRaises(StormpathError) as error:
                self.user_from_social('foobar')

            self.assertTrue(
                self.error_message in error.exception.developer_message[
                    'developerMessage'])

    def test_from_social_invalid_access_token_with_existing_directory(self):
        # First we will create a social directory if one doesn't already
        # exist.
        with self.app.app_context() and self.app.test_request_context(
                ':%s' % environ.get('PORT')):
            if not self.search_query.items:
                social_dir = (
                    self.app.stormpath_manager.client.directories.create({
                        'name': self.social_dir_name,
                        'provider': self.provider
                    })
                )

                # Now we'll map the new directory to our application.
                (
                    self.app.stormpath_manager.application.
                    account_store_mappings.create({
                        'application': self.app.stormpath_manager.application,
                        'account_store': social_dir,
                        'list_index': 99,
                        'is_default_account_store': False,
                        'is_default_group_store': False,
                    })
                )

            # Ensure that from_<social> will raise a StormpathError if access
            # token is invalid and social directory present.
            with self.assertRaises(StormpathError) as error:
                self.user_from_social('foobar')

            self.assertTrue(
                self.error_message in error.exception.developer_message[
                    'developerMessage'])


class TestFacebookLogin(StormpathTestCase, SocialMethodsTestMixin):
    """Our User facebook login test suite."""
    def __init__(self, *args, **kwargs):
        super(TestFacebookLogin, self).__init__(*args, **kwargs)
        SocialMethodsTestMixin.__init__(self, 'facebook')

    def setUp(self):
        super(TestFacebookLogin, self).setUp()

        # Set a provider
        self.provider = {
            'client_id': environ.get('FACEBOOK_APP_ID'),
            'client_secret': environ.get('FACEBOOK_APP_SECRET'),
            'provider_id': Provider.FACEBOOK,
        }


class TestGoogleLogin(StormpathTestCase, SocialMethodsTestMixin):
    """Our User google login test suite."""
    def __init__(self, *args, **kwargs):
        super(TestGoogleLogin, self).__init__(*args, **kwargs)
        SocialMethodsTestMixin.__init__(self, 'google')

    def setUp(self):
        super(TestGoogleLogin, self).setUp()

        with self.app.app_context():
            # Set a provider
            self.provider = {
                'client_id': environ.get('GOOGLE_CLIENT_ID'),
                'client_secret': environ.get('GOOGLE_CLIENT_SECRET'),
                'redirect_uri': (
                    ''.join(
                        (environ.get('ROOT_URL'), ':', environ.get('PORT'))) +
                    self.app.config['STORMPATH_GOOGLE_LOGIN_URL']),
                'provider_id': Provider.GOOGLE,
            }
