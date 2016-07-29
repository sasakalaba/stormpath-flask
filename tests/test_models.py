"""Tests for our data models."""


from flask_stormpath.models import User
from flask_stormpath import StormpathError
from flask import request
from stormpath.resources.account import Account
from stormpath.resources.provider import Provider
from .helpers import StormpathTestCase
from os import environ
from mock import patch
import json


class TestUser(StormpathTestCase):
    """Our User test suite."""
    def setUp(self):
        super(TestUser, self).setUp()

        # Create a user.
        with self.app.app_context():
            self.user = User.create(
                email='r@rdegges.com',
                password='woot1LoveCookies!',
                given_name='Randall',
                surname='Degges')

    def test_subclass(self):
        # Ensure that our lazy construction of the subclass works as
        # expected for users (a `User` should be a valid Stormpath
        # `Account`.
        self.assertTrue(self.user.writable_attrs)
        self.assertIsInstance(self.user, Account)
        self.assertIsInstance(self.user, User)

    def test_repr(self):
        # Ensure `email` is shown in the output if no `username` is
        # specified.
        self.assertTrue(self.user.email in self.user.__repr__())

        # Delete this user.
        self.user.delete()

        # Ensure `username` is shown in the output if specified.
        with self.app.app_context():
            user = User.create(
                username='omgrandall',
                email='r@rdegges.com',
                password='woot1LoveCookies!',
                given_name='Randall',
                surname='Degges',
            )
            self.assertTrue(user.username in user.__repr__())

            # Ensure Stormpath `href` is shown in the output.
            self.assertTrue(user.href in user.__repr__())

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
        self.assertEqual(self.user.username, 'r@rdegges.com')
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
        self.fail('Implementation reminder.')

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
            'username': 'r@rdegges.com',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'full_name': 'Randall Degges'
        }}
        self.assertEqual(json_data, expected_json_data)

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_facebook_valid(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for facebook login.
        user_mock.return_value = self.user

        # Ensure that from_facebook will return a User instance if access token
        # is valid.
        with self.app.app_context():
            user = User.from_facebook('mocked access token')
            self.assertTrue(isinstance(user, User))

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_facebook_create_facebook_directory(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for facebook login.
        user_mock.return_value = self.user
        user_mock.side_effect = StormpathError(
            {'developerMessage': 'Mocked message.'})

        # Ensure that from_facebook will create a Facebook directory if the
        # access token is valid but a directory doesn't exist.
        with self.app.app_context():
            # Ensure that a Facebook directory is not present.
            facebook_dir_name = (
                self.app.stormpath_manager.application.name + '-facebook')
            search_query = (
                self.app.stormpath_manager.client.tenant.directories.
                query(name=facebook_dir_name))
            if search_query.items:
                search_query.items[0].delete()

            # We have to catch our exception since we're the one raising it
            # with our mocking.
            with self.assertRaises(StormpathError):
                # Create a directory by creating the user for the first time.
                with self.app.test_request_context(
                        ':%s' % environ.get('PORT')):
                    user = User.from_facebook('mocked access token')
                    self.assertTrue(isinstance(user, User))

                # To ensure that this error is caught at the right time
                # however, we will assert the number of mock calls.
                self.assertEqual(user_mock.call_count, 2)

            # Ensure that the Facebook directory is now present.
            search_query = (
                self.app.stormpath_manager.client.tenant.directories.
                query(name=facebook_dir_name))
            self.assertEqual(len(search_query.items), 1)
            self.assertEqual(search_query.items[0].name, facebook_dir_name)

    def test_from_facebook_invalid_access_token(self):
        # Ensure that from_facebook will raise a StormpathError if access
        # token is invalid.
        with self.app.app_context():
            with self.assertRaises(StormpathError) as error:
                User.from_facebook('foobar')

            self.assertTrue((
                'Stormpath was not able to complete the request to ' +
                'Facebook: this can be caused by either a bad Facebook ' +
                'Directory configuration, or the provided Account ' +
                'credentials are not valid') in (
                    error.exception.developer_message['developerMessage']))

    def test_from_facebook_invalid_access_token_with_existing_directory(self):
        # First we will create a Facebook directory if one doesn't already
        # exist.
        facebook_dir_name = (
            self.app.stormpath_manager.application.name + '-facebook')
        search_query = (
            self.app.stormpath_manager.client.tenant.directories.
            query(name=facebook_dir_name))

        with self.app.app_context():
            if not search_query.items:
                self.app.stormpath_manager.client.directories.create({
                    'name': facebook_dir_name,
                    'provider': {
                        'client_id': environ.get('FACEBOOK_APP_ID'),
                        'client_secret': environ.get('FACEBOOK_APP_SECRET'),
                        'provider_id': Provider.FACEBOOK,
                    }
                })

            # Ensure that from_facebook will raise a StormpathError if access
            # token is invalid and Facebook directory present.
            with self.assertRaises(StormpathError) as error:
                User.from_facebook('foobar')

            self.assertEqual(
                'A Directory named \'%s\' already exists.' % facebook_dir_name,
                error.exception.developer_message['developerMessage'])

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_google_valid(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for google login.
        user_mock.return_value = self.user

        # Ensure that from_google will return a User instance if access token
        # is valid.
        with self.app.app_context():
            user = User.from_google('mocked access token')
            self.assertTrue(isinstance(user, User))

    @patch('stormpath.resources.application.Application.get_provider_account')
    def test_from_google_create_google_directory(self, user_mock):
        # We'll mock the social account getter since we cannot replicate the
        # access token needed for google login.
        user_mock.return_value = self.user
        user_mock.side_effect = StormpathError(
            {'developerMessage': 'Mocked message.'})

        # Ensure that from_google will create a Google directory if the
        # access token is valid but a directory doesn't exist.
        with self.app.app_context():
            # Ensure that a Google directory is not present.
            google_dir_name = (
                self.app.stormpath_manager.application.name + '-google')
            search_query = (
                self.app.stormpath_manager.client.tenant.directories.
                query(name=google_dir_name))
            if search_query.items:
                search_query.items[0].delete()

            # We have to catch our exception since we're the one raising it
            # with our mocking.
            with self.assertRaises(StormpathError):
                # Create a directory by creating the user for the first time.
                with self.app.test_request_context(
                        ':%s' % environ.get('PORT')):
                    user = User.from_google('mocked access token')
                    self.assertTrue(isinstance(user, User))

                # To ensure that this error is caught at the right time
                # however, we will assert the number of mock calls.
                self.assertEqual(user_mock.call_count, 2)

            # Ensure that the Google directory is now present.
            search_query = (
                self.app.stormpath_manager.client.tenant.directories.
                query(name=google_dir_name))
            self.assertEqual(len(search_query.items), 1)
            self.assertEqual(search_query.items[0].name, google_dir_name)

    def test_from_google_invalid_access_token(self):
        # Ensure that from_google will raise a StormpathError if access
        # token is invalid.
        with self.app.app_context() and self.app.test_request_context(
                ':%s' % environ.get('PORT')):
            with self.assertRaises(StormpathError) as error:
                User.from_google('foobar')

            self.assertTrue((
                'Stormpath was not able to complete the request to ' +
                'Google: this can be caused by either a bad ' +
                'Google Directory configuration, or the provided ' +
                'Account credentials are not valid') in (
                    error.exception.developer_message['developerMessage']))

    def test_from_google_invalid_access_token_with_existing_directory(self):
        # First we will create a Google directory if one doesn't already exist.
        google_dir_name = (
            self.app.stormpath_manager.application.name + '-google')
        search_query = (
            self.app.stormpath_manager.client.tenant.directories.
            query(name=google_dir_name))

        with self.app.app_context() and self.app.test_request_context(
                ':%s' % environ.get('PORT')):
            if not search_query.items:
                self.app.stormpath_manager.client.directories.create({
                    'name': google_dir_name,
                    'provider': {
                        'client_id': environ.get('GOOGLE_CLIENT_ID'),
                        'client_secret': environ.get('GOOGLE_CLIENT_SECRET'),
                        'redirect_uri': (
                            request.url_root[:-1] + self.app.config[
                                'STORMPATH_GOOGLE_LOGIN_URL']),
                        'provider_id': Provider.GOOGLE,
                    }
                })

            # Ensure that from_google will raise a StormpathError if access
            # token is invalid and Google directory present.
            with self.assertRaises(StormpathError) as error:
                User.from_google('foobar')

            self.assertEqual(
                'A Directory named \'%s\' already exists.' % google_dir_name,
                error.exception.developer_message['developerMessage'])
