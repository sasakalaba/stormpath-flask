"""Tests for our data models."""


from flask_stormpath.models import User
from stormpath.resources.account import Account
from .helpers import StormpathTestCase
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
        self.assertTrue(isinstance(self.user.to_json(), str))
        json_data = json.loads(self.user.to_json())
        expected_json_data = {'account': {
            'username': self.user.username,
            'email': self.user.email,
            'given_name': self.user.given_name,
            'middle_name': self.user.middle_name,
            'surname': self.user.surname,
            'status': self.user.status}}
        self.assertEqual(json_data, expected_json_data)
