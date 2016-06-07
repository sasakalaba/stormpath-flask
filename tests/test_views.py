"""Run tests against our custom views."""


from flask.ext.stormpath.models import User

from .helpers import StormpathTestCase
from flask_stormpath.forms import RegistrationForm
from stormpath.resources import Resource
from unittest import skip


class AppWrapper(object):
    """
    Helper class for injecting HTTP headers.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ['HTTP_ACCEPT'] = ('text/html,application/xhtml+xml,' +
            'application/xml;')
        return self.app(environ, start_response)


class TestRegister(StormpathTestCase):
    """Test our registration view."""

    def setUp(self):
        super(TestRegister, self).setUp()
        self.app.wsgi_app = AppWrapper(self.app.wsgi_app)
        self.form_fields = (self.app.config['stormpath']['web']['register']
            ['form']['fields'])

    def test_default_fields(self):
        # By default, we'll register new users with username, first name,
        # last name, email, and password.
        with self.app.test_client() as c:
            # Ensure that missing fields will cause a failure.
            resp = c.post('/register', data={
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 200)

            # Ensure that valid fields will result in a success.
            resp = c.post('/register', data={
                'username': 'randalldeg',
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_disable_all_except_mandatory(self):
        # Here we'll disable all the fields except for the mandatory fields:
        # email and password.
        for field in ['givenName', 'middleName', 'surname', 'username']:
            self.form_fields[field]['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that missing fields will cause a failure.
            resp = c.post('/register', data={
                'email': 'r@rdegges.com',
            })
            self.assertEqual(resp.status_code, 200)

            # Ensure that valid fields will result in a success.
            resp = c.post('/register', data={
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_require_settings(self):
        # Here we'll change our backend behavior such that users *can* enter a
        # username, first and last name, but they aren't required server side.
        for field in ['givenName', 'surname', 'username']:
            self.form_fields[field]['required'] = False

        with self.app.test_client() as c:
            # Ensure that registration works *without* given name and surname
            # since they aren't required.
            resp = c.post('/register', data={
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!'
            })
            self.assertEqual(resp.status_code, 302)

            # Find our user account that was just created, and ensure the given
            # name and surname fields were set to our default string.
            user = User.from_login('r@rdegges.com', 'woot1LoveCookies!')
            self.assertEqual(user.given_name, 'Anonymous')
            self.assertEqual(user.surname, 'Anonymous')
            self.assertEqual(user.username, user.email)

    def test_error_messages(self):

        # We don't need a username field for this test. We'll disable it
        # so the form can be valid.
        self.form_fields['username']['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that an error is raised if an invalid password is
            # specified.
            resp = c.post('/register', data={
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'hilol',
            })
            self.assertEqual(resp.status_code, 200)

            self.assertTrue(
                'Account password minimum length not satisfied.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

            resp = c.post('/register', data={
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'hilolwoot1',
            })
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Password requires at least 1 uppercase character.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

            resp = c.post('/register', data={
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'hilolwoothi',
            })
            self.assertEqual(resp.status_code, 200)

            self.assertTrue(
                'Password requires at least 1 numeric character.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

    def test_redirect_to_login_and_register_url(self):
        # Setting redirect URL to something that is easy to check
        stormpath_redirect_url = '/redirect_for_login_and_registration'
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_redirect_url

        # We're disabling the default register redirect so we can check if
        # the login redirect will be applied
        self.app.config['stormpath']['web']['register']['nextUri'] = None

        # We don't need a username field for this test. We'll disable it
        # so the form can be valid.
        self.form_fields['username']['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that valid registration will redirect to
            # STORMPATH_REDIRECT_URL
            resp = c.post('/register', data={
                'given_name': 'Randall',
                'middle_name': 'Clark',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_redirect_url in location)

    def test_redirect_to_register_url(self):
        # Setting redirect URLs to something that is easy to check
        stormpath_redirect_url = '/redirect_for_login'
        stormpath_registration_redirect_url = '/redirect_for_registration'
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_redirect_url
        (self.app.config['stormpath']['web']['register']
            ['nextUri']) = stormpath_registration_redirect_url

        # We don't need a username field for this test. We'll disable it
        # so the form can be valid.
        self.form_fields['username']['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that valid registration will redirect to
            # ['stormpath']['web']['register']['nextUri'] if it exists
            resp = c.post('/register', data={
                'given_name': 'Randall',
                'middle_name': 'Clark',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertFalse(stormpath_redirect_url in location)
            self.assertTrue(stormpath_registration_redirect_url in location)

    def tearDown(self):
        """Remove every attribute added by StormpathForm, so as not to cause
        invalid form on consecutive tests."""
        form_config = (self.app.config['stormpath']['web']['register']
            ['form'])
        field_order = form_config['fieldOrder']
        field_list = form_config['fields']

        for field in field_order:
            if field_list[field]['enabled']:
                delattr(RegistrationForm, Resource.from_camel_case(field))
        super(TestRegister, self).tearDown()


@skip('StormpathForm.data (returns empty {}) ::AttributeError::')
class TestLogin(StormpathTestCase):
    """Test our login view."""

    def test_email_login(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        # Attempt a login using email and password.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_username_login(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                username = 'rdegges',
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        # Attempt a login using username and password.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'rdegges',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_error_messages(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                username = 'rdegges',
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        # Ensure that an error is raised if an invalid username or password is
        # specified.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'rdegges',
                'password': 'hilol',
            })
            self.assertEqual(resp.status_code, 200)

            self.assertTrue(
                'Invalid username or password.' in resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

    def test_redirect_to_login_and_register_url(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                username = 'rdegges',
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        # Setting redirect URL to something that is easy to check
        stormpath_redirect_url = '/redirect_for_login_and_registration'
        self.app.config['STORMPATH_REDIRECT_URL'] = stormpath_redirect_url

        with self.app.test_client() as c:
            # Attempt a login using username and password.
            resp = c.post(
                '/login',
                data={'login': 'rdegges', 'password': 'woot1LoveCookies!',})

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_redirect_url in location)

    def test_redirect_to_register_url(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                username = 'rdegges',
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        # Setting redirect URLs to something that is easy to check
        stormpath_redirect_url = '/redirect_for_login'
        stormpath_registration_redirect_url = '/redirect_for_registration'
        self.app.config['STORMPATH_REDIRECT_URL'] = stormpath_redirect_url
        self.app.config['STORMPATH_REGISTRATION_REDIRECT_URL'] = \
            stormpath_registration_redirect_url

        with self.app.test_client() as c:
            # Attempt a login using username and password.
            resp = c.post(
                '/login',
                data={'login': 'rdegges', 'password': 'woot1LoveCookies!',})

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue('redirect_for_login' in location)
            self.assertFalse('redirect_for_registration' in location)


@skip('StormpathForm.data (returns empty {}) ::AttributeError::')
class TestLogout(StormpathTestCase):
    """Test our logout view."""

    def test_logout_works_with_anonymous_users(self):
        with self.app.test_client() as c:
            resp = c.get('/logout')
            self.assertEqual(resp.status_code, 302)

    def test_logout_works(self):
        # Create a user.
        with self.app.app_context():
            User.create(
                given_name = 'Randall',
                surname = 'Degges',
                email = 'r@rdegges.com',
                password = 'woot1LoveCookies!',
            )

        with self.app.test_client() as c:
            # Log this user in.
            resp = c.post('/login', data={
                'login': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

            # Log this user out.
            resp = c.get('/logout')
            self.assertEqual(resp.status_code, 302)
