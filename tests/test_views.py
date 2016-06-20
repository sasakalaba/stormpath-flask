"""Run tests against our custom views."""


from flask.ext.stormpath.models import User

from .helpers import StormpathTestCase
from flask_stormpath.views import make_stormpath_response, request_wants_json
from flask import session


class AppWrapper(object):
    """
    Helper class for injecting HTTP headers.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ['HTTP_ACCEPT'] = (
            'text/html,application/xhtml+xml,' + 'application/xml;')
        return self.app(environ, start_response)


class StormpathViewTestCase(StormpathTestCase):
    """Base test class for Stormpath views."""
    def setUp(self):
        super(StormpathViewTestCase, self).setUp()

        # Make sure our requests don't trigger a json response.
        self.app.wsgi_app = AppWrapper(self.app.wsgi_app)

        # Create a user.
        with self.app.app_context():
            User.create(
                username='randalldeg',
                given_name='Randall',
                surname='Degges',
                email='r@rdegges.com',
                password='woot1LoveCookies!')


class TestHelperFunctions(StormpathTestCase):
    """Test our helper functions."""
    def test_request_wants_json(self):
        with self.app.test_client() as c:
            # Ensure that request_wants_json returns True if 'text/html'
            # accept header is missing.
            c.get('/')
            self.assertTrue(request_wants_json())

            # Add an 'text/html' accept header
            self.app.wsgi_app = AppWrapper(self.app.wsgi_app)
            c.get('/')
            self.assertFalse(request_wants_json())


class TestRegister(StormpathViewTestCase):
    """Test our registration view."""

    def setUp(self):
        super(TestRegister, self).setUp()
        self.form_fields = self.app.config['stormpath']['web']['register'][
            'form']['fields']

    def test_get(self):
        # Ensure that a get request will only render the template and skip
        # form validation and users creation.
        with self.app.test_client() as c:
            resp = c.get('/register')
            self.assertEqual(resp.status_code, 200)

    def test_default_fields(self):
        # By default, we'll register new users with username, first name,
        # last name, email, and password.
        with self.app.test_client() as c:
            # Ensure that missing fields will cause a failure.
            resp = c.post('/register', data={
                'email': 'r@rdegges2.com',
                'password': 'thisisMy0therpassword...',
            })
            self.assertEqual(resp.status_code, 200)

            # Ensure that valid fields will result in a success.
            resp = c.post('/register', data={
                'username': 'randalldeg_registration',
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...',
            })
            self.assertEqual(resp.status_code, 302)

    def test_confirm_password(self):
        # Register a user with confirmPassword enabled.
        self.form_fields['confirmPassword']['enabled'] = True

        with self.app.test_client() as c:
            # Ensure that confirmPassword will be popped from data before
            # creating the new User instance.
            resp = c.post('/register', data={
                'username': 'randalldeg_registration',
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...',
                'confirm_password': 'thisisMy0therpassword...'
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
                'email': 'r_registration@rdegges.com',
            })
            self.assertEqual(resp.status_code, 200)

            # Ensure that valid fields will result in a success.
            resp = c.post('/register', data={
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...',
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
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...'
            })
            self.assertEqual(resp.status_code, 302)

            # Find our user account that was just created, and ensure the given
            # name and surname fields were set to our default string.
            user = User.from_login(
                'r_registration@rdegges.com', 'thisisMy0therpassword...')
            self.assertEqual(user.given_name, 'Anonymous')
            self.assertEqual(user.surname, 'Anonymous')
            self.assertEqual(user.username, user.email)

    def test_error_messages(self):
        # We don't need a username field for this test. We'll disable it
        # so the form can be valid.
        self.form_fields['username']['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that the form error is raised if the form is invalid.
            resp = c.post('/register', data={
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'hilol',
            })
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'First Name is required.' in resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

            # Ensure that an error is raised if an invalid password is
            # specified.
            resp = c.post('/register', data={
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'hilol',
            })
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Account password minimum length not satisfied.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

            resp = c.post('/register', data={
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'hilolwoot1',
            })
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Password requires at least 1 uppercase character.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

            resp = c.post('/register', data={
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'hilolwoothi',
            })
            self.assertEqual(resp.status_code, 200)

            self.assertTrue(
                'Password requires at least 1 numeric character.' in
                resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

    def test_autologin(self):
        # If the autologin option is enabled the user must be logged in after
        # successful registration.
        self.app.config['stormpath']['web']['register']['autoLogin'] = True
        stormpath_register_redirect_url = '/redirect_for_registration'
        (self.app.config['stormpath']['web']['register']
            ['nextUri']) = stormpath_register_redirect_url

        with self.app.test_client() as c:
            resp = c.get('/register')
            self.assertFalse('user_id' in session)

            # Check that the user was redirected to the proper url and is
            # logged in after successful registration
            resp = c.post('/register', data={
                'username': 'randalldeg_registration',
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...',
            })

            # Get our user that was just created
            user = User.from_login(
                'r_registration@rdegges.com', 'thisisMy0therpassword...')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(stormpath_register_redirect_url in resp.location)
            self.assertEqual(session['user_id'], user.href)

            resp = c.get('/logout')
            self.assertFalse('user_id' in session)

    def test_redirect_to_login_or_register_url(self):
        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        stormpath_register_redirect_url = '/redirect_for_registration'
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_login_redirect_url
        (self.app.config['stormpath']['web']['register']
            ['nextUri']) = stormpath_register_redirect_url

        # We don't need a username field for this test. We'll disable it
        # so the form can be valid.
        self.form_fields['username']['enabled'] = False

        with self.app.test_client() as c:
            # Ensure that valid registration will redirect to
            # register redirect url
            resp = c.post('/register', data={
                'given_name': 'Randall registration',
                'middle_name': 'Clark registration',
                'surname': 'Degges registration',
                'email': 'r_registration@rdegges.com',
                'password': 'thisisMy0therpassword...',
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_register_redirect_url in location)
            self.assertFalse(stormpath_login_redirect_url in location)

            # We're disabling the default register redirect so we can check if
            # the login redirect will be applied
            self.app.config['stormpath']['web']['register']['nextUri'] = None

            # Ensure that valid registration will redirect to
            # login redirect url
            resp = c.post('/register', data={
                'given_name': 'Randall_registration2',
                'middle_name': 'Clark_registration2',
                'surname': 'Degges_registration2',
                'email': 'r_registration2@rdegges.com',
                'password': 'thisisMy0therpassword2...',
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_login_redirect_url in location)
            self.assertFalse(stormpath_register_redirect_url in location)

            # We're disabling the default login redirect so we can check if
            # the default redirect will be applied
            self.app.config['stormpath']['web']['login']['nextUri'] = None

            # Ensure that valid registration will redirect to
            # default redirect url
            resp = c.post('/register', data={
                'given_name': 'Randall_registration3',
                'middle_name': 'Clark_registration3',
                'surname': 'Degges_registration3',
                'email': 'r_registration3@rdegges.com',
                'password': 'thisisMy0therpassword3...',
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertFalse(stormpath_login_redirect_url in location)
            self.assertFalse(stormpath_register_redirect_url in location)


class TestLogin(StormpathViewTestCase):
    """Test our login view."""

    def setUp(self):
        super(TestLogin, self).setUp()
        self.form_fields = self.app.config['stormpath']['web']['login'][
            'form']['fields']

    def test_email_login(self):
        # Attempt a login using email and password.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_username_login(self):
        # Attempt a login using username and password.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'randalldeg',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_error_messages(self):
        # Ensure that an error is raised if an invalid username or password is
        # specified.
        with self.app.test_client() as c:
            resp = c.post('/login', data={
                'login': 'randalldeg',
                'password': 'hilol',
            })
            self.assertEqual(resp.status_code, 200)

            self.assertTrue(
                'Invalid username or password.' in resp.data.decode('utf-8'))
            self.assertFalse("developerMessage" in resp.data.decode('utf-8'))

    def test_redirect_to_login_or_register_url(self):
        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        stormpath_register_redirect_url = '/redirect_for_registration'
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_login_redirect_url
        (self.app.config['stormpath']['web']['register']
            ['nextUri']) = stormpath_register_redirect_url

        with self.app.test_client() as c:
            # Attempt a login using username and password.
            resp = c.post('/login', data={
                'login': 'randalldeg',
                'password': 'woot1LoveCookies!'
            })

            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_login_redirect_url in location)
            self.assertFalse(stormpath_register_redirect_url in location)


class TestLogout(StormpathViewTestCase):
    """Test our logout view."""

    def test_logout_works_with_anonymous_users(self):
        with self.app.test_client() as c:
            resp = c.get('/logout')
            self.assertEqual(resp.status_code, 302)

    def test_logout_works(self):
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


class TestForgot(StormpathViewTestCase):
    """Test our forgot view."""

    def test_proper_template_rendering(self):
        # Ensure that proper templates are rendered based on the request
        # method.
        with self.app.test_client() as c:
            # Ensure request.GET will render the forgot.html template.
            resp = c.get('/forgot')
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Enter your email address below to reset your password.' in
                resp.data.decode('utf-8'))

            # Ensure that request.POST will render the forgot_email_sent.html
            resp = c.post('/forgot', data={'email': 'r@rdegges.com'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Your password reset email has been sent!' in
                resp.data.decode('utf-8'))

    def test_error_messages(self):
        with self.app.test_client() as c:
            # Ensure than en email wasn't sent if an invalid email format was
            # entered.
            resp = c.post('/forgot', data={'email': 'rdegges'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Invalid email address.' in resp.data.decode('utf-8'))

            # Ensure than en email wasn't sent if an email that doesn't exist
            # in our database was entered.
            resp = c.post('/forgot', data={'email': 'idonot@exist.com'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Invalid email address.' in resp.data.decode('utf-8'))

            # Ensure that an email was sent if a valid email was entered.
            resp = c.post('/forgot', data={'email': 'r@rdegges.com'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Your password reset email has been sent!' in
                resp.data.decode('utf-8'))
