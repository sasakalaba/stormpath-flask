"""Run tests against our custom views."""


from flask.ext.stormpath.models import User
from .helpers import StormpathTestCase, HttpAcceptWrapper
from stormpath.resources import Resource
from flask_stormpath.views import make_stormpath_response, request_wants_json
from flask import session
from flask.ext.login import current_user
import json


class StormpathViewTestCase(StormpathTestCase):
    """Base test class for Stormpath views."""
    def setUp(self):
        super(StormpathViewTestCase, self).setUp()

        # html and json header settings
        self.html_header = 'text/html,application/xhtml+xml,application/xml;'
        self.json_header = 'application/json'

        # Remember default wsgi_app instance for dynamically changing request
        # type later in tests.
        self.default_wsgi_app = self.app.wsgi_app

        # Make sure our requests don't trigger a json response.
        self.app.wsgi_app = HttpAcceptWrapper(
            self.default_wsgi_app, self.html_header)

        # Create a user.
        with self.app.app_context():
            User.create(
                username='randalldeg',
                given_name='Randall',
                surname='Degges',
                email='r@rdegges.com',
                password='woot1LoveCookies!')

    def check_header(self, st, headers):
        return any(st in header for header in headers)

    def assertJsonResponse(
            self, method, view, status_code, expected_response, **kwargs):
        """Custom assert for testing json responses on flask_stormpath
           views."""

        # Set our request type to json.
        self.app.wsgi_app = HttpAcceptWrapper(
            self.default_wsgi_app, self.json_header)

        with self.app.test_client() as c:
            # Create a request.
            allowed_methods = {
                'get': c.get,
                'post': c.post}

            if method in allowed_methods:
                resp = allowed_methods[method]('/%s' % view, **kwargs)
            else:
                raise ValueError('\'%s\' is not a supported method.' % method)

            # Ensure that the HTTP status code is correct.
            self.assertEqual(resp.status_code, status_code)

            # Check that response is json.
            self.assertFalse(self.check_header('text/html', resp.headers[0]))
            self.assertTrue(self.check_header(
                'application/json', resp.headers[0]))

            # Check that response data is correct.
            if method == 'get':
                # If method is get, ensure that response data is the json
                # representation of form field settings.

                # Build form fields from the response and compare them to form
                # fields specified in the config file.
                resp_data = json.loads(resp.data)
                form_fields = {}
                for field in resp_data:
                    field['enabled'] = True
                    form_fields[Resource.to_camel_case(
                        field.pop('name'))] = field

                # Remove disabled fields
                for key in self.form_fields.keys():
                    if not self.form_fields[key]['enabled']:
                        self.form_fields.pop(key)

                # Ensure that form field specifications from json response are
                # the same as in the config file.
                self.assertEqual(self.form_fields, form_fields)

            else:
                # If method is post, ensure that either account info or
                # stormpath error is returned.
                self.assertTrue('data' in kwargs.keys())

            # Ensure that response data is the same as the expected data.
            self.assertEqual(resp.data, expected_response)


class TestHelperFunctions(StormpathViewTestCase):
    """Test our helper functions."""
    def test_request_wants_json(self):
        with self.app.test_client() as c:
            # Ensure that request_wants_json returns False if 'text/html'
            # accept header is present.
            c.get('/')
            self.assertFalse(request_wants_json())

            # Add an 'text/html' accept header
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)

            # Ensure that request_wants_json returns True if 'text/html'
            # accept header is missing.
            c.get('/')
            self.assertTrue(request_wants_json())

    def test_make_stormpath_response(self):
        data = {'foo': 'bar'}
        with self.app.test_client() as c:
            # Ensure that stormpath_response is json if request wants json.
            c.get('/')
            resp = make_stormpath_response(json.dumps(data))
            self.assertFalse(self.check_header(
                'text/html', resp.headers[0]))
            self.assertTrue(self.check_header(
                'application/json', resp.headers[0]))
            self.assertEqual(resp.data, '{"foo": "bar"}')

            # Ensure that stormpath_response is html if request wants html.
            c.get('/')
            resp = make_stormpath_response(
                data, template='flask_stormpath/base.html', return_json=False)
            self.assertTrue(isinstance(resp, unicode))


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

    def test_json_response_get(self):
        # Here we'll disable all the fields except for the mandatory fields:
        # email and password.
        for field in ['givenName', 'middleName', 'surname', 'username']:
            self.form_fields[field]['enabled'] = False

        # Specify expected response.
        expected_response = [
            {'label': 'Email',
             'name': 'email',
             'placeholder': 'Email',
             'required': True,
             'type': 'email'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'type': 'password'}]

        self.assertJsonResponse(
            'get', 'register', 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify user data
        user_data = {
            'username': 'rdegges2',
            'email': 'r@rdegges2.com',
            'given_name': 'Randall2',
            'middle_name': None,
            'surname': 'Degges2',
            'password': 'woot1LoveCookies!2'
        }

        # Specify expected response.
        expected_response = {'account': user_data.copy()}
        expected_response['account']['status'] = 'ENABLED'
        expected_response['account'].pop('password')

        # Specify post data
        json_data = json.dumps(user_data)
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'register', 200, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_stormpath_error(self):
        # Specify post data
        json_data = json.dumps({
            'username': 'rdegges',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': 'Clark',
            'surname': 'Degges',
            'password': 'woot1LoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': (
                'Account with that email already exists.' +
                '  Please choose another email.'),
            'error': 409}
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'register', 409, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_form_error(self):
        # Specify post data
        json_data = json.dumps({
            'username': 'rdegges',
            'email': 'r@rdegges.com',
            'middle_name': 'Clark',
            'surname': 'Degges',
            'password': 'woot1LoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': {"given_name": ["First Name is required."]},
            'status': 400}

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'register', 400, json.dumps(expected_response),
            **request_kwargs)


class TestLogin(StormpathViewTestCase):
    """Test our login view."""

    def setUp(self):
        super(TestLogin, self).setUp()
        # We need to set form fields to test out json stuff in the
        # assertJsonResponse method.
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

    def test_json_response_get(self):
        # Specify expected response.
        expected_response = [
            {'label': 'Username or Email',
             'name': 'login',
             'placeholder': 'Username or Email',
             'required': True,
             'type': 'text'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'type': 'password'}]

        self.assertJsonResponse(
            'get', 'login', 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify expected response.
        expected_response = {'account': {
            'username': 'randalldeg',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'status': 'ENABLED'}
        }

        # Specify post data
        json_data = json.dumps({
            'login': 'r@rdegges.com',
            'password': 'woot1LoveCookies!'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', 'login', 200, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_stormpath_error(self):
        # Specify post data
        json_data = json.dumps({
            'login': 'wrong@email.com',
            'password': 'woot1LoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': 'Invalid username or password.',
            'error': 400}
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', 'login', 400, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_form_error(self):
        # Specify post data
        json_data = json.dumps({
            'password': 'woot1LoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': {"login": ["Username or Email is required."]},
            'status': 400}

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'login', 400, json.dumps(expected_response),
            **request_kwargs)


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

    def setUp(self):
        super(TestForgot, self).setUp()
        # We need to set form fields to test out json stuff in the
        # assertJsonResponse method.
        self.form_fields = self.app.config['stormpath']['web'][
            'forgotPassword']['form']['fields']

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
                'Email must be in valid format.' in resp.data.decode('utf-8'))

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

    def test_json_response_get(self):
        # Specify expected response.
        expected_response = [
            {'label': 'Email',
             'name': 'email',
             'placeholder': 'Email',
             'required': True,
             'type': 'email'}]

        self.assertJsonResponse(
            'get', 'forgot', 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify expected response.
        expected_response = {
            'status': 200,
            'message': {"email": "r@rdegges.com"}
        }

        # Specify post data
        json_data = json.dumps({'email': 'r@rdegges.com'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', 'forgot', 200, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_stormpath_error(self):
        # Specify post data
        json_data = json.dumps({'email': 'wrong@email.com'})

        # Specify expected response
        expected_response = {
            'message': 'Invalid email address.',
            'status': 400}
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', 'forgot', 400, json.dumps(expected_response),
            **request_kwargs)

    def test_json_response_form_error(self):
        # Specify post data
        json_data = json.dumps({'email': 'rdegges'})

        # Specify expected response
        expected_response = {
            'message': {"email": ["Email must be in valid format."]},
            'status': 400}

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'forgot', 400, json.dumps(expected_response),
            **request_kwargs)


class TestChange(StormpathViewTestCase):
    """Test our change view."""

    def setUp(self):
        super(TestChange, self).setUp()
        # We need to set form fields to test out json stuff in the
        # assertJsonResponse method.
        self.form_fields = self.app.config['stormpath']['web'][
            'changePassword']['form']['fields']

        # Generate a token
        self.token = self.application.password_reset_tokens.create(
            {'email': 'r@rdegges.com'}).token
        self.reset_password_url = ''.join(['change?sptoken=', self.token])

    def test_proper_template_rendering(self):
        # Ensure that proper templates are rendered based on the request
        # method.
        with self.app.test_client() as c:
            # Ensure request.GET will render the forgot_change.html template.
            resp = c.get(self.reset_password_url)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Enter your new account password below.' in
                resp.data.decode('utf-8'))

            # Ensure that request.POST will render the forgot_complete.html
            resp = c.post(self.reset_password_url, data={
                'password': 'woot1DontLoveCookies!',
                'confirm_password': 'woot1DontLoveCookies!'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Your password has been changed, and you have been logged' +
                ' into' in resp.data.decode('utf-8'))

    def test_error_messages(self):
        with self.app.test_client() as c:
            # Ensure than en email wasn't changed if password and confirm
            # password don't match.
            resp = c.post(
                self.reset_password_url,
                data={
                    'password': 'woot1DontLoveCookies!',
                    'confirm_password': 'woot1DoLoveCookies!'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Passwords do not match.' in resp.data.decode('utf-8'))

            # Ensure than en email wasn't changed if one of the password
            # fields is left empty
            resp = c.post(
                self.reset_password_url,
                data={'password': 'woot1DontLoveCookies!'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Confirm Password is required.' in resp.data.decode('utf-8'))

            # Ensure than en email wasn't changed if passwords don't satisfy
            # minimum requirements (one number, one uppercase letter, minimum
            # length).
            resp = c.post(
                self.reset_password_url,
                data={
                    'password': 'woot',
                    'confirm_password': 'woot'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Account password minimum length not satisfied.' in
                resp.data.decode('utf-8'))

    def test_sptoken(self):
        # Ensure that a proper token will render the change view
        with self.app.test_client() as c:
            # Ensure request.GET will render the forgot_change.html template.
            resp = c.get(self.reset_password_url)
            self.assertEqual(resp.status_code, 200)

        # Ensure that a missing token will return a 400 error
        with self.app.test_client() as c:
            # Ensure request.GET will render the forgot_change.html template.
            resp = c.get('/change')
            self.assertEqual(resp.status_code, 400)

    def test_password_changed_and_logged_in(self):
        with self.app.test_client() as c:
            # Ensure that a user will be logged in after successful password
            # reset.
            self.assertFalse(current_user)
            resp = c.post(
                self.reset_password_url,
                data={
                    'password': 'woot1DontLoveCookies!',
                    'confirm_password': 'woot1DontLoveCookies!'})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(current_user.email, 'r@rdegges.com')

        # Ensure that our password changed.
        with self.app.app_context():
            User.from_login('r@rdegges.com', 'woot1DontLoveCookies!')

    def test_json_response_get(self):
        # Specify expected response.
        expected_response = [
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'type': 'password'},
            {'label': 'Confirm Password',
             'name': 'confirm_password',
             'placeholder': 'Confirm Password',
             'required': True,
             'type': 'password'}]

        self.assertJsonResponse(
            'get', self.reset_password_url, 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify expected response.
        expected_response = {'account': {
            'username': 'randalldeg',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'status': 'ENABLED'}
        }

        # Specify post data
        json_data = json.dumps({
            'password': 'woot1DontLoveCookies!',
            'confirm_password': 'woot1DontLoveCookies!'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', self.reset_password_url, 200,
            json.dumps(expected_response), **request_kwargs)

        # Ensure that our password changed.
        with self.app.app_context():
            User.from_login('r@rdegges.com', 'woot1DontLoveCookies!')

    def test_json_response_stormpath_error(self):
        # Specify post data
        json_data = json.dumps({
            'password': 'woot',
            'confirm_password': 'woot'})

        # Specify expected response
        expected_response = {
            'message': 'Account password minimum length not satisfied.',
            'status': 400}
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}
        self.assertJsonResponse(
            'post', self.reset_password_url, 400,
            json.dumps(expected_response), **request_kwargs)

    def test_json_response_form_error(self):
        # Specify post data
        json_data = json.dumps({'password': 'woot1DontLoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': {"confirm_password": ["Confirm Password is required."]},
            'status': 400}

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', self.reset_password_url, 400,
            json.dumps(expected_response), **request_kwargs)


class TestMe(StormpathViewTestCase):
    """Test our me view."""
    def test_json_response(self):
        with self.app.test_client() as c:
            email = 'r@rdegges.com'
            password = 'woot1LoveCookies!'
            # Authenticate our user.
            resp = c.post('/login', data={
                'login': email,
                'password': password,
            })
            resp = c.get('/me')
            account = User.from_login(email, password)
            self.assertEqual(resp.data, account.to_json())

    def test_added_expansion(self):
        self.fail('This will be added when the json issue is addressed.')
