"""Run tests against our custom views."""


import sys
import os
from flask_stormpath.models import User
from .helpers import StormpathTestCase, HttpAcceptWrapper, create_config_path
from stormpath.resources import Resource
from stormpath.error import Error as StormpathError
from flask_stormpath.views import (
    StormpathView, FacebookLoginView, GoogleLoginView, VerifyEmailView, View)
from flask import session, url_for, Response
from flask_login import current_user
from werkzeug.exceptions import BadRequest
from ruamel.yaml import util, round_trip_dump
import json
import shutil

if sys.version_info.major == 3:
    from unittest.mock import patch
else:
    from mock import patch


class StormpathViewTestCase(StormpathTestCase):
    """Base test class for Stormpath views."""

    def check_header(self, st, headers):
        return any(st in header for header in headers)

    def assertFormSettings(self, expected_fields):
        """
        Expected response set in json tests is based on the default settings
        specified in the config file. This method ensures that the developer
        didn't change the config file before running tests.
        """

        # Build form fields from the config and compare them to those
        # specified in the expected response.
        form_fields = []
        for key in self.form_fields.keys():
            field = self.form_fields[key].copy()

            # Convert fields from config to json response format.
            if field['enabled']:
                field.pop('enabled')
                field['name'] = Resource.from_camel_case(key)
                form_fields.append(field)

        # Sort and compare form fields
        self.assertDictList(form_fields, expected_fields, 'name')

    def assertJsonResponse(
            self, method, view, status_code, expected_response,
            user_to_json=False, **kwargs):
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

            # If we're expecting a redirect, follow the redirect flow so we
            # can access the final response data.
            if status_code == 302:
                resp = allowed_methods[method](
                    '/%s' % view, follow_redirects=True)
                self.assertEqual(resp.status_code, 200)

            # Check that response is json.
            self.assertFalse(self.check_header('text/html', resp.headers[0]))
            self.assertTrue(self.check_header(
                'application/json', resp.headers[0]))

            # If we're comparing json response with account info,  make sure
            # that the following values are present in the response and pop
            # them, since we cannot predetermine these values in our expected
            # response.
            if user_to_json:
                request_response = json.loads(resp.data.decode())
                undefined_data = ('href', 'modified_at', 'created_at')
                self.assertTrue(
                    all(key in request_response['account'].keys()
                        for key in undefined_data))
                for key in undefined_data:
                    request_response['account'].pop(key)
            else:
                request_response = json.loads(resp.data.decode())

        # Convert responses to dicts, sort them if necessary, and compare.
        expected_response = json.loads(expected_response)
        if hasattr(request_response, 'sort'):
            self.assertDictList(request_response, expected_response, 'name')
        else:
            self.assertEqual(request_response, expected_response)

    def assertDisabledView(self, view_name, post_data):
        # Ensure that a disabled view will always return a 404 response.

        # Create a config directory for storing different temporary yaml config
        # files needed for testing.
        self.config_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'config')
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

        # Disable the view.

        # Create a new updated config file from the default one.
        config, ind, bsi = util.load_yaml_guess_indent(
            open(self.app.config['STORMPATH_CONFIG_PATH']))
        config['stormpath']['web'][view_name]['enabled'] = False
        config_name = 'test-config-%s' % view_name
        round_trip_dump(
            config, open(create_config_path(config_name, default=False), 'w'),
            indent=ind, block_seq_indent=bsi)

        # Set new config file before app init.
        os.environ['TEST_CONFIG'] = json.dumps(
            {'filename': config_name, 'default': False})

        # Reinitialize the application.
        self.reinit_app()

        # Ensure that both GET and POST will return a 404.
        with self.app.test_client() as c:
            resp = c.get('/' + view_name)
            self.assertEqual(resp.status_code, 404)

            resp = c.post('/' + view_name, data=post_data)
            self.assertEqual(resp.status_code, 404)

        # Revert to the default config.
        os.environ['TEST_CONFIG'] = json.dumps({})

    def tearDown(self):
        # Destroy temporary yaml config resources.
        if hasattr(self, 'config_dir') and os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)


class TestHelperMethods(StormpathViewTestCase):
    """Test our helper functions."""

    def setUp(self):
        super(TestHelperMethods, self).setUp()
        # We need a config for a StormpathView, so we'll use login form config.
        self.config = self.app.config['stormpath']['web']['login']

        # Create an 'invalid_request' view. This view has to be implemented by
        # the developer/framework, so it is not part of the stormpath-flask
        # library. We will create one for testing purposes. Flask requires
        # this do be done in setUp, before the first request is handled.
        class InvalidRequestView(View):
            def dispatch_request(self):
                xml = 'Invalid request.'
                return Response(xml, mimetype='text/xml', status=400)

        self.app.add_url_rule(
            self.app.config['stormpath']['web']['invalidRequest']['uri'],
            'stormpath.invalid_request',
            InvalidRequestView.as_view('invalid_request'),
        )

        # Ensure that StormpathView.accept_header is properly set.
        with self.app.test_client() as c:
            # Create a request with html accept header
            c.get('/')

            with self.app.app_context():
                self.view = StormpathView(self.config)

    def test_request_wants_json(self):
        # Ensure that request_wants_json returns False if 'application/json'
        # accept header isn't present.
        self.view.accept_header = 'text/html'
        self.assertFalse(self.view.request_wants_json)

        self.view.accept_header = None
        self.assertFalse(self.view.request_wants_json)

        self.view.accept_header = 'foo/bar'
        self.assertFalse(self.view.request_wants_json)

        self.view.accept_header = 'application/json'
        self.assertTrue(self.view.request_wants_json)

    def test_make_stormpath_response(self):
        data = {'foo': 'bar'}
        with self.app.test_client() as c:
            # Ensure that stormpath_response is json if request wants json.
            c.get('/')
            resp = self.view.make_stormpath_response(json.dumps(data))
            self.assertFalse(self.check_header(
                'text/html', resp.headers[0]))
            self.assertTrue(self.check_header(
                'application/json', resp.headers[0]))
            self.assertEqual(resp.data.decode(), '{"foo": "bar"}')

            # Ensure that stormpath_response is html if request wants html.
            c.get('/')
            resp = self.view.make_stormpath_response(
                data, template='flask_stormpath/base.html', return_json=False)

            # Python 3 support for testing html response.
            if sys.version_info.major == 3:
                self.assertTrue(isinstance(resp, str))
            else:
                self.assertTrue(isinstance(resp, unicode))

    def test_validate_request(self):
        with self.app.test_client() as c:
            # Ensure that a request with an html accept header will return an
            # html response.
            c.get('/')
            with self.app.app_context():
                self.view.__init__(self.config)
                self.assertEqual(self.view.accept_header, 'text/html')

            # Ensure that a request with a json accept header will return a
            # json response.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)
            c.get('/')
            with self.app.app_context():
                self.view.__init__(self.config)
                self.assertEqual(self.view.accept_header, 'application/json')

            # Ensure that a request with no accept headers will return the
            # first allowed type.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, '')
            c.get('/')
            with self.app.app_context():
                self.view.__init__(self.config)
                self.assertEqual(
                    self.view.accept_header,
                    self.app.config['stormpath']['web']['produces'][0])

            # Ensure that a request with */* accept header will return the
            # first allowed type.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, '*/*')
            c.get('/')
            with self.app.app_context():
                self.view.__init__(self.config)
                self.assertEqual(
                    self.view.accept_header,
                    self.app.config['stormpath']['web']['produces'][0])

            # Ensure that an invalid accept header type will return None.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, 'text/plain')
            c.get('/')
            with self.app.app_context():
                self.view.__init__(self.config)
                self.assertEqual(self.view.accept_header, None)

    def test_accept_header_valid(self):
        # Ensure that StormpathView.accept_header is properly set.
        with self.app.test_client() as c:
            # Create a request with html accept header
            c.get('/')

            with self.app.app_context():
                view = StormpathView(self.config)
                self.assertEqual(view.accept_header, 'text/html')
                self.assertFalse(view.invalid_request)

            # Create a request with json accept header
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)
            c.get('/')

            with self.app.app_context():
                view = StormpathView(self.config)
                self.assertEqual(view.accept_header, 'application/json')
                self.assertFalse(view.invalid_request)

    def test_accept_header_invalid(self):
        # If a request type is not HTML, JSON, */* or empty, request is
        # deemed invalid and is passed to the developer to handle the response.
        # The developer handles the response via uri specified in the config
        # file, in:
        #    web > invalidRequest.
        with self.app.test_client() as c:
            # Create a request with an accept header not supported by
            # flask_stormpath.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, 'text/plain')
            # We'll use login since '/' is not an implemented route.
            response = c.get('/login')

            # Ensure that accept header and invalid_request are properly set.
            with self.app.app_context():
                view = StormpathView(self.config)
                self.assertEqual(view.accept_header, None)
                self.assertTrue(view.invalid_request)

            # If a view for 'invalid_request' uri is implemented, the response
            # is determined in that view. (We've implemented that as our
            # InvalidRequestView).
            response = c.get('/login', follow_redirects=True)
            self.assertEqual(response.status, '400 BAD REQUEST')
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content_type, 'text/xml; charset=utf-8')

            # If view for that uri is not implemented, the response is 501.
            self.app.config[
                'stormpath']['web']['invalidRequest']['uri'] = None
            response = c.get('/login', follow_redirects=True)

            self.assertEqual(response.status, '501 NOT IMPLEMENTED')
            self.assertEqual(response.status_code, 501)
            self.assertEqual(response.content_type, 'text/html')

    @patch('flask_stormpath.views.flash')
    def test_process_stormpath_error(self, flash):
        # Ensure that process_stormpath_error properly parses the error
        # message and returns a proper response (json or html).

        error = StormpathError('This is a default message.')

        # Ensure that process_stormpath_error will return a proper response.
        with self.app.test_request_context():
            # HTML (or other non JSON) response.
            response = self.view.process_stormpath_error(error)
            self.assertIsNone(response)
            self.assertEqual(flash.call_count, 1)

            # JSON response.
            self.view.accept_header = 'application/json'
            response = self.view.process_stormpath_error(error)
            self.assertEqual(
                response.headers['Content-Type'], 'application/json')
            json_response = json.loads(response.response[0].decode())
            self.assertEqual(
                json_response['message'], 'This is a default message.')

            # Ensure that self.error_message will check for error.user_message
            # first, but will default to error.message otherwise.
            error.user_message = 'This is a user message.'
            response = self.view.process_stormpath_error(error)
            json_response = json.loads(response.response[0].decode())
            self.assertEqual(
                json_response['message'], 'This is a user message.')

    def test_csrf_disabled_on_json(self):
        # Ensure that JSON requests have CSRF disabled.

        with self.app.test_client() as c:
            # Ensure that HTML will have CSRF enabled.
            c.get('/')
            with self.app.app_context():
                self.view = StormpathView(self.config)
            self.assertTrue(self.view.form.csrf_enabled)

            # Ensure that JSON will have CSRF disabled.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)
            c.get('/')
            with self.app.app_context():
                self.view = StormpathView(self.config)
            self.assertFalse(self.view.form.csrf_enabled)

            # Ensure that non JSON will have CSRF enabled.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, 'text/plain')
            c.get('/')
            with self.app.app_context():
                self.view = StormpathView(self.config)
            self.assertTrue(self.view.form.csrf_enabled)


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
            # Ensure that the form error is raised if the email already
            # exists.
            resp = c.post('/register', data={
                'given_name': 'Randall registration',
                'surname': 'Degges registration',
                'email': 'r@rdegges.com',
                'password': 'Hilolsds1',
            })
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Account with that email already exists.'
                in resp.data.decode('utf-8'))
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
        self.app.config['stormpath']['web']['register'][
            'nextUri'] = stormpath_register_redirect_url

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
        self.app.config['stormpath']['web']['login'][
            'nextUri'] = stormpath_login_redirect_url
        self.app.config['stormpath']['web']['register'][
            'nextUri'] = stormpath_register_redirect_url

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
             'visible': True,
             'type': 'email'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'visible': True,
             'type': 'password'}]

        # Ensure that the form fields specified in the expected response
        # match those specified in the config file.
        self.assertFormSettings(expected_response)

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
        expected_response['account']['full_name'] = 'Randall2 Degges2'
        expected_response['account'].pop('password')

        # Specify post data
        json_data = json.dumps(user_data)
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        self.assertJsonResponse(
            'post', 'register', 200, json.dumps(expected_response),
            user_to_json=True, **request_kwargs)

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
            'status': 409}
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

    def test_enabled(self):
        # Ensure that a disabled login will return 404.
        data = {
            'login': 'r@rdegges.com',
            'password': 'woot1LoveCookies!'
        }
        self.assertDisabledView('login', data)

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
                'login': 'rdegges',
                'password': 'woot1LoveCookies!',
            })
            self.assertEqual(resp.status_code, 302)

    def test_error_messages(self):
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

    def test_redirect_to_login_or_register_url(self):
        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        stormpath_register_redirect_url = '/redirect_for_registration'
        self.app.config['stormpath']['web']['login'][
            'nextUri'] = stormpath_login_redirect_url
        self.app.config['stormpath']['web']['register'][
            'nextUri'] = stormpath_register_redirect_url

        with self.app.test_client() as c:
            # Attempt a login using username and password.
            resp = c.post('/login', data={
                'login': 'rdegges',
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
             'visible': True,
             'type': 'text'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'visible': True,
             'type': 'password'}]

        # Ensure that the form fields specified in the expected response
        # match those specified in the config file.
        self.assertFormSettings(expected_response)

        self.assertJsonResponse(
            'get', 'login', 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify expected response.
        expected_response = {'account': {
            'username': 'rdegges',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'full_name': 'Randall Degges',
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
            user_to_json=True, **request_kwargs)

    def test_json_response_stormpath_error(self):
        # Specify post data
        json_data = json.dumps({
            'login': 'wrong@email.com',
            'password': 'woot1LoveCookies!'})

        # Specify expected response
        expected_response = {
            'message': 'Invalid username or password.',
            'status': 400}
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

    def test_json_response_get(self):
        # We'll use login form for our json response
        self.form_fields = self.app.config['stormpath']['web']['login'][
            'form']['fields']

        # We'll set the redirect url login since test client cannot redirect
        # to index view.
        self.app.config['stormpath']['web']['logout']['nextUri'] = '/login'

        # Specify expected response.
        expected_response = [
            {'label': 'Username or Email',
             'name': 'login',
             'placeholder': 'Username or Email',
             'required': True,
             'visible': True,
             'type': 'text'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'visible': True,
             'type': 'password'}]

        # Ensure that the form fields specified in the expected response
        # match those specified in the config file.
        self.assertFormSettings(expected_response)

        self.assertJsonResponse(
            'get', 'logout', 302, json.dumps(expected_response))


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
            # Ensure request.GET will render the forgot_password.html template.
            resp = c.get('/forgot')
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Enter your email address below to reset your password.' in
                resp.data.decode('utf-8'))

            # Ensure that request.POST will render the
            # forgot_password_success.html
            resp = c.post('/forgot', data={'email': 'r@rdegges.com'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Your password reset email has been sent!' in
                resp.data.decode('utf-8'))

    def test_error_messages(self):
        with self.app.test_client() as c:
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
             'visible': True,
             'type': 'email'}]

        # Ensure that the form fields specified in the expected response
        # match those specified in the config file.
        self.assertFormSettings(expected_response)

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

        # Specify url for json
        self.reset_password_url = ''.join(['change?sptoken=', self.token])

    def test_proper_template_rendering(self):
        # Ensure that proper templates are rendered based on the request
        # method.
        with self.app.test_client() as c:
            # Ensure request.GET will render the change_password.html template.
            resp = c.get(self.reset_password_url)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Enter your new account password below.' in
                resp.data.decode('utf-8'))

            # Ensure that request.POST will render the
            # change_password_success.html
            resp = c.post(self.reset_password_url, data={
                'password': 'woot1DontLoveCookies!',
                'confirm_password': 'woot1DontLoveCookies!'})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Your password has been changed, and you have been logged' +
                ' into' in resp.data.decode('utf-8'))

    def test_error_messages(self):
        with self.app.test_client() as c:
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
            # Ensure request.GET will render the change_password.html template.
            resp = c.get(self.reset_password_url)
            self.assertEqual(resp.status_code, 200)

        # Ensure that a missing token will return a 400 error
        with self.app.test_client() as c:
            # Ensure request.GET will render the change_password.html template.
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
             'visible': True,
             'type': 'password'},
            {'label': 'Confirm Password',
             'name': 'confirm_password',
             'placeholder': 'Confirm Password',
             'required': True,
             'visible': True,
             'type': 'password'}]

        # Ensure that the form fields specified in the expected response
        # match those specified in the config file.
        self.assertFormSettings(expected_response)

        self.assertJsonResponse(
            'get', self.reset_password_url, 200, json.dumps(expected_response))

    def test_json_response_valid_form(self):
        # Specify expected response.
        expected_response = {'account': {
            'username': 'rdegges',
            'email': 'r@rdegges.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'full_name': 'Randall Degges',
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
            json.dumps(expected_response), user_to_json=True,
            **request_kwargs)

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


class TestVerify(StormpathViewTestCase):
    """ Test our verify view. """

    def setUp(self):
        super(TestVerify, self).setUp()
        # We need to set form fields to test out json stuff in the
        # assertJsonResponse method.
        self.form_fields = self.app.config['stormpath']['web'][
            'verifyEmail']['form']['fields']

        # Set our verify route (by default is missing)
        self.app.add_url_rule(
            self.app.config['stormpath']['web']['verifyEmail']['uri'],
            'stormpath.verify',
            VerifyEmailView.as_view('verify'),
            methods=['GET', 'POST'],
        )

        # Enable verification flow.
        self.directory = self.client.directories.search(self.name).items[0]
        account_policy = self.directory.account_creation_policy
        account_policy.verification_email_status = 'ENABLED'
        account_policy.save()

        # Create a new account
        with self.app.app_context():
            user = User.create(
                username='rdegges_verify',
                given_name='Randall',
                surname='Degges',
                email='r@verify.com',
                password='woot1LoveCookies!',
            )
        self.account = self.directory.accounts.search(user.email)[0]

        # Specify url for json
        self.verify_url = ''.join([
            'verify?sptoken=', self.get_verification_token()])

    def get_verification_token(self):
        # Retrieves an email verification token.
        self.account.refresh()
        if self.account.email_verification_token:
            return self.account.email_verification_token.href.split('/')[-1]
        return None

    def test_verify_token_valid(self):
        # Ensure that a valid token will activate a users account. By default,
        # autologin is set to false, so the response should be a redirect
        # to verifyEmail next uri.

        # Setting redirect URL to something that is easy to check
        stormpath_verify_redirect_url = '/redirect_for_verify'
        self.app.config['stormpath']['web']['verifyEmail'][
            'nextUri'] = stormpath_verify_redirect_url

        # Get activation token
        sptoken = self.get_verification_token()

        # Ensure that a proper verify token will activate a user's account.
        with self.app.test_client() as c:
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 302)

            # Ensure proper redirection if autologin is disabled
            location = resp.headers.get('location')
            self.assertTrue(stormpath_verify_redirect_url in location)
            self.account.refresh()
            self.assertEqual(self.account.status, 'ENABLED')

    def test_verify_token_invalid(self):
        # If the verification token is invalid, render a template with a form
        # used to resend an activation token.

        # Set invalid activation token
        sptoken = 'foobar'

        # Ensure that a proper verify token will activate a user's account.
        with self.app.test_client() as c:
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'This verification link is no longer valid.' in
                resp.data.decode('utf-8'))
            self.account.refresh()
            self.assertEqual(self.account.status, 'UNVERIFIED')

    def test_verify_token_missing(self):
        # If the verification token is missing, render a template with a form
        # used to resend an activation token.

        # Set missing activation token
        sptoken = None

        # Ensure that a proper verify token will activate a user's account.
        with self.app.test_client() as c:
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'This verification link is no longer valid.' in
                resp.data.decode('utf-8'))
            self.account.refresh()
            self.assertEqual(self.account.status, 'UNVERIFIED')

    def test_resend_verification_token(self):
        # Ensure that submitting an email form will generate a new activation
        # token. Make sure that a redirect uri will have an unverified status.

        # Get current activation token
        sptoken = self.get_verification_token()

        with self.app.test_client() as c:
            # Activate the account
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 302)
            self.account.refresh()
            self.assertEqual(self.account.status, 'ENABLED')

            # Set the account back to 'UNVERIFIED'
            self.account.status = 'UNVERIFIED'
            self.account.save()
            self.account.refresh()

            # Submit a form that will resend a new activation token
            resp = c.post('/verify', data={'email': 'r@verify.com'})
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(
                'You should be redirected automatically to target URL: ' +
                '<a href="%s">' % self.app.config[
                    'stormpath']['web']['verifyEmail']['unverifiedUri'] +
                '/login?status=unverified</a>.' in
                resp.data.decode('utf-8'))
            self.account.refresh()
            self.assertEqual(self.account.status, 'UNVERIFIED')

            # Make sure that a new token has replaced the old one
            new_sptoken = self.get_verification_token()
            self.assertNotEqual(sptoken, new_sptoken)

            # Activate an account with a new token
            resp = c.get('/verify', query_string={'sptoken': new_sptoken})
            self.assertEqual(resp.status_code, 302)
            self.account.refresh()
            self.assertEqual(self.account.status, 'ENABLED')

    def test_resend_verification_token_unassociated_email(self):
        # Ensure that submitting an unassociated  email form will not
        # generate a new activation token. Make sure that a redirect uri will
        # still have an unverified status.

        # Get current activation token
        sptoken = self.get_verification_token()

        with self.app.test_client() as c:
            # Activate the account
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 302)
            self.account.refresh()
            self.assertEqual(self.account.status, 'ENABLED')

            # Set the account back to 'UNVERIFIED'
            self.account.status = 'UNVERIFIED'
            self.account.save()
            self.account.refresh()

            # Submit a form with an unassociated email
            resp = c.post('/verify', data={'email': 'doesnot@exist.com'})
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(
                'You should be redirected automatically to target URL: ' +
                '<a href="%s">' % self.app.config[
                    'stormpath']['web']['verifyEmail']['unverifiedUri'] +
                '/login?status=unverified</a>.' in
                resp.data.decode('utf-8'))
            self.account.refresh()
            self.assertEqual(self.account.status, 'UNVERIFIED')

            # Make sure that a new token was not generated
            new_sptoken = self.get_verification_token()
            self.assertIsNone(new_sptoken)

    def test_autologin_true(self):
        # Ensure that the enabled autologin will log a user in and redirect
        # him user to the uri specified in the login > nextUri.

        # Set autologin to true
        self.app.config['stormpath']['web']['register']['autoLogin'] = True

        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        self.app.config['stormpath']['web']['login'][
            'nextUri'] = stormpath_login_redirect_url

        # Get activation token
        sptoken = self.get_verification_token()

        # Ensure that a proper verify token will activate a user's account.
        with self.app.test_client() as c:
            resp = c.get('/verify', query_string={'sptoken': sptoken})
            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_login_redirect_url in location)
            self.account.refresh()
            self.assertEqual(self.account.status, 'ENABLED')

    def test_response_form_error_missing(self):
        # Ensure that a missing email will render a proper error.
        # Get current activation token
        with self.app.test_client() as c:
            resp = c.post('/verify', data={}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue('Email is required.' in resp.data.decode('utf-8'))

    def test_response_form_error_invalid(self):
        # Ensure that an invalid email will render a proper error.
        with self.app.test_client() as c:
            resp = c.post(
                '/verify', data={'email': 'foobar'}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                'Email must be in valid format.' in resp.data.decode('utf-8'))

    def test_verify_token_valid_json(self):
        # Ensure that a valid token will activate a users account. By default,
        # autologin is set to false, so the response should be an empty body
        # with 200 status code.

        # Specify expected response.
        expected_response = {}

        # Check the json response.
        self.assertJsonResponse(
            'get', self.verify_url, 200, json.dumps(expected_response))

    def test_verify_token_invalid_json(self):
        # If the verification token is invalid, return an error from the
        # REST API.

        # Set an invalid token
        self.verify_url = 'verify?sptoken=foobar'

        # Specify expected response.
        expected_response = {
            'status': 404,
            'message': 'The requested resource does not exist.'
        }

        # Check the json response.
        self.assertJsonResponse(
            'get', self.verify_url, 404, json.dumps(expected_response))

    def test_verify_token_missing_json(self):
        # If the verification token is missing, respond with our custom
        # message and a 400 status code.

        # Specify expected response.
        expected_response = {
            'status': 400,
            'message': 'sptoken parameter not provided.'
        }

        # Check the json response.
        self.assertJsonResponse(
            'get', 'verify', 400, json.dumps(expected_response))

    def test_resend_verification_token_json(self):
        # Ensure that submitting an email form will generate a new activation
        # token. Response should be an empty body with a 200 status code.

        # First we will activate the account

        # Specify expected response.
        expected_response = {}

        # Check the json response.
        self.assertJsonResponse(
            'get', self.verify_url, 200, json.dumps(expected_response))

        # Ensure that the account is enabled
        self.account.refresh()
        self.assertEqual(self.account.status, 'ENABLED')

        # Set the account back to 'UNVERIFIED'
        self.account.status = 'UNVERIFIED'
        self.account.save()
        self.account.refresh()

        # Submit a form that will resend a new activation token

        # Specify expected response.
        expected_response = {}

        # Post data
        json_data = json.dumps({'email': 'r@verify.com'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'
        }

        # Check the json response.
        self.assertJsonResponse(
            'post', 'verify', 200, json.dumps(expected_response),
            **request_kwargs)

        # Ensure that the account is still unverified.
        self.account.refresh()
        self.assertEqual(self.account.status, 'UNVERIFIED')

        # Retrieve a newly generated token
        self.new_verify_url = ''.join([
            'verify?sptoken=', self.get_verification_token()])
        self.assertNotEqual(self.verify_url, self.new_verify_url)

        # Activate an account with a new token

        # Specify expected response.
        expected_response = {}

        # Check the json response.
        self.assertJsonResponse(
            'get', self.new_verify_url, 200, json.dumps(expected_response))

        # Ensure that the account is now enabled
        self.account.refresh()
        self.assertEqual(self.account.status, 'ENABLED')

    def test_resend_verification_token_unassociated_email_json(self):
        # Ensure that submitting an unassociated  email form will not
        # generate a new activation token. Make sure that response will still
        # be an empty body with a 200 status code.

        # First we will activate the account

        # Specify expected response.
        expected_response = {}

        # Check the json response.
        self.assertJsonResponse(
            'get', self.verify_url, 200, json.dumps(expected_response))

        # Ensure that the account is enabled
        self.account.refresh()
        self.assertEqual(self.account.status, 'ENABLED')

        # Set the account back to 'UNVERIFIED'
        self.account.status = 'UNVERIFIED'
        self.account.save()
        self.account.refresh()

        # Submit a form that will resend a new activation token

        # Specify expected response.
        expected_response = {}

        # Post data
        json_data = json.dumps({'email': 'doesnot@exist.com'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'
        }

        # Check the json response.
        self.assertJsonResponse(
            'post', 'verify', 200, json.dumps(expected_response),
            **request_kwargs)

        # Ensure that the account is still unverified.
        self.account.refresh()
        self.assertEqual(self.account.status, 'UNVERIFIED')

        # Make sure that a new token was not generated
        new_sptoken = self.get_verification_token()
        self.assertIsNone(new_sptoken)

    def test_autologin_true_json(self):
        # Ensure that the enabled autologin will log a user in and return an
        # account json response.

        # Set autologin to true
        self.app.config['stormpath']['web']['register']['autoLogin'] = True

        # Specify expected response.
        expected_response = {'account': {
            'username': 'rdegges_verify',
            'email': 'r@verify.com',
            'given_name': 'Randall',
            'middle_name': None,
            'surname': 'Degges',
            'full_name': 'Randall Degges',
            'status': 'ENABLED'}
        }

        # Check the json response.
        self.assertJsonResponse(
            'get', self.verify_url, 200, json.dumps(expected_response),
            user_to_json=True)

    def test_response_form_error_missing_json(self):
        # Ensure that a missing email will render a proper error.

        # Specify expected response
        expected_response = {
            'message': {"email": ["Email is required."]},
            'status': 400}

        # Post data
        json_data = json.dumps({})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'
        }

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        # Check the json response-
        self.assertJsonResponse(
            'post', 'verify', 400, json.dumps(expected_response),
            **request_kwargs)

    def test_response_form_error_invalid_json(self):
        # Ensure that an invalid email will render a proper error.

        # Specify expected response
        expected_response = {
            'message': {"email": ["Email must be in valid format."]},
            'status': 400}

        # Post data
        json_data = json.dumps({'email': 'foobar'})
        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'
        }

        request_kwargs = {
            'data': json_data,
            'content_type': 'application/json'}

        # Check the json response-
        self.assertJsonResponse(
            'post', 'verify', 400, json.dumps(expected_response),
            **request_kwargs)


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
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.data.decode(), account.to_json())

    def test_redirect_to_login(self):

        with self.app.test_client() as c:
            # Ensure that the user will be redirected to login if he/she is not
            # logged it.
            resp = c.get('/me')

            redirect_url = url_for('stormpath.login', next='/me')
            self.assertEqual(resp.status_code, 302)
            location = resp.headers.get('location')
            self.assertTrue(redirect_url in location)

    def test_added_expansion(self):
        # NOTE: We're not testing expansion in models since we need to call
        # the expanded me view.

        # Enable expanded info on our me view
        me_expand = self.app.config['stormpath']['web']['me']['expand']
        for key in me_expand.keys():
            me_expand[key] = True

        with self.app.test_client() as c:
            email = 'r@rdegges.com'
            password = 'woot1LoveCookies!'

            # Authenticate our user.
            resp = c.post('/login', data={
                'login': email,
                'password': password,
            })
            resp = c.get('/me')
            self.assertEqual(resp.status_code, 200)

            # Get unexpanded account object
            account = User.from_login(email, password)

            json_data = {'account': {
                'href': account.href,
                'modified_at': account.modified_at.isoformat(),
                'created_at': account.created_at.isoformat(),
                'email': 'r@rdegges.com',
                'full_name': 'Randall Degges',
                'given_name': 'Randall',
                'middle_name': None,
                'status': 'ENABLED',
                'surname': 'Degges',
                'username': 'rdegges'
            }}

            # Ensure that the missing expanded info won't break
            # User.to_json() flow.
            self.assertEqual(json.loads(account.to_json()), json_data)

            json_data['account'].update({
                'applications': {},
                'customData': {},
                'directory': {},
                'tenant': {},
                'providerData': {},
                'groupMemberships': {},
                'groups': {},
                'apiKeys': {}
            })

            # Ensure that expanded me response will return proper data.
            self.assertEqual(json.loads(resp.data.decode()), json_data)


class TestFacebookLogin(StormpathViewTestCase):
    """ Test our Facebook login view. """

    @patch('flask_stormpath.views.get_user_from_cookie')
    def test_access_token(self, access_token_mock):
        # Ensure that proper access code fetching will continue processing
        # the view.
        access_token_mock.return_value = {
            'access_token': 'mocked access token'}
        with self.app.test_request_context():
            FacebookLoginView()

        # Ensure that invalid access code fetching will return a 400 BadRequest
        # response.
        access_token_mock.return_value = None
        with self.app.test_request_context():
            with self.assertRaises(BadRequest) as error:
                FacebookLoginView()
            self.assertEqual(error.exception.name, 'Bad Request')
            self.assertEqual(error.exception.code, 400)

    @patch('flask_stormpath.views.get_user_from_cookie')
    @patch('flask_stormpath.views.SocialView.get_account')
    def test_user_logged_in_and_redirect(self, user_mock, access_token_mock):
        # Access token is retrieved on the front end of our applications, so
        # we have to mock it.
        access_token_mock.return_value = {
            'access_token': 'mocked access token'}
        user_mock.return_value = self.user

        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        self.app.config['stormpath']['web']['login'][
            'nextUri'] = stormpath_login_redirect_url

        # Ensure that the correct access token will log our user in and
        # redirect him to the index page.
        with self.app.test_client() as c:
            self.assertFalse(current_user)
            # Log this user in.
            resp = c.get('/facebook')
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(current_user, self.user)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_login_redirect_url in location)

    @patch('flask_stormpath.views.get_user_from_cookie')
    def test_error_retrieving_user(self, access_token_mock):
        # Access token is retrieved on the front end of our applications, so
        # we have to mock it.
        access_token_mock.return_value = {
            'access_token': 'mocked access token'}

        # Ensure that the user will be redirected back to the login page with
        # the proper error message rendered in case we fail to fetch the user
        # account.
        with self.app.test_client() as c:
            # First we'll check the error message.
            self.assertFalse(current_user)
            # Try to log a user in.
            resp = c.get('/facebook', follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(current_user.is_anonymous)

            self.assertTrue(
                'Oops! We encountered an unexpected error.  Please contact ' +
                'support and explain what you were doing at the time this ' +
                'error occurred.' in
                resp.data.decode('utf-8'))

            # Then we'll make the same request, but this time checking the
            # redirect status code and location.

            # Setting redirect URL to something that is easy to check
            facebook_login_redirect_url = '/redirect_for_facebook_login'
            self.app.config['stormpath']['web']['login'][
                'uri'] = facebook_login_redirect_url

            # Try to log a user in.
            resp = c.get('/facebook')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(current_user.is_anonymous)
            location = resp.headers.get('location')
            self.assertTrue(facebook_login_redirect_url in location)


class TestGoogleLogin(StormpathViewTestCase):
    """ Test our Google login view. """

    def test_access_token(self):
        # Ensure that proper access code fetching will continue processing
        # the view.
        with self.app.test_request_context() as req:
            req.request.args = {'code': 'mocked access token'}
            GoogleLoginView()

        # Ensure that invalid access code fetching will return a 400 BadRequest
        # response.
        with self.app.test_request_context() as req:
            req.request.args = {}
            with self.assertRaises(BadRequest) as error:
                GoogleLoginView()
            self.assertEqual(error.exception.name, 'Bad Request')
            self.assertEqual(error.exception.code, 400)

    @patch('flask_stormpath.views.SocialView.get_account')
    def test_user_logged_in_and_redirect(self, user_mock):
        # Access token is retrieved on the front end of our applications, so
        # we have to mock it.
        user_mock.return_value = self.user

        # Setting redirect URL to something that is easy to check
        stormpath_login_redirect_url = '/redirect_for_login'
        self.app.config['stormpath']['web']['login'][
            'nextUri'] = stormpath_login_redirect_url

        # Ensure that the correct access token will log our user in and
        # redirect him to the index page.
        with self.app.test_client() as c:
            self.assertFalse(current_user)
            # Log this user in.
            resp = c.get(
                '/google', query_string={'code': 'mocked access token'})
            self.assertEqual(resp.status_code, 302)
            self.assertEqual(current_user, self.user)
            location = resp.headers.get('location')
            self.assertTrue(stormpath_login_redirect_url in location)

    def test_error_retrieving_user(self):
        # Ensure that the user will be redirected back to the login page with
        # the proper error message rendered in case we fail to fetch the user
        # account.
        with self.app.test_client() as c:
            # First we'll check the error message.
            self.assertFalse(current_user)
            # Try to log a user in.
            resp = c.get(
                '/google', query_string={'code': 'mocked access token'},
                follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(current_user.is_anonymous)

            self.assertTrue(
                'Oops! We encountered an unexpected error.  Please contact ' +
                'support and explain what you were doing at the time this ' +
                'error occurred.' in
                resp.data.decode('utf-8'))

            # Then we'll make the same request, but this time checking the
            # redirect status code and location.

            # Setting redirect URL to something that is easy to check
            facebook_login_redirect_url = '/redirect_for_facebook_login'
            self.app.config['stormpath']['web']['login'][
                'uri'] = facebook_login_redirect_url

            # Try to log a user in.
            resp = c.get(
                '/google', query_string={'code': 'mocked access token'})
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(current_user.is_anonymous)
            location = resp.headers.get('location')
            self.assertTrue(facebook_login_redirect_url in location)
