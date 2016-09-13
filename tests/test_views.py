"""Run tests against our custom views."""


import sys
from flask.ext.stormpath.models import User
from .helpers import StormpathTestCase, HttpAcceptWrapper
from stormpath.resources import Resource
from flask_stormpath.views import (
    StormpathView, FacebookLoginView, GoogleLoginView, View)
from flask import session, url_for, Response
from flask.ext.login import current_user
from werkzeug.exceptions import BadRequest
import json

if sys.version_info.major == 3:
    from unittest.mock import patch
else:
    from mock import patch


class StormpathViewTestCase(StormpathTestCase):
    """Base test class for Stormpath views."""

    def check_header(self, st, headers):
        return any(st in header for header in headers)

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

            # If we're comparing json response with account info,  make sure
            # that the following values are present in the response and pop
            # them, since we cannot predetermine these values in our expected
            # response.
            if user_to_json:
                resp_data = json.loads(resp.data)
                undefined_data = ('href', 'modified_at', 'created_at')
                self.assertTrue(
                    all(key in resp_data['account'].keys()
                        for key in undefined_data))
                for key in undefined_data:
                    resp_data['account'].pop(key)
                expected_response = json.loads(expected_response)

                # Ensure that response data is the same as the expected data.
                self.assertEqual(resp_data, expected_response)

            else:
                # Ensure that response data is the same as the expected data.
                self.assertEqual(
                    json.loads(resp.data), json.loads(expected_response))


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

        self.app.add_url_rule(self.app.config['stormpath']['web'][
                'invalidRequest']['uri'],
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
            self.assertEqual(resp.data, '{"foo": "bar"}')

            # Ensure that stormpath_response is html if request wants html.
            c.get('/')
            resp = self.view.make_stormpath_response(
                data, template='flask_stormpath/base.html', return_json=False)
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
             'visible': True,
             'type': 'email'},
            {'label': 'Password',
             'name': 'password',
             'placeholder': 'Password',
             'required': True,
             'visible': True,
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
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_login_redirect_url
        (self.app.config['stormpath']['web']['register']
            ['nextUri']) = stormpath_register_redirect_url

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
            self.assertEqual(resp.data, account.to_json())

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
            self.assertEqual(json.loads(resp.data), json_data)


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
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_login_redirect_url

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
            self.assertTrue(current_user.is_anonymous())

            self.assertTrue(
                'Oops! We encountered an unexpected error.  Please contact ' +
                'support and explain what you were doing at the time this ' +
                'error occurred.' in
                resp.data.decode('utf-8'))

            # Then we'll make the same request, but this time checking the
            # redirect status code and location.

            # Setting redirect URL to something that is easy to check
            facebook_login_redirect_url = '/redirect_for_facebook_login'
            (self.app.config['stormpath'][
                'web']['login']['uri']) = facebook_login_redirect_url

            # Try to log a user in.
            resp = c.get('/facebook')
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(current_user.is_anonymous())
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
        (self.app.config['stormpath']['web']['login']
            ['nextUri']) = stormpath_login_redirect_url

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
            self.assertTrue(current_user.is_anonymous())

            self.assertTrue(
                'Oops! We encountered an unexpected error.  Please contact ' +
                'support and explain what you were doing at the time this ' +
                'error occurred.' in
                resp.data.decode('utf-8'))

            # Then we'll make the same request, but this time checking the
            # redirect status code and location.

            # Setting redirect URL to something that is easy to check
            facebook_login_redirect_url = '/redirect_for_facebook_login'
            (self.app.config['stormpath'][
                'web']['login']['uri']) = facebook_login_redirect_url

            # Try to log a user in.
            resp = c.get(
                '/google', query_string={'code': 'mocked access token'})
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(current_user.is_anonymous())
            location = resp.headers.get('location')
            self.assertTrue(facebook_login_redirect_url in location)
