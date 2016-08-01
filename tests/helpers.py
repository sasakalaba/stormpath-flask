"""
Test helpers.

These utilities are meant to simplify our tests, and abstract away common test
operations.
"""


from os import environ
from unittest import TestCase
from uuid import uuid4

from flask import Flask
from flask.ext.stormpath import StormpathManager, StormpathError, User
from facebook import GraphAPI, GraphAPIError
from stormpath.client import Client
from oauth2client.client import OAuth2WebServerFlow
import requests


class StormpathTestCase(TestCase):
    """
    Custom test case which bootstraps a Stormpath client, application, and
    Flask app.

    This makes writing tests significantly easier as there's no work to do for
    setUp / tearDown.

    When a test finishes, we'll delete all Stormpath resources that were
    created.
    """
    def setUp(self):
        """Provision a new Client, Application, and Flask app."""
        self.client = bootstrap_client()
        self.application = bootstrap_app(self.client)
        self.app = bootstrap_flask_app(self.application)
        self.manager = StormpathManager(self.app)

        # html and json header settings
        self.html_header = 'text/html'
        self.json_header = 'application/json'

        # Remember default wsgi_app instance for dynamically changing request
        # type later in tests.
        self.default_wsgi_app = self.app.wsgi_app

        # Make sure our requests don't trigger a json response.
        self.app.wsgi_app = HttpAcceptWrapper(
            self.default_wsgi_app, self.html_header)

        # Add secrets and ids for social login stuff.
        self.app.config['STORMPATH_SOCIAL'] = {
            'FACEBOOK': {
                'app_id': environ.get('FACEBOOK_APP_ID'),
                'app_secret': environ.get('FACEBOOK_APP_SECRET')},
            'GOOGLE': {
                'client_id': environ.get('GOOGLE_CLIENT_ID'),
                'client_secret': environ.get('GOOGLE_CLIENT_SECRET')}
        }

        # Create a user.
        with self.app.app_context():
            self.user = User.create(
                username='rdegges',
                given_name='Randall',
                surname='Degges',
                email='r@rdegges.com',
                password='woot1LoveCookies!',
            )

    def tearDown(self):
        """Destroy all provisioned Stormpath resources."""
        destroy_resources(self.application, self.client)


class SignalReceiver(object):
    received_signals = None

    def signal_user_receiver_function(self, sender, user):
        if self.received_signals is None:
            self.received_signals = []
        self.received_signals.append((sender, user))


class HttpAcceptWrapper(object):
    """
    Helper class for injecting HTTP headers.
    """
    def __init__(self, app, accept_header):
        self.app = app
        self.accept_header = accept_header

    def __call__(self, environ, start_response):
        environ['HTTP_ACCEPT'] = (self.accept_header)
        return self.app(environ, start_response)


class CredentialsValidator(object):
    """
    Helper class for validating all the environment variables.
    """

    def validate_stormpath_credentials(self, client):
        """
        Ensure that we have proper credentials needed to properly test our
        Flask-Stormpath integration.
        """
        try:
            # Trying to access a resource that requires an api call
            # (like a tenant key) without the proper id and secret should
            # raise an error.
            client.tenant.key
        except StormpathError:
            raise ValueError(
                'Stormpath api id and secret invalid or missing. Set your ' +
                'credentials as environment variables before testing.')

    def validate_facebook_credentials(self, app):
        # Ensure that Facebook api id and secret are valid:
        graph_api = GraphAPI()
        try:
            graph_api.get_app_access_token(
                environ.get('FACEBOOK_APP_ID'),
                environ.get('FACEBOOK_APP_SECRET'))
        except GraphAPIError:
            raise ValueError(
                'Facebook app id and secret invalid or missing. Set your ' +
                'credentials as environment variables before testing.')

    def validate_google_credentials(self, app):
        root_url = environ.get('ROOT_URL')
        port = environ.get('PORT')

        # Ensure that our url parameters are present
        if not root_url or not port:
            raise ValueError(
                'Root url and port invalid or missing. Set your ' +
                'values as environment variables before testing.')
        redirect_uri = ''.join((root_url, ':', port, '/google'))

        # Ensure that Google api id and secret are valid:
        flow = OAuth2WebServerFlow(
            client_id=environ.get('GOOGLE_CLIENT_ID'),
            client_secret=environ.get('GOOGLE_CLIENT_SECRET'),
            scope=(
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'),
            redirect_uri=redirect_uri)
        url = flow.step1_get_authorize_url()

        resp = requests.get(url)
        if resp.status_code != 200:
            raise ValueError(
                'Google client id and secret invalid or missing. Set your ' +
                'credentials as environment variables before testing.')

    def validate_credentials(self, app, flask_app, client):
        """
        Ensure that we have proper credentials needed to properly test our
        social login stuff.
        """
        try:
            self.validate_stormpath_credentials(client)
            self.validate_facebook_credentials(flask_app)
            self.validate_google_credentials(flask_app)
        except ValueError as error:
            destroy_resources(app, client)
            raise error


def bootstrap_client():
    """
    Create a new Stormpath Client from environment variables.

    :rtype: obj
    :returns: A new Stormpath Client, fully initialized.
    """
    return Client(
        id=environ.get('STORMPATH_API_KEY_ID'),
        secret=environ.get('STORMPATH_API_KEY_SECRET'),
    )


def bootstrap_app(client):
    """
    Create a new, uniquely named, Stormpath Application.

    This application can be used in tests that run concurrently, as each
    application has a unique namespace.

    .. note::
        This will *also* create a Stormpath directory of the same name, so that
        you can use this application to create users immediately.

    :param obj client: A Stormpath Client resource.
    :rtype: obj
    :returns: A new Stormpath Application, fully initialized.
    """
    return client.applications.create({
        'name': 'flask-stormpath-tests-%s' % uuid4().hex,
        'description': 'This application is ONLY used for testing the ' +
        'Flask-Stormpath library. Please do not use this for anything ' +
        'serious.',
    }, create_directory=True)


def bootstrap_flask_app(app):
    """
    Create a new, fully initialized Flask app.

    :param obj app: A Stormpath Application resource.
    :rtype: obj
    :returns: A new Flask app.
    """
    a = Flask(__name__)
    a.config['DEBUG'] = True
    a.config['SECRET_KEY'] = uuid4().hex
    a.config['STORMPATH_API_KEY_ID'] = environ.get('STORMPATH_API_KEY_ID')
    a.config['STORMPATH_API_KEY_SECRET'] = environ.get(
        'STORMPATH_API_KEY_SECRET')
    a.config['STORMPATH_APPLICATION'] = app.name
    a.config['WTF_CSRF_ENABLED'] = False

    return a


def destroy_resources(app, client):
    """Destroy all provisioned Stormpath resources."""
    # Clean up the application.
    app_name = app.name
    app.delete()

    # Clean up the directories.
    for directory in client.directories.search(app_name):
        directory.delete()


""" Stormpath and social login credentials validation. """

# Create resources needed for validation.
client = bootstrap_client()
app = bootstrap_app(client)
flask_app = bootstrap_flask_app(app)

# Validate credentials.
cred_validator = CredentialsValidator()
cred_validator.validate_credentials(app, flask_app, client)

# Destroy resources.
destroy_resources(app, client)
