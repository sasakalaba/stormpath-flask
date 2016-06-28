"""
Test helpers.

These utilities are meant to simplify our tests, and abstract away common test
operations.
"""


from os import environ, path
from unittest import TestCase
from uuid import uuid4

from flask import Flask
from flask.ext.stormpath import StormpathManager
from stormpath.client import Client


# Make sure you've created a StormpathAccount, generated your apikey
# properties file, and saved to tests directory
if path.isfile('tests/apiKey.properties'):
    with open('tests/apiKey.properties') as f:
        lines = f.read().splitlines()
        apikey_properties = {}
        for line in lines:
            (key, val) = line.split(' = ')
            if 'id' in key:
                environ['STORMPATH_API_KEY_ID'] = val
            if 'secret' in key:
                environ['STORMPATH_API_KEY_SECRET'] = val
else:
    raise ValueError('First create your api properties file before testing!')


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

    def tearDown(self):
        """Destroy all provisioned Stormpath resources."""
        # Clean up the application.
        app_name = self.application.name
        self.application.delete()

        # Clean up the directories.
        for directory in self.client.directories.search(app_name):
            directory.delete()


class SignalReceiver(object):
    received_signals = None

    def signal_user_receiver_function(self, sender, user):
        if self.received_signals is None:
            self.received_signals = []
        self.received_signals.append((sender, user))


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
