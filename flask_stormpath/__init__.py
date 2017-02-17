# -*- coding: utf-8 -*-


import os
from datetime import timedelta
from flask import Blueprint, __version__ as flask_version, current_app

from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user
)

from flask_login.utils import _get_user
from stormpath.client import Client
from stormpath.error import Error as StormpathError
from stormpath_config.loader import ConfigLoader
from stormpath_config.strategies import (
    LoadEnvConfigStrategy,
    LoadFileConfigStrategy,
    LoadAPIKeyConfigStrategy,
    LoadAPIKeyFromConfigStrategy,
    ValidateClientConfigStrategy,
    EnrichClientFromRemoteConfigStrategy,
    EnrichIntegrationFromRemoteConfigStrategy,
    MoveAPIKeyToClientAPIKeyStrategy)

from werkzeug.local import LocalProxy
from .context_processors import user_context_processor
from .request_processors import request_wants_json
from .models import User
from .settings import StormpathSettings
from .views import (
    RegisterView,
    LoginView,
    ForgotPasswordView,
    ChangePasswordView,
    VerifyEmailView,
    LogoutView,
    MeView,
    GoogleLoginView,
    FacebookLoginView
)


"""
    flask-stormpath
    ---------------

    This module provides secure user authentication and authorization for Flask
    via Stormpath (https://stormpath.com/).  It lets you log users in and out
    of your application in a database-independent fashion, along with allowing
    you to store variable user information in a JSON data store.

    No user table required! :)

    :copyright: (c) 2012 - 2015 Stormpath, Inc.
    :license: Apache, see LICENSE for more details.
"""


__version__ = '0.4.4'
__version_info__ = __version__.split('.')
__author__ = 'Stormpath, Inc.'
__license__ = 'Apache'
__copyright__ = '(c) 2012 - 2015 Stormpath, Inc.'


# A proxy for the current user.
user = LocalProxy(lambda: _get_user())


class StormpathManager(object):
    """
    This object is used to hold the settings used to communicate with
    Stormpath.  Instances of :class:`StormpathManager` are not bound to
    specific apps, so you can create one in the main body of your code and
    then bind it to your app in a factory function.
    """
    def __init__(self, app=None, csrf=None):
        """
        Initialize this extension.

        :param obj app: (optional) The Flask app.
        :param obj csrf: (optional) CSRFProtect object.
        """
        self.app = app
        self.csrf = csrf

        # If the user specifies an app, let's configure go ahead and handle all
        # configuration stuff for the user's app.
        if app is not None:
            self.init_app(app)

            @app.before_request
            def check_csrf():
                if self.csrf and not request_wants_json():
                    csrf.protect()

    def init_app(self, app):
        """
        Initialize this application.

        This method will handle:

            - Configuring application settings.
            - Configuring Flask-Stormpath.
            - Adding ourself to the user's app (so the user can reference this
              extension later on, if they want).

        :param obj app: The Flask app.
        """
        # Initialize all of the Flask-Stormpath configuration variables and
        # settings.
        self.init_settings(app.config)

        # Initialize the Flask-Login extension.
        self.init_login(app)

        # Initialize all URL routes / views.
        self.init_routes(app)

        # Initialize our blueprint.  This lets us do cool template stuff.
        blueprint = Blueprint(
            'flask_stormpath', 'flask_stormpath', template_folder='templates')
        app.register_blueprint(blueprint)

        # Ensure the `user` context is available in templates.  This makes it
        # really easy for developers to grab user data for display purposes in
        # templates.
        app.context_processor(user_context_processor)

        # Store a reference to the Flask app so we can use it later if
        # necessary!
        self.app = app

    def init_settings(self, config):
        """
        Initialize the Flask-Stormpath settings.

        This function sets all default configuration values.

        :param dict config: The Flask app config.
        """
        # Basic Stormpath credentials and configuration.
        web_config_file = config.get('STORMPATH_CONFIG_PATH')
        config_loader = ConfigLoader(
            load_strategies=[
                LoadFileConfigStrategy(web_config_file),
                LoadAPIKeyConfigStrategy("~/.stormpath/apiKey.properties"),
                LoadFileConfigStrategy("~/.stormpath/stormpath.json"),
                LoadFileConfigStrategy("~/.stormpath/stormpath.yaml"),
                LoadAPIKeyConfigStrategy("./apiKey.properties"),
                LoadFileConfigStrategy("./stormpath.yaml"),
                LoadFileConfigStrategy("./stormpath.json"),
                LoadEnvConfigStrategy(prefix='STORMPATH')
            ],
            post_processing_strategies=[
                LoadAPIKeyFromConfigStrategy(),
                MoveAPIKeyToClientAPIKeyStrategy()
            ],
            validation_strategies=[ValidateClientConfigStrategy()])
        config['stormpath'] = StormpathSettings(config_loader.load())

        # Set csrf default check to False, since our StormpathManager applies
        # custom logic for applying csrf tokens.
        config.setdefault('WTF_CSRF_CHECK_DEFAULT', False)

        # Which fields should be displayed when registering new users?
        config.setdefault('STORMPATH_ENABLE_FACEBOOK', False)
        config.setdefault('STORMPATH_ENABLE_GOOGLE', False)

        # Configure URL mappings.  These URL mappings control which URLs will
        # be used by Flask-Stormpath views.
        config.setdefault('STORMPATH_GOOGLE_LOGIN_URL', '/google')
        config.setdefault('STORMPATH_FACEBOOK_LOGIN_URL', '/facebook')

        # Cache configuration.
        config.setdefault('STORMPATH_CACHE', None)

        # Configure templates.  These template settings control which
        # templates are used to render the Flask-Stormpath views.
        config.setdefault(
            'STORMPATH_BASE_TEMPLATE', 'flask_stormpath/base.html')

        # Social login configuration.
        config.setdefault('STORMPATH_SOCIAL', {})

        # Cookie configuration.
        config.setdefault('STORMPATH_COOKIE_DOMAIN', None)
        config.setdefault('STORMPATH_COOKIE_DURATION', timedelta(days=365))

        # Cookie name (this is not overridable by users, at least
        # not explicitly).
        config.setdefault('REMEMBER_COOKIE_NAME', 'stormpath_token')

        for key, value in config.items():
            if (key.startswith(config['stormpath'].STORMPATH_PREFIX) and
                    key in config['stormpath']):
                config['stormpath'][key] = value

        # Create our custom user agent.  This allows us to see which
        # version of this SDK are out in the wild!
        user_agent = 'stormpath-flask/%s flask/%s' % (
            __version__, flask_version)

        # Instantiate client with apiKey id and secret from config.
        self.client = Client(
            id=self.app.config['stormpath']['client']['apiKey']['id'],
            secret=self.app.config['stormpath']['client']['apiKey']['secret'],
            user_agent=user_agent,
            cache_options=self.app.config['STORMPATH_CACHE'],
        )

        ecfrcs = EnrichClientFromRemoteConfigStrategy(
            client_factory=lambda client: self.client)
        ecfrcs.process(self.app.config['stormpath'].store)
        eifrcs = EnrichIntegrationFromRemoteConfigStrategy(
            client_factory=lambda client: self.client)
        eifrcs.process(self.app.config['stormpath'].store)

        self.application = self.client.applications.get(
            self.app.config['stormpath']['application']['href'])

    def init_login(self, app):
        """
        Initialize the Flask-Login extension.

        We use Flask-Login for managing sessions (primarily), so setting it up
        is necessary.

        :param obj app: The Flask app.
        """
        app.config['REMEMBER_COOKIE_DURATION'] = app.config[
            'STORMPATH_COOKIE_DURATION']
        app.config['REMEMBER_COOKIE_DOMAIN'] = app.config[
            'STORMPATH_COOKIE_DOMAIN']

        app.login_manager = LoginManager(app)
        app.login_manager.user_callback = self.load_user
        app.stormpath_manager = self

        if app.config['stormpath']['web']['login']['enabled']:
            app.login_manager.login_view = 'stormpath.login'

        # Make this Flask session expire automatically.
        app.config['PERMANENT_SESSION_LIFETIME'] = app.config[
            'STORMPATH_COOKIE_DURATION']

    def init_routes(self, app):
        """
        Initialize our built-in routes.

        If the user has enabled the built-in views / routes, they will be
        enabled here.

        This behavior is fully customizable in the user's settings.

        :param obj app: The Flask app.
        """
        if app.config['stormpath']['web']['basePath']:
            base_path = app.config['stormpath']['web']['basePath']
        else:
            base_path = '/'

        if app.config['stormpath']['web']['register']['enabled']:
            app.add_url_rule(
                os.path.join(
                    base_path,
                    app.config['stormpath']['web']['register'][
                        'uri'].strip('/')),
                'stormpath.register',
                RegisterView.as_view('register'),
                methods=['GET', 'POST'],
            )

        if app.config['stormpath']['web']['login']['enabled']:
            app.add_url_rule(
                os.path.join(
                    base_path, app.config['stormpath']['web']['login'][
                        'uri'].strip('/')),
                'stormpath.login',
                LoginView.as_view('login'),
                methods=['GET', 'POST'],
            )

        if app.config['stormpath']['web']['forgotPassword']['enabled']:
            app.add_url_rule(
                os.path.join(
                    base_path,
                    app.config['stormpath']['web']['forgotPassword'][
                        'uri'].strip('/')),
                'stormpath.forgot',
                ForgotPasswordView.as_view('forgot'),
                methods=['GET', 'POST'],
            )
            app.add_url_rule(
                os.path.join(
                    base_path,
                    app.config['stormpath']['web']['changePassword'][
                        'uri'].strip('/')),
                'stormpath.forgot_change',
                ChangePasswordView.as_view('change'),
                methods=['GET', 'POST'],
            )

        if app.config['stormpath']['web']['verifyEmail']['enabled']:
            app.add_url_rule(
                app.config['stormpath']['web']['verifyEmail']['uri'],
                'stormpath.verify',
                VerifyEmailView.as_view('verify'),
                methods=['GET', 'POST'],
            )

        if app.config['stormpath']['web']['logout']['enabled']:
            app.add_url_rule(
                os.path.join(
                    base_path,
                    app.config['stormpath']['web']['logout'][
                        'uri'].strip('/')),
                'stormpath.logout',
                LogoutView.as_view('logout'),
            )

        if app.config['stormpath']['web']['me']['enabled']:
            app.add_url_rule(
                os.path.join(
                    base_path,
                    app.config['stormpath']['web']['me']['uri'].strip('/')),
                'stormpath.me',
                MeView.as_view('me'),
            )

        if app.config['STORMPATH_ENABLE_GOOGLE']:
            app.add_url_rule(
                os.path.join(
                    base_path, app.config['STORMPATH_GOOGLE_LOGIN_URL']),
                'stormpath.google_login',
                GoogleLoginView.as_view('google'),
            )

        if app.config['STORMPATH_ENABLE_FACEBOOK']:
            app.add_url_rule(
                os.path.join(
                    base_path, app.config['STORMPATH_FACEBOOK_LOGIN_URL']),
                'stormpath.facebook_login',
                FacebookLoginView.as_view('facebook'),
            )

    @property
    def login_view(self):
        """
        Return the user's Flask-Login login view, behind the scenes.
        """
        return current_app.login_manager.login_view

    @login_view.setter
    def login_view(self, value):
        """
        Proxy any changes to the user's login view to Flask-Login, behind the
        scenes.
        """
        self.app.login_manager.login_view = value

    @staticmethod
    def load_user(account_href):
        """
        Given an Account href (a valid Stormpath Account URL), return the
        associated User account object (or None).

        :returns: The User object or None.
        """
        user = current_app.stormpath_manager.client.accounts.get(account_href)

        try:
            user._ensure_data()
            user.__class__ = User

            return user
        except StormpathError:
            return None
