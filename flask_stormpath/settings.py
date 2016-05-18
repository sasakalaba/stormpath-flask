"""Helper functions for dealing with Flask-Stormpath settings."""

import os
from datetime import timedelta

# FIXME: cannot install stormpath_config via pip
import sys
sys.path.insert(0, '/home/sasa/Projects/stormpath/stormpath-python-config')

from stormpath_config.loader import ConfigLoader
from stormpath_config.strategies import (
    LoadEnvConfigStrategy, LoadFileConfigStrategy, LoadAPIKeyConfigStrategy,
    LoadAPIKeyFromConfigStrategy, ValidateClientConfigStrategy,
    #MoveAPIKeyToClientAPIKeyStrategy,
    EnrichClientFromRemoteConfigStrategy)


from .errors import ConfigurationError

import collections


class StormpathSettings(collections.MutableMapping):
    STORMPATH_PREFIX = 'STORMPATH'
    DELIMITER = '_'
    REGEX_SIGN = '*'
    MAPPINGS = {  # used for backwards compatibility
        'API_KEY_ID': 'client_apiKey_id',
        'API_KEY_SECRET': 'client_apiKey_secret',
        'APPLICATION': 'application_name',

        'ENABLE_LOGIN': 'web_login_enabled',
        'ENABLE_REGISTRATION': 'web_register_enabled',
        'ENABLE_FORGOT_PASSWORD': 'web_forgotPassword_enabled',

        'LOGIN_URL': 'web_login_uri',
        'REGISTRATION_URL': 'web_register_uri',
        'LOGOUT_URL': 'web_logout_uri',

        'REDIRECT_URL': 'web_login_nextUri',

        'REGISTRATION_TEMPLATE': 'web_register_template',
        'LOGIN_TEMPLATE': 'web_login_template',

        'REGISTRATION_REDIRECT_URL': 'web_register_nextUri',
        'REQUIRE_*': 'web_register_form_fields_*_required',
        'ENABLE_*': 'web_register_form_fields_*_enabled',

        'FORGOT_PASSWORD_TEMPLATE': 'web_forgotPassword_template',
        'FORGOT_PASSWORD_CHANGE_TEMPLATE': 'web_changePassword_template'
        # 'FORGOT_PASSWORD_EMAIL_SENT_TEMPLATE'
        # 'FORGOT_PASSWORD_COMPLETE_TEMPLATE'
        # 'ENABLE_FACEBOOK'
        # 'ENABLE_GOOGLE'
        # 'SOCIAL'
        # 'CACHE'
    }

    def __init__(self, *args, **kwargs):
        self.store = dict(*args, **kwargs)

    @staticmethod
    def _from_camel(key):
        cs = []
        for c in key:
            cl = c.lower()
            if c == cl:
                cs.append(c)
            else:
                cs.append('_')
                cs.append(c.lower())
        return ''.join(cs).upper()

    def __search__(self, root, key, root_string):
        for node in root.keys():
            search_string = '%s%s%s' % (
                root_string, self.DELIMITER,
                self._from_camel(node)
            )
            if key == search_string:
                return root, node
            if key.startswith(search_string):
                return self.__search__(root[node], key, search_string)
        raise KeyError

    def __traverse__(self, parent, descendants):
        child = descendants.pop(0)
        if descendants:
            if child not in parent:
                parent[child] = {}
            return self.__traverse__(parent[child], descendants)
        return parent, child

    def __nodematch__(self, key):
        if key.startswith(self.STORMPATH_PREFIX):
            store_key = key.lstrip(self.STORMPATH_PREFIX).strip(self.DELIMITER)
            if store_key in self.MAPPINGS:
                members = self.MAPPINGS[store_key].split(self.DELIMITER)
                store = self.__traverse__(self.store, members)
            else:
                store = self.__search__(self.store, key, self.STORMPATH_PREFIX)
        else:
            store = self.store, key
        return store

    def __getitem__(self, key):
        node, child = self.__nodematch__(key)
        return node[child]

    def __setitem__(self, key, value):
        node, child = self.__nodematch__(key)
        node[child] = value

    def __delitem__(self, key):
        node, child = self.__keytransform__(key)
        del node[child]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)


def init_settings(config):
    """
    Initialize the Flask-Stormpath settings.

    This function sets all default configuration values.

    :param dict config: The Flask app config.
    """
    # Basic Stormpath credentials and configuration.
    web_config_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'config/default-config.yml')
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
            LoadAPIKeyFromConfigStrategy(), #MoveAPIKeyToClientAPIKeyStrategy()
        ],
        validation_strategies=[ValidateClientConfigStrategy()])
    config['stormpath'] = StormpathSettings(config_loader.load())

    # Most of the settings are used for backwards compatibility.
    config.setdefault('STORMPATH_API_KEY_ID', None)
    config.setdefault('STORMPATH_API_KEY_SECRET', None)
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_API_KEY_FILE', None)
    config.setdefault('STORMPATH_APPLICATION', None)

    # Which fields should be displayed when registering new users?
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_ENABLE_FACEBOOK', False)
    # config.setdefault('STORMPATH_ENABLE_GOOGLE', False)
    # config.setdefault('STORMPATH_ENABLE_EMAIL', True)  # If this is diabled,
                                                       # only social login can
                                                       # be used.

    # Will new users be required to verify new accounts via email before
    # they're made active?
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_VERIFY_EMAIL', False)

    # Configure URL mappings.  These URL mappings control which URLs will be
    # used by Flask-Stormpath views.
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_GOOGLE_LOGIN_URL', '/google')
    # config.setdefault('STORMPATH_FACEBOOK_LOGIN_URL', '/facebook')

    # After a successful login, where should users be redirected?
    config.setdefault('STORMPATH_REDIRECT_URL', '/')

    # Cache configuration.
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_CACHE', None)

    # Configure templates.  These template settings control which templates are
    # used to render the Flask-Stormpath views.
    # FIXME: some of the settings break the code because they're not in the spec
    # config.setdefault('STORMPATH_BASE_TEMPLATE', 'flask_stormpath/base.html')
    config.setdefault('STORMPATH_REGISTRATION_TEMPLATE', 'flask_stormpath/register.html')
    config.setdefault('STORMPATH_LOGIN_TEMPLATE', 'flask_stormpath/login.html')
    config.setdefault('STORMPATH_FORGOT_PASSWORD_TEMPLATE', 'flask_stormpath/forgot.html')
    # config.setdefault('STORMPATH_FORGOT_PASSWORD_EMAIL_SENT_TEMPLATE', 'flask_stormpath/forgot_email_sent.html')
    config.setdefault('STORMPATH_FORGOT_PASSWORD_CHANGE_TEMPLATE', 'flask_stormpath/forgot_change.html')
    # config.setdefault('STORMPATH_FORGOT_PASSWORD_COMPLETE_TEMPLATE', 'flask_stormpath/forgot_complete.html')

    # Social login configuration.
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_SOCIAL', {})

    # Cookie configuration.
    # FIXME: this breaks the code because it's not in the spec
    # config.setdefault('STORMPATH_COOKIE_DOMAIN', None)
    # config.setdefault('STORMPATH_COOKIE_DURATION', timedelta(days=365))

    # Cookie name (this is not overridable by users, at least not explicitly).
    config.setdefault('REMEMBER_COOKIE_NAME', 'stormpath_token')

    for key, value in config.items():
        if key.startswith(config['stormpath'].STORMPATH_PREFIX):
            config['stormpath'][key] = value


def check_settings(config):
    """
    Ensure the user-specified settings are valid.

    This will raise a ConfigurationError if anything mandatory is not
    specified.

    :param dict config: The Flask app config.
    """
    # FIXME: this needs to be uncommented based on settings in init_settings
    # if config['STORMPATH_ENABLE_GOOGLE']:
    #     google_config = config['STORMPATH_SOCIAL'].get('GOOGLE')

    #     if not google_config or not all([
    #         google_config.get('client_id'),
    #         google_config.get('client_secret'),
    #     ]):
    #         raise ConfigurationError('You must define your Google app settings.')

    # if config['STORMPATH_ENABLE_FACEBOOK']:
    #     facebook_config = config['STORMPATH_SOCIAL'].get('FACEBOOK')

    #     if not facebook_config or not all([
    #         facebook_config,
    #         facebook_config.get('app_id'),
    #         facebook_config.get('app_secret'),
    #     ]):
    #         raise ConfigurationError('You must define your Facebook app settings.')

    # if config['STORMPATH_COOKIE_DOMAIN'] and not isinstance(config['STORMPATH_COOKIE_DOMAIN'], str):
    #     raise ConfigurationError('STORMPATH_COOKIE_DOMAIN must be a string.')

    # if config['STORMPATH_COOKIE_DURATION'] and not isinstance(config['STORMPATH_COOKIE_DURATION'], timedelta):
    #     raise ConfigurationError('STORMPATH_COOKIE_DURATION must be a timedelta object.')
