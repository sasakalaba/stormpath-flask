"""Tests for our settings stuff."""


from datetime import timedelta
from unittest import skip
from flask_stormpath.errors import ConfigurationError
from flask_stormpath.settings import (
    StormpathSettings)
from .helpers import StormpathTestCase


class TestInitSettings(StormpathTestCase):
    """Ensure we can properly initialize Flask app settings."""

    def test_works(self):
        self.manager.init_settings(self.app.config)

        # Ensure a couple of settings exist that we didn't explicitly specify
        # anywhere.
        self.assertEqual(self.app.config['stormpath'][
            'STORMPATH_WEB_REGISTER_ENABLED'], True)
        self.assertEqual(self.app.config['stormpath'][
            'STORMPATH_WEB_LOGIN_ENABLED'], True)

    def test_helpers(self):
        self.manager.init_settings(self.app.config)
        settings = self.app.config['stormpath']

        self.assertEqual(settings._from_camel('givenName'), 'GIVEN_NAME')
        self.assertEqual(settings._from_camel('given_name'), 'GIVEN_NAME')
        self.assertNotEqual(settings._from_camel('GivenName'), 'GIVEN_NAME')

        settings.store = {
            'application': {
                'name': 'StormpathApp'
            }
        }

        # test key search
        node, child = settings.__search__(
            settings.store, 'STORMPATH_APPLICATION_NAME', 'STORMPATH')
        self.assertEqual(node, settings.store['application'])
        self.assertEqual(node[child], settings.store['application']['name'])

        # key node matching with no direct mapping
        node, child = settings.__nodematch__('STORMPATH_APPLICATION_NAME')
        self.assertEqual(node, settings.store['application'])
        self.assertEqual(node[child], settings.store['application']['name'])

        # key node matching with direct mapping
        node, child = settings.__nodematch__('STORMPATH_APPLICATION')
        self.assertEqual(node, settings.store['application'])
        self.assertEqual(node[child], settings.store['application']['name'])

    def test_settings_init(self):
        self.manager.init_settings(self.app.config)
        settings = self.app.config['stormpath']

        # flattened settings with direct mapping
        settings['STORMPATH_APPLICATION'] = 'StormpathApp'
        self.assertEqual(settings.store['application']['name'], 'StormpathApp')
        self.assertEqual(settings.get('STORMPATH_APPLICATION'), 'StormpathApp')
        self.assertEqual(settings['STORMPATH_APPLICATION'], 'StormpathApp')
        self.assertEqual(settings.get('application')['name'], 'StormpathApp')
        self.assertEqual(settings['application']['name'], 'StormpathApp')

    def test_set(self):
        settings = StormpathSettings()
        # flattened setting wasn't defined during init
        with self.assertRaises(KeyError):
            settings['STORMPATH_WEB_SETTING'] = 'StormWebSetting'

        # flattened setting defined during init
        settings = StormpathSettings(web={'setting': 'StormSetting'})
        settings['STORMPATH_WEB_SETTING'] = 'StormWebSetting'
        self.assertEqual(
            settings['web']['setting'], 'StormWebSetting')
        # dict setting defined during init
        settings = StormpathSettings(web={'setting': 'StormSetting'})
        settings['web']['setting'] = 'StormWebSetting'
        self.assertEqual(
            settings['web']['setting'], 'StormWebSetting')

        # overriding flattened setting
        settings = StormpathSettings(web={'setting': 'StormSetting'})
        settings['STORMPATH_WEB'] = 'StormWebSetting'
        self.assertEqual(settings['web'], 'StormWebSetting')
        # overriding dict setting
        settings = StormpathSettings(web={'setting': 'StormSetting'})
        settings['web'] = 'StormWebSetting'
        self.assertEqual(settings['web'], 'StormWebSetting')

    def test_get(self):
        self.manager.init_settings(self.app.config)
        settings = self.app.config['stormpath']

        register_setting = {
            'enabled': True,
            'form': {
                'fields': {
                    'givenName': {
                        'enabled': True
                    }
                }
            }
        }

        # flattened setting without mappings
        settings['STORMPATH_WEB_REGISTER'] = register_setting
        self.assertEqual(
            settings.get('STORMPATH_WEB_REGISTER'), register_setting)
        self.assertEqual(settings['STORMPATH_WEB_REGISTER'], register_setting)
        self.assertEqual(settings.get('web')['register'], register_setting)
        self.assertEqual(settings['web']['register'], register_setting)

        # dict setting without mappings
        settings['web']['register'] = register_setting
        self.assertEqual(
            settings.get('STORMPATH_WEB_REGISTER'), register_setting)
        self.assertEqual(settings['STORMPATH_WEB_REGISTER'], register_setting)
        self.assertEqual(settings.get('web')['register'], register_setting)
        self.assertEqual(settings['web']['register'], register_setting)

    def test_del(self):
        self.manager.init_settings(self.app.config)
        settings = self.app.config['stormpath']
        register_setting = {
            'enabled': True,
            'form': {
                'fields': {
                    'givenName': {
                        'enabled': True
                    }
                }
            }
        }
        settings['STORMPATH_WEB_REGISTER'] = register_setting
        del settings['web']['register']
        with self.assertRaises(KeyError):
            settings['STORMPATH_WEB_REGISTER']

    def test_camel_case(self):
        web_settings = {
            'register': {
                'enabled': True,
                'form': {
                    'fields': {
                        'givenName': {
                            'enabled': True
                        }
                    }
                }
            }
        }

        settings = StormpathSettings(web=web_settings)
        self.assertTrue(settings['web']['register']['form']['fields'][
            'givenName']['enabled'])
        self.assertTrue(
            settings['STORMPATH_WEB_REGISTER_FORM_FIELDS_GIVEN_NAME_ENABLED'])
        settings[
            'STORMPATH_WEB_REGISTER_FORM_FIELDS_GIVEN_NAME_ENABLED'] = False
        self.assertFalse(settings['web']['register']['form']['fields'][
            'givenName']['enabled'])
        self.assertFalse(
            settings['STORMPATH_WEB_REGISTER_FORM_FIELDS_GIVEN_NAME_ENABLED'])
        settings[
            'web']['register']['form']['fields']['givenName']['enabled'] = True
        self.assertTrue(settings['web']['register']['form']['fields'][
            'givenName']['enabled'])
        self.assertTrue(
            settings['STORMPATH_WEB_REGISTER_FORM_FIELDS_GIVEN_NAME_ENABLED'])


class TestCheckSettings(StormpathTestCase):
    """Ensure our settings checker is working properly."""

    def test_google_settings(self):
        # Disable facebook login for this test.
        self.app.config['STORMPATH_ENABLE_FACEBOOK'] = False

        # Ensure that things don't work if not all social configs are
        # specified.
        self.app.config['STORMPATH_SOCIAL'] = {}
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        self.app.config['STORMPATH_SOCIAL'] = {'GOOGLE': {}}
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        self.app.config['STORMPATH_SOCIAL']['GOOGLE']['client_id'] = 'xxx'
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        # Now that we've configured things properly, it should work.
        self.app.config['STORMPATH_SOCIAL']['GOOGLE']['client_secret'] = 'xxx'
        self.manager.check_settings(self.app.config)

    def test_facebook_settings(self):
        # Disable google login for this test.
        self.app.config['STORMPATH_ENABLE_GOOGLE'] = False

        # Ensure that things don't work if not all social configs are
        # specified.
        self.app.config['STORMPATH_SOCIAL'] = {}
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        self.app.config['STORMPATH_SOCIAL'] = {'FACEBOOK': {}}
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        self.app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_id'] = 'xxx'
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        # Now that we've configured things properly, it should work.
        self.app.config['STORMPATH_SOCIAL']['FACEBOOK']['app_secret'] = 'xxx'
        self.manager.check_settings(self.app.config)

    def test_cookie_settings(self):
        # Ensure that if a user specifies a cookie domain which isn't a string,
        # an error is raised.
        self.app.config['STORMPATH_COOKIE_DOMAIN'] = 1
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        # Now that we've configured things properly, it should work.
        self.app.config['STORMPATH_COOKIE_DOMAIN'] = 'test'
        self.manager.check_settings(self.app.config)

        # Ensure that if a user specifies a cookie duration which isn't a
        # timedelta object, an error is raised.
        self.app.config['STORMPATH_COOKIE_DURATION'] = 1
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)

        # Now that we've configured things properly, it should work.
        self.app.config['STORMPATH_COOKIE_DURATION'] = timedelta(minutes=1)
        self.manager.check_settings(self.app.config)

    @skip('This will be fixed once the verifyEmail view is finished.')
    def test_verify_email_autologin(self):
        # stormpath.web.register.autoLogin is true, but the default account
        # store of the specified application has the email verification
        # workflow enabled. Auto login is only possible if email verification
        # is disabled
        self.app.config['stormpath']['web']['verifyEmail']['enabled'] = True
        self.app.config['stormpath']['web']['register']['autoLogin'] = True
        with self.assertRaises(ConfigurationError) as config_error:
            self.manager.check_settings(self.app.config)
        self.assertEqual(config_error.exception.message, (
            'Invalid configuration: stormpath.web.register.autoLogin is' +
            ' true, but the default account store of the specified' +
            ' application has the email verification workflow enabled.' +
            ' Auto login is only possible if email verification is' +
            ' disabled. Please disable this workflow on this' +
            ' application\'s default account store.'))

        # Now that we've configured things properly, it should work.
        self.app.config['stormpath']['web']['verifyEmail']['enabled'] = False
        self.manager.check_settings(self.app.config)

    def test_register_default_account_store(self):
        # Ensure that proper configuration won't raise an error.
        self.manager.check_settings(self.app.config)

        # Ensure that an application without an account store will raise an
        #  error.
        self.app.config['stormpath']['web']['register']['enabled'] = False
        app = self.client.applications.get(
            self.app.config['stormpath']['application']['href'])
        app.default_account_store_mapping.delete()
        self.assertRaises(
            ConfigurationError, self.manager.check_settings, self.app.config)
