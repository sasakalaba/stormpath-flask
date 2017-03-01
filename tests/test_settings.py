"""Tests for our settings stuff."""


from flask_stormpath.settings import (
    StormpathSettings)
from flask_stormpath import __version__ as stormpath_flask_version
from flask import __version__ as flask_version
from .helpers import StormpathTestCase

try:
    from mock import MagicMock, patch
except ImportError:
    from unittest.mock import MagicMock, patch


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

    @patch('requests.sessions.PreparedRequest')
    def test_user_agent(self, PreparedRequest):
        # Ensure that every request sent to the Stormpath API has a proper
        # user agent header.

        # Set mock.
        request_mock = PreparedRequest.return_value.prepare
        request_mock.return_value = MagicMock()

        # Attempt a login using email and password.
        with self.app.test_client() as c:
            c.post('/login', data={
                'login': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })

        # Ensure our login generated a request.
        self.assertEqual(request_mock.call_count, 1)
        call = request_mock._mock_call_args_list[0]

        # Extract the User-Agent header.
        user_agent_header = tuple(call)[1]['headers']['User-Agent']

        # Ensure that stormpath-flask and flask version are included in
        # user-agent string.
        stormpath_flask_version_str = (
            'stormpath-flask/%s' % stormpath_flask_version)
        flask_version_str = 'flask/%s' % flask_version
        self.assertTrue(stormpath_flask_version_str in user_agent_header)
        self.assertTrue(flask_version_str in user_agent_header)
