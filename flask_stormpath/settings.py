"""Helper functions for dealing with Flask-Stormpath settings."""

import collections
import json


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

    def __contains__(self, key):
        try:
            # FIXME: passwordPolicy breaks the code, in
            # stormpath-python-config.stormpath_config:strategies._enrich_with_directory_policies
            # self.__nodematch__(key)
            self[key]
            return True
        except KeyError:
            return False

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)
