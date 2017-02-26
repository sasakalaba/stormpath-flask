"""Run tests against our custom request processors."""

from flask import current_app
from .helpers import StormpathTestCase, HttpAcceptWrapper
from stormpath_config.errors import ConfigurationError
from flask_stormpath.request_processors import (
    get_accept_header,
    request_wants_json
)


class TestRequestProcessor(StormpathTestCase):
    """Test request_processor functions."""

    def test_get_accept_header(self):
        # Ensure that get_accept_header will return a proper accept header.

        with self.app.app_context():
            allowed_types = current_app.config['stormpath']['web']['produces']

        with self.app.test_client() as c:
            # HTML header.
            c.get('/')
            self.assertEqual(get_accept_header(), 'text/html')

            # JSON header.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)
            c.get('/')
            self.assertEqual(get_accept_header(), 'application/json')

            # Accept header empty.
            self.app.wsgi_app = HttpAcceptWrapper(self.default_wsgi_app, None)
            c.get('/')
            self.assertEqual(get_accept_header(), allowed_types[0])

            # Accept header */*.
            self.app.wsgi_app = HttpAcceptWrapper(self.default_wsgi_app, '*/*')
            c.get('/')
            self.assertEqual(get_accept_header(), allowed_types[0])

        # Ensure that get_accept_header will throw an error if called from
        # outside application context or without stormpath config.
        with self.assertRaises(ConfigurationError) as error:
            get_accept_header()
        self.assertEqual(
            error.exception.message,
            'You must initialize flask app before calling this function.')

    def test_request_wants_json(self):
        # Ensure that a request with a json accept header will return a
        # json response.

        with self.app.test_client() as c:
            # JSON header.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.json_header)
            c.get('/')
            self.assertTrue(request_wants_json())

            # HTML header
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, self.html_header)
            c.get('/')
            self.assertFalse(request_wants_json())

            # If the accept header is empty, get_accept_header will return
            # the first type in produces list, which is currently set to json.
            self.app.wsgi_app = HttpAcceptWrapper(
                self.default_wsgi_app, None)
            c.get('/')
            self.assertEqual(
                current_app.config['stormpath']['web']['produces'][0],
                'application/json')
            self.assertTrue(request_wants_json())
