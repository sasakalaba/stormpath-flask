"""Run tests against our custom context processors."""


from flask_stormpath import User, user
from flask_stormpath.context_processors import user_context_processor
from .helpers import StormpathTestCase


class TestUserContextProcessor(StormpathTestCase):
    def test_raw_works(self):
        with self.app.test_client() as c:
            c.post('/login', data={
                'login': self.user.email,
                'password': 'woot1LoveCookies!',
            })

            self.assertIsInstance(user_context_processor(), dict)
            self.assertTrue(user_context_processor().get('user'))
            self.assertIsInstance(user_context_processor()['user'], User)

    def test_works(self):
        with self.app.test_client() as c:
            c.post('/login', data={
                'login': self.user.email,
                'password': 'woot1LoveCookies!',
            })

            self.assertEqual(user.href, self.user.href)
