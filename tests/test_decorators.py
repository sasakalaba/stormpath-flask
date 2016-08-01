"""Run tests against our custom decorators."""


from flask.ext.stormpath.decorators import groups_required
from .helpers import StormpathTestCase


class TestGroupsRequired(StormpathTestCase):

    def setUp(self):
        """Provision a single user account and some groups for testing."""
        # Call the parent setUp method first -- this will bootstrap our tests.
        super(TestGroupsRequired, self).setUp()

        with self.app.app_context():
            # Create two groups.
            self.admins = self.application.groups.create({
                'name': 'admins',
            })
            self.developers = self.application.groups.create({
                'name': 'developers',
            })

    def test_defaults_to_all(self):
        @self.app.route('/test')
        @groups_required(['admins', 'developers'])
        def some_view():
            """
            A view which requires a user to be a member of both the admins and
            developers groups to gain access.
            """
            return 'hello, world'

        with self.app.test_client() as c:

            # Log our user in.
            c.post('/login', data={
                'login': self.user.email,
                'password': 'woot1LoveCookies!',
            })

            # Ensure our user can't access the test view since he isn't a
            # member of the required groups (he should get redirected to the
            # login page).
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/login', resp.headers['Location'])

            # Add our user to only one of the required groups.
            self.user.add_group(self.admins)

            # Ensure our user can't access the test view since he isn't a
            # member of the required groups (he should get redirected to the
            # login page).
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/login', resp.headers['Location'])

            # Add our user to the last required group.
            self.user.add_group(self.developers)

            # Ensure our user can now access the test view since he was added
            # to both groups.
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 200)

    def test_all_can_be_disabled(self):
        @self.app.route('/test')
        @groups_required(['admins', 'developers'], all=False)
        def some_view():
            """
            A view which requires a user to be a member of at least one group:
            either admins or developers.
            """
            return 'hello, world'

        with self.app.test_client() as c:

            # Log our user in.
            c.post('/login', data={
                'login': self.user.email,
                'password': 'woot1LoveCookies!',
            })

            # Ensure our user can't access the test view since he isn't a
            # member of the required groups (he should get redirected to the
            # login page).
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/login', resp.headers['Location'])

            # Add our user to only one of the required groups.
            self.user.add_group(self.admins)

            # Ensure our user can now access the test view since he was added
            # to one of the required groups.
            resp = c.get('/test')
            self.assertEqual(resp.status_code, 200)
