"""Tests for our custom forms."""


from .helpers import StormpathTestCase
from flask_stormpath.forms import StormpathForm
from wtforms.fields import PasswordField, StringField
from wtforms.validators import InputRequired, Email, EqualTo
from stormpath.resources import Resource


class TestStormpathForm(StormpathTestCase):
    """Test the StormpathForm."""

    def assertFormFields(self, form, config):
        # Iterate through form config and check if the settings are
        # properly applied to our form class.

        for field in config['fieldOrder']:
            # Convert the key to underscore format
            form_field = Resource.from_camel_case(field)

            if config['fields'][field]['enabled']:
                # Check if all enabled fields are set.
                self.assertTrue(hasattr(form, form_field))

                # Get validators.
                validators = getattr(form, form_field).kwargs.get(
                    'validators')

                # Check if field type is set.
                if config['fields'][field]['type'] == 'text':
                    self.assertTrue(getattr(
                        form, form_field).field_class, StringField)
                elif config['fields'][field]['type'] == 'password':
                    self.assertTrue(getattr(
                        form, form_field).field_class, PasswordField)
                elif config['fields'][field]['type'] == 'email':
                    self.assertTrue(any(isinstance(
                        validator, Email) for validator in validators))

                # Check if required validator is set.
                if config['fields'][field]['required']:
                    self.assertTrue(any(isinstance(
                        validator, InputRequired) for validator in validators))

                # If 'confirmPassword' field is enabled, check that the proper
                # validator is applied.
                if (field == 'confirmPassword' and config['fields'][field][
                        'enabled']):
                    self.assertTrue(any(isinstance(
                        validator, EqualTo) for validator in validators))

                # Check if placeholders are set.
                placeholder = config['fields'][field].get('placeholder')
                if placeholder:
                    self.assertTrue(getattr(
                        form, form_field).kwargs['render_kw']['placeholder'],
                        config['fields'][field]['placeholder'])

                # Check if labels are set.
                label = config['fields'][field].get('label')
                if label:
                    self.assertTrue(getattr(form, form_field).args[0], config[
                        'fields'][field]['label'])

    def test_login_form_building(self):
        # Check if the login form is built as specified in the config file.
        form_config = self.app.config['stormpath']['web']['login']['form']

        with self.app.app_context():
            form = StormpathForm.specialize_form(form_config)
            self.assertFormFields(form, form_config)

            # Check to see if the StormpathFrom base class is left unaltered
            # after form building.
            new_form = StormpathForm()
            field_diff = list(set(form_config['fieldOrder']) - set(
                dir(new_form)))
            self.assertEqual(field_diff, form_config['fieldOrder'])

    def test_registration_form_building(self):
        # Check if the registration form is built as specified in the config
        # file.
        form_config = self.app.config['stormpath']['web']['register']['form']
        form_config['fields']['confirmPassword']['enabled'] = True

        with self.app.app_context():
            form = StormpathForm.specialize_form(form_config)
            self.assertFormFields(form, form_config)

            # Check to see if the StormpathFrom base class is left unaltered
            # after form building.
            new_form = StormpathForm()
            field_diff = list(set(form_config['fieldOrder']) - set(
                dir(new_form)))
            self.assertEqual(set(field_diff), set(form_config['fieldOrder']))

    def test_error_messages(self):
        # FIX ME: mozda ne samo koristiti register formu, mozda se rijesi
        # ako kostistis samo StormpathFormu
        form_config = self.app.config['stormpath']['web']['register']['form']

        # We are creating requests, since wtforms pass request.form to form
        # init automatically.
        with self.app.test_client() as c:
            # Ensure that an error is raised if a required field is left
            # empty.
            c.post('', data={
                'username': 'rdegges',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
            })
            form = StormpathForm.specialize_form(form_config)()
            self.assertFalse(form.validate_on_submit())
            self.assertTrue(form.errors, {
                'given_name': ['First Name is required.']})

            # Ensure that an error is raised if the email format is invalid.
            c.post('', data={
                'username': 'rdegges',
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'rrdegges.com',
                'password': 'woot1LoveCookies!',
            })
            form = StormpathForm.specialize_form(form_config)()
            self.assertFalse(form.validate_on_submit())
            self.assertTrue(form.errors, {
                'email': ['Email must be in valid format.']})

            # Ensure that an error is raised if confirm password is enabled
            # the two passwords mismatch.
            form_config['fields']['confirmPassword']['enabled'] = True

            c.post('', data={
                'username': 'rdegges',
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
                'confirm_password': 'woot1LoveCookies!...NOT!!'
            })
            form = StormpathForm.specialize_form(form_config)()
            self.assertFalse(form.validate_on_submit())
            self.assertTrue(form.errors, {
                'confirm_password': ['Passwords do not match.']})

            # Ensure that proper form will result in success.
            c.post('', data={
                'username': 'rdegges',
                'given_name': 'Randall',
                'surname': 'Degges',
                'email': 'r@rdegges.com',
                'password': 'woot1LoveCookies!',
                'confirm_password': 'woot1LoveCookies!'
            })
            form = StormpathForm.specialize_form(form_config)()
            self.assertTrue(form.validate_on_submit())

            # Ensure that enabled but optional fields won't cause an error.
            form_config['fields']['givenName']['required'] = False

            c.post('', data={
                'username': 'rdegges2',
                'surname': 'Degges2',
                'email': 'r@rdegges2.com',
                'password': 'woot1LoveCookies!2',
                'confirm_password': 'woot1LoveCookies!2'
            })
            form = StormpathForm.specialize_form(form_config)()
            self.assertTrue(form.validate_on_submit())
