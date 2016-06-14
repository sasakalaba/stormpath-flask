"""Helper forms which make handling common operations simpler."""

import json
from collections import OrderedDict

from flask import current_app
from flask.ext.wtf import Form
from wtforms.fields import PasswordField, StringField
from wtforms.validators import InputRequired, ValidationError, EqualTo
from stormpath.resources import Resource


class StormpathForm(Form):
    @classmethod
    def append_fields(cls, config):
        """
        Dynamic form.

        This class is used to set fields dynamically on our form class based
        on the form fields settings from the config.

        .. note::
            This doesn't include support for Stormpath's social login stuff.

            Since social login stuff is handled separately (through
            Javascript), we don't need to have a form for
            registering/logging in users that way.

        """
        field_list = config['fields']
        field_order = config['fieldOrder']

        for field in field_order:
            if field_list[field]['enabled']:
                validators = []

                if field_list[field]['required']:
                    validators.append(InputRequired())

                if field_list[field]['type'] == 'password':
                    field_class = PasswordField
                else:
                    field_class = StringField

                if 'label' in field_list[field] and isinstance(
                        field_list[field]['label'], str):
                    label = field_list[field]['label']
                else:
                    label = ''

                placeholder = field_list[field]['placeholder']

                setattr(
                    cls, Resource.from_camel_case(field),
                    field_class(
                        label, validators=validators,
                        render_kw={"placeholder": placeholder}))

        return cls


class ForgotPasswordForm(Form):
    """
    Retrieve a user's email address for initializing the password reset
    workflow.

    This class is used to retrieve a user's email address.
    """
    email = StringField('Email', validators=[InputRequired()])


class ChangePasswordForm(Form):
    """
    Change a user's password.

    This class is used to retrieve a user's password twice to ensure it's valid
    before making a change.
    """
    password = PasswordField('Password', validators=[InputRequired()])
    password_again = PasswordField(
        'Password (again)', validators=[InputRequired()])

    def validate_password_again(self, field):
        """
        Ensure both password fields match, otherwise raise a ValidationError.

        :raises: ValidationError if passwords don't match.
        """
        if self.password.data != field.data:
            raise ValidationError("Passwords don't match.")


class VerificationForm(Form):
    """
    Verify a user's email.

    This class is used to Verify a user's email address
    """
    email = StringField('Email', validators=[InputRequired()])
