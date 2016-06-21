"""Helper forms which make handling common operations simpler."""


from flask.ext.wtf import Form
from wtforms.fields import PasswordField, StringField
from wtforms.validators import InputRequired, ValidationError, EqualTo, Email
from stormpath.resources import Resource
import json


class StormpathForm(Form):
    @classmethod
    def specialize_form(basecls, config):
        """
        Dynamic form.

        This class is used to set fields dynamically based on the form fields
        settings from the config.

        .. note::
            This doesn't include support for Stormpath's social login stuff.
            Since social login stuff is handled separately (through
            Javascript), we don't need to have a form for registering/logging
            in users that way.
        """

        class cls(basecls):
            # Make sure that the original class is left unaltered.
            pass

        field_list = config['fields']
        field_order = config['fieldOrder']

        setattr(cls, '_json', [])

        for field in field_order:
            if field_list[field]['enabled']:
                validators = []
                placeholder = field_list[field]['placeholder']

                # Construct json fields
                json_field = {'name': Resource.from_camel_case(field)}
                json_field['placeholder'] = placeholder

                # Apply validators.
                if field_list[field]['required']:
                    validators.append(InputRequired(
                        message='%s is required.' % placeholder))

                if field_list[field]['type'] == 'email':
                    validators.append(Email(
                        message='Email must be in valid format.'))

                if field == 'confirmPassword':
                    validators.append(EqualTo(
                        'password', message='Passwords do not match.'))
                json_field['required'] = field_list[field]['required']

                # Apply field classes.
                if field_list[field]['type'] == 'password':
                    field_class = PasswordField
                else:
                    field_class = StringField
                json_field['type'] = field_list[field]['type']

                # Apply labels.
                if 'label' in field_list[field] and isinstance(
                        field_list[field]['label'], str):
                    label = field_list[field]['label']
                else:
                    label = ''
                json_field['label'] = field_list[field]['label']

                # Set json fields.
                cls._json.append(json_field)

                # Finally, create our fields dynamically.
                setattr(
                    cls, Resource.from_camel_case(field),
                    field_class(
                        label, validators=validators,
                        render_kw={"placeholder": placeholder}))

        return cls

    @property
    def json(self):
        return json.dumps(self._json)


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
