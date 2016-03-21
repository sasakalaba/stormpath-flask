"""Helper forms which make handling common operations simpler."""

from flask import current_app
from flask.ext.wtf import Form
from wtforms.fields import PasswordField, StringField
from wtforms.validators import InputRequired, ValidationError
from stormpath.resources import Resource


class StormpathForm(Form):
    def __init__(self, config, *args, **kwargs):
        super(StormpathForm, self).__init__(*args, **kwargs)
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
                    self.__class__, Resource.from_camel_case(field),
                    field_class(
                        label, validators=validators,
                        render_kw={"placeholder": placeholder}))


class RegistrationForm(StormpathForm):
    """
    Register a new user.

    This class is used to provide safe user registration.  The only required
    fields are `email` and `password` -- everything else is optional (and can
    be configured by the developer to be used or not).

    .. note::
        This form only includes the fields that are available to register
        users with Stormpath directly -- this doesn't include support for
        Stormpath's social login stuff.

        Since social login stuff is handled separately (registration happens
        through Javascript) we don't need to have a form for registering users
        that way.
    """
    def __init__(self, *args, **kwargs):
        form_config = current_app.config['stormpath']['web']['register']['form']
        super(RegistrationForm, self).__init__(form_config, *args, **kwargs)


class LoginForm(StormpathForm):
    """
    Log in an existing user.

    This class is used to provide safe user login.  A user can log in using
    a login identifier (either email or username) and password.  Stormpath
    handles the username / email abstractions itself, so we don't need any
    special logic to handle those cases.

    .. note::
        This form only includes the fields that are available to log users in
        with Stormpath directly -- this doesn't include support for Stormpath's
        social login stuff.

        Since social login stuff is handled separately (login happens through
        Javascript) we don't need to have a form for logging in users that way.
    """
    def __init__(self, *args, **kwargs):
        form_config = current_app.config['stormpath']['web']['login']['form']
        super(LoginForm, self).__init__(form_config, *args, **kwargs)


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
    password_again = PasswordField('Password (again)', validators=[InputRequired()])

    def validate_password_again(self, field):
        """
        Ensure both password fields match, otherwise raise a ValidationError.

        :raises: ValidationError if passwords don't match.
        """
        if self.password.data != field.data:
            raise ValidationError("Passwords don't match.")
