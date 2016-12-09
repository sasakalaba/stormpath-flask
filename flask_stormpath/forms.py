"""Helper forms which make handling common operations simpler."""


from flask_wtf import FlaskForm
from wtforms.widgets import HiddenInput
from wtforms.fields import PasswordField, StringField
from wtforms.validators import InputRequired, EqualTo, Email
from stormpath.resources import Resource
import json


class StormpathForm(FlaskForm):
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

        field_list = config.get('fields', {})
        field_order = config.get('fieldOrder', [])

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

                # Apply widgets.
                if not field_list[field]['visible']:
                    widget = HiddenInput()
                else:
                    widget = None
                json_field['visible'] = field_list[field]['visible']

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
                        render_kw={"placeholder": placeholder},
                        widget=widget))

        return cls

    @property
    def json(self):
        return json.dumps(self._json)
