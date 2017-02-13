"""Description here."""

from flask import request, current_app
from .errors import ConfigurationError


def get_accept_header():
    """
    Fetch the request content type and match it against our allowed types.
    """
    if current_app and 'stormpath' in current_app.config:
        allowed_types = current_app.config['stormpath']['web']['produces']
        request_accept_types = request.accept_mimetypes

        # If no accept types are specified, or the preferred accept type is
        # */*, response type will be the first element of self.allowed_types.
        if not request_accept_types or request_accept_types[0][0] == '*/*':
            return allowed_types[0]
        else:
            return request_accept_types.best_match(allowed_types)
    else:
        raise ConfigurationError(
            'You must initialize flask app before calling this function.')


def request_wants_json():
    """
    Check if request wants json.
    """
    return get_accept_header() == 'application/json'
