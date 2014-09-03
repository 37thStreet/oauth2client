"""Utilities for reading and writing Google Credentials models.

This Google Credential JSON model provides a common format for reading and
validating credentials for use in calling Google APIs. Notably, the format is
used for Google Application Default Credentials as described here:
https://developers.google.com/accounts/docs/application-default-credentials
"""


import json
from oauth2client import GOOGLE_REVOKE_URI
from oauth2client import GOOGLE_TOKEN_URI


class Error(Exception):
  """Base error for this module."""


class InvalidCredentialModelError(Error):
  """Supplied arguments would not produce a valid credential object."""


class GoogleCredentialsJson(object):
  """Wrapper for loading and serializing Google Credentials JSON objects."""

  # Properties which describe various types of default credential model objects.
  TYPE_SERVICE_ACCOUNT = 'service_account'
  TYPE_AUTHORIZED_USER = 'authorized_user'

  TYPE_FIELD_NAME = 'type'
  CLIENT_ID_FIELD_NAME = 'client_id'
  CLIENT_EMAIL_FIELD_NAME = 'client_email'
  PRIVATE_KEY_ID_FIELD_NAME = 'private_key_id'
  PRIVATE_KEY_FIELD_NAME = 'private_key'
  CLIENT_SECRET_FIELD_NAME = 'client_secret'
  REFRESH_TOKEN_FIELD_NAME = 'refresh_token'

  # optional field names
  TOKEN_URI_FIELD_NAME = 'token_uri'
  REVOKE_URI_FIELD_NAME = 'revoke_uri'

  _REQUIRED_SERVICE_ACCOUNT_FIELDS = set(
      [TYPE_FIELD_NAME, CLIENT_ID_FIELD_NAME, CLIENT_EMAIL_FIELD_NAME,
       PRIVATE_KEY_ID_FIELD_NAME, PRIVATE_KEY_FIELD_NAME])
  _REQUIRED_AUTHORIZED_USER_FIELDS = set(
      [TYPE_FIELD_NAME, CLIENT_ID_FIELD_NAME, CLIENT_SECRET_FIELD_NAME,
       REFRESH_TOKEN_FIELD_NAME])

  @classmethod
  def _validate_credential_object(cls, credential_object):
    """Private method for validating Google Credentials."""

    if credential_object is None:
      raise InvalidCredentialModelError('Empty credential object.')

    credential_type = credential_object[cls.TYPE_FIELD_NAME]

    cls._check_credential_type(credential_type)

    if credential_type == cls.TYPE_AUTHORIZED_USER:
      missing_fields = cls._REQUIRED_AUTHORIZED_USER_FIELDS.difference(
          credential_object.keys())
    if credential_type == cls.TYPE_SERVICE_ACCOUNT:
      missing_fields = cls._REQUIRED_SERVICE_ACCOUNT_FIELDS.difference(
          credential_object.keys())

    if missing_fields:
      cls._raise_exception_for_missing_fields(missing_fields)

    return credential_object

  @classmethod
  def _check_credential_type(cls, credential_type):
    if not (
        credential_type == cls.TYPE_SERVICE_ACCOUNT or
        credential_type == cls.TYPE_AUTHORIZED_USER):
      cls._raise_exception_for_unknown_type()

  @classmethod
  def _set_optional_fields(cls, obj, token_uri=GOOGLE_TOKEN_URI,
                           revoke_uri=GOOGLE_REVOKE_URI):
    # set uri fields to default values if unspecified
    if cls.TOKEN_URI_FIELD_NAME not in obj:
      obj[cls.TOKEN_URI_FIELD_NAME] = token_uri
    if cls.REVOKE_URI_FIELD_NAME not in obj:
      obj[cls.REVOKE_URI_FIELD_NAME] = revoke_uri
    return obj

  @staticmethod
  def _raise_exception_for_missing_fields(missing_fields):
    raise InvalidCredentialModelError(
        'The following field(s) must be defined: ' + ', '.join(missing_fields))

  @classmethod
  def _raise_exception_for_unknown_type(cls):
    raise InvalidCredentialModelError(
        "'type' field should be defined (and have one of the '" +
        cls.TYPE_AUTHORIZED_USER + "' or '" + cls.TYPE_SERVICE_ACCOUNT +
        "' values)")

  @classmethod
  def serialize_data(cls, credential_type=None, client_id=None,
                     client_email=None, client_secret=None, private_key=None,
                     private_key_id=None, refresh_token=None,
                     token_uri=GOOGLE_TOKEN_URI, revoke_uri=GOOGLE_REVOKE_URI,
                     include_optional_fields=False):
    """Returns a validated string representation of a credential JSON object.

    Usage:
      serialize_data('authorized_user', client_id, client_secret, refresh_token)

    Args:
      credential_type: string, type of credential, e.g. 'authorized_user'
      client_id: string, client identifier.
      client_email: string, client email or service account email.
      client_secret: string, client secret.
      private_key: string, private key, typically, in PKCS12 or PEM format.
      private_key_id: string, a hint for your signing key.
      refresh_token: string, refresh token.
      token_uri: string, URI of token endpoint.
      revoke_uri: string, URI for revoke endpoint.
      include_optional_fields: bool, if true include optional fields in output.

    Returns:
      a dict representation of a validated credential object
    """
    credential_object = {}

    if credential_type is cls.TYPE_SERVICE_ACCOUNT:
      credential_object[cls.TYPE_FIELD_NAME] = cls.TYPE_SERVICE_ACCOUNT
      credential_object[cls.CLIENT_ID_FIELD_NAME] = client_id
      credential_object[cls.CLIENT_EMAIL_FIELD_NAME] = client_email
      credential_object[cls.PRIVATE_KEY_ID_FIELD_NAME] = private_key_id
      credential_object[cls.PRIVATE_KEY_FIELD_NAME] = private_key
      if include_optional_fields:
        credential_object = cls._set_optional_fields(credential_object,
                                                     token_uri, revoke_uri)
      return cls._validate_credential_object(credential_object)

    if credential_type is cls.TYPE_AUTHORIZED_USER:
      credential_object[cls.TYPE_FIELD_NAME] = cls.TYPE_AUTHORIZED_USER
      credential_object[cls.CLIENT_ID_FIELD_NAME] = client_id
      credential_object[cls.CLIENT_SECRET_FIELD_NAME] = client_secret
      credential_object[cls.REFRESH_TOKEN_FIELD_NAME] = refresh_token
      if include_optional_fields:
        credential_object = cls._set_optional_fields(credential_object,
                                                     token_uri, revoke_uri)
      return cls._validate_credential_object(credential_object)

    # raise an error if no valid credential_type provided
    cls._check_credential_type(credential_type)

  @classmethod
  def load(cls, fp):
    obj = cls._set_optional_fields(json.load(fp))
    return cls._validate_credential_object(obj)

  @classmethod
  def loads(cls, s):
    obj = cls._set_optional_fields(json.loads(s))
    return cls._validate_credential_object(obj)
