"""GoogleCredentialJson tests.

Unit tests for GoogleCredentialsJson model.
"""

import os
import unittest

from oauth2client import GOOGLE_REVOKE_URI
from oauth2client import GOOGLE_TOKEN_URI
from oauth2client.google_credentials_json import GoogleCredentialsJson
from oauth2client.google_credentials_json import InvalidCredentialModelError

_SAMPLE_CLIENT_ID = '123'
_SAMPLE_CLIENT_EMAIL = 'dummy@google.com'
_SAMPLE_CLIENT_SECRET = 'secret'
_SAMPLE_REFRESH_TOKEN = 'alabalaportocala'
_SAMPLE_PRIVATE_KEY_ID = 'ABCDEF'
_SAMPLE_PRIVATE_KEY = 'localKeyID: 22 7E 04 FC 64 48 20 83 1E C1...'
_SAMPLE_TOKEN_URI = 'dummy_token_uri'
_SAMPLE_REVOKE_URI = 'dummy_revoke_uri'


def datafile(filename):
  f = open(os.path.join(os.path.dirname(__file__), 'data', filename), 'r')
  data = f.read()
  f.close()
  return data


class GoogleCredentialsJsonTests(unittest.TestCase):

  def setUp(self):
    self.os_name = os.name

  def test_serialize_data_unknown_type(self):
    try:
      GoogleCredentialsJson.serialize_data(credential_type='badtype')
    except InvalidCredentialModelError:
      pass  # Expected

  def test_serialize_data_service_account(self):
    cred = GoogleCredentialsJson.serialize_data(
        credential_type=GoogleCredentialsJson.TYPE_SERVICE_ACCOUNT,
        client_id=_SAMPLE_CLIENT_ID, client_email=_SAMPLE_CLIENT_EMAIL,
        private_key_id=_SAMPLE_PRIVATE_KEY_ID, private_key=_SAMPLE_PRIVATE_KEY)
    self.assertEqual(GoogleCredentialsJson.TYPE_SERVICE_ACCOUNT,
                     cred[GoogleCredentialsJson.TYPE_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_ID,
                     cred[GoogleCredentialsJson.CLIENT_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_EMAIL,
                     cred[GoogleCredentialsJson.CLIENT_EMAIL_FIELD_NAME])
    self.assertEqual(_SAMPLE_PRIVATE_KEY_ID,
                     cred[GoogleCredentialsJson.PRIVATE_KEY_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_PRIVATE_KEY,
                     cred[GoogleCredentialsJson.PRIVATE_KEY_FIELD_NAME])

  def test_serialize_data_authorized_user(self):
    cred = GoogleCredentialsJson.serialize_data(
        credential_type=GoogleCredentialsJson.TYPE_AUTHORIZED_USER,
        client_id=_SAMPLE_CLIENT_ID, client_secret=_SAMPLE_CLIENT_SECRET,
        refresh_token=_SAMPLE_REFRESH_TOKEN)
    self.assertEqual(GoogleCredentialsJson.TYPE_AUTHORIZED_USER,
                     cred[GoogleCredentialsJson.TYPE_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_ID,
                     cred[GoogleCredentialsJson.CLIENT_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_SECRET,
                     cred[GoogleCredentialsJson.CLIENT_SECRET_FIELD_NAME])
    self.assertEqual(_SAMPLE_REFRESH_TOKEN,
                     cred[GoogleCredentialsJson.REFRESH_TOKEN_FIELD_NAME])
    # check that optional fields are not present
    self.assertFalse(GoogleCredentialsJson.TOKEN_URI_FIELD_NAME in cred)
    self.assertFalse(GoogleCredentialsJson.REVOKE_URI_FIELD_NAME in cred)

  def test_serialize_data_enable_optional_fields(self):
    cred = GoogleCredentialsJson.serialize_data(
        credential_type=GoogleCredentialsJson.TYPE_AUTHORIZED_USER,
        client_id=_SAMPLE_CLIENT_ID, client_secret=_SAMPLE_CLIENT_SECRET,
        refresh_token=_SAMPLE_REFRESH_TOKEN, include_optional_fields=True)

    self.assertEqual(GoogleCredentialsJson.TYPE_AUTHORIZED_USER,
                     cred[GoogleCredentialsJson.TYPE_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_ID,
                     cred[GoogleCredentialsJson.CLIENT_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_SECRET,
                     cred[GoogleCredentialsJson.CLIENT_SECRET_FIELD_NAME])
    self.assertEqual(_SAMPLE_REFRESH_TOKEN,
                     cred[GoogleCredentialsJson.REFRESH_TOKEN_FIELD_NAME])
    # check that optional fields are present
    self.assertEqual(GOOGLE_TOKEN_URI,
                     cred[GoogleCredentialsJson.TOKEN_URI_FIELD_NAME])
    self.assertEqual(GOOGLE_REVOKE_URI,
                     cred[GoogleCredentialsJson.REVOKE_URI_FIELD_NAME])

  def test_loads_success(self):
    fn = 'application_default_credentials.json'
    well_known_file = datafile(os.path.join('gcloud', fn))
    cred = GoogleCredentialsJson.loads(well_known_file)

    self.assertEqual(GoogleCredentialsJson.TYPE_SERVICE_ACCOUNT,
                     cred[GoogleCredentialsJson.TYPE_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_ID,
                     cred[GoogleCredentialsJson.CLIENT_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_EMAIL,
                     cred[GoogleCredentialsJson.CLIENT_EMAIL_FIELD_NAME])
    self.assertEqual(_SAMPLE_PRIVATE_KEY_ID,
                     cred[GoogleCredentialsJson.PRIVATE_KEY_ID_FIELD_NAME])
    self.assertEqual(GOOGLE_TOKEN_URI,
                     cred[GoogleCredentialsJson.TOKEN_URI_FIELD_NAME])
    self.assertEqual(GOOGLE_REVOKE_URI,
                     cred[GoogleCredentialsJson.REVOKE_URI_FIELD_NAME])

  def test_load_success(self):
    fn = 'application_default_credentials.json'
    f = open(os.path.join(os.path.dirname(__file__), 'data', 'gcloud', fn), 'r')
    cred = GoogleCredentialsJson.load(f)
    f.close()

    self.assertEqual(GoogleCredentialsJson.TYPE_SERVICE_ACCOUNT,
                     cred[GoogleCredentialsJson.TYPE_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_ID,
                     cred[GoogleCredentialsJson.CLIENT_ID_FIELD_NAME])
    self.assertEqual(_SAMPLE_CLIENT_EMAIL,
                     cred[GoogleCredentialsJson.CLIENT_EMAIL_FIELD_NAME])
    self.assertEqual(_SAMPLE_PRIVATE_KEY_ID,
                     cred[GoogleCredentialsJson.PRIVATE_KEY_ID_FIELD_NAME])
    self.assertEqual(GOOGLE_TOKEN_URI,
                     cred[GoogleCredentialsJson.TOKEN_URI_FIELD_NAME])
    self.assertEqual(GOOGLE_REVOKE_URI,
                     cred[GoogleCredentialsJson.REVOKE_URI_FIELD_NAME])

  def test_loads_missing_fields(self):
    fn = 'application_default_credentials_malformed_2.json'
    well_known_file = datafile(os.path.join('gcloud', fn))
    try:
      GoogleCredentialsJson.loads(well_known_file)
    except InvalidCredentialModelError:
      pass  # Expected

  def test_loads_verify_optional_fields(self):
    fn = 'application_default_credentials_optional_uris.json'
    f = open(os.path.join(os.path.dirname(__file__), 'data', 'gcloud', fn), 'r')
    cred = GoogleCredentialsJson.load(f)
    f.close()

    self.assertEqual(_SAMPLE_TOKEN_URI,
                     cred[GoogleCredentialsJson.TOKEN_URI_FIELD_NAME])
    self.assertEqual(_SAMPLE_REVOKE_URI,
                     cred[GoogleCredentialsJson.REVOKE_URI_FIELD_NAME])
