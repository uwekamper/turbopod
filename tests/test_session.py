import json
import os
from unittest.mock import patch
from unittest import TestCase

from tetrapod.session import (
    try_environment_token,
    create_podio_session,
)

class TestSession(TestCase):

    def test_try_environment_token(self):
        # Set environment variable
        vars = {
            "TETRAPOD_CLIENT_ID": 'testclientid',
            "TETRAPOD_ACCESS_TOKEN": "abc123456789"
        }
        with patch.dict('os.environ', vars):
            self.assertEqual(
                "abc123456789",
                try_environment_token()["access_token"]
            )
            self.assertEqual(
                "testclientid",
                try_environment_token()["client_id"]
            )
            self.assertEqual(
                "bearer",
                try_environment_token()["token_type"]
            )

    def test_try_environment_token_not_set(self):
        self.assertEqual(None, try_environment_token())