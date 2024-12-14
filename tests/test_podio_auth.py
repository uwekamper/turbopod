import json
import os
from unittest import TestCase

from tetrapod.items import Item
from tetrapod.podio_auth import make_client
from tetrapod.session import create_podio_session


class TestPodioOAuthSession(TestCase):
    def setUp(self):
        self.podio = create_podio_session(robust=True, check=False)

    # TODO: Find a way to test the podio authentication in offline mode.
    #def test_make_request(self):
    #    resp = self.podio.get('https://api.podio.com/user/status')
    #    print(resp.json())

    # def test_make_request_save(self):
    #     resp = self.podio.get('https://api.podio.com/item/1218885031')
    #     resp.raise_for_status()
    #     item = Item(resp.json())
    #     item['name1'] = None
    #     resp2 = item.save(self.podio)
    #     print(resp2)