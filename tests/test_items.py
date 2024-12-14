import os
import json
from unittest import TestCase
import datetime

from tetrapod.items import (
    fetch_field,
    Item,
    CategoryMediator,
)


class ItemTestCase(TestCase):
    """Abstract base class for anything that needs test_item.json to be tested."""

    def setUp(self):
        super().setUp()
        json_path = os.path.join(os.path.dirname(__file__), 'test_item.json')
        with open(json_path, mode='r') as fh:
            self.test_item = json.load(fh)

class TestCategoryMediator(ItemTestCase):

    def setUp(self):
        super().setUp()
        self.field = self.test_item['fields'][7]
        self.mediator = CategoryMediator()

    def test_update_category_str(self):
        value = 'Accepted'
        res = self.mediator.update(self.field, value)
        self.assertEqual(
            [{'value': {
                'status': 'active',
                'text': 'Accepted',
                'id': 2,
                'color': 'DCEBD8'}
            }],
            res
        )

    def test_fetch_category(self):
        self.assertEqual(
            [(1, "Entered"), (2, "Accepted"), (3, "Rejected")],
            self.mediator.fetch(self.field, field_param='choices')
        )
        self.assertEqual(
            "Accepted",
            self.mediator.fetch(self.field)
        )
        self.assertEqual(
            "Accepted",
            self.mediator.fetch(self.field, field_param='active')['text']
        )
        self.assertEqual(
            2,
            self.mediator.fetch(self.field, field_param='active')['id']
        )
        self.assertEqual(
            "DCEBD8",
            self.mediator.fetch(self.field, field_param='active')['color']
        )


    def test_as_podio_dict(self):
        res = self.mediator.as_podio_dict(self.field)
        self.assertEqual([2], res)


class TestFetchField(ItemTestCase):

    def test_get_field_not_found(self):
        self.assertEqual(
            None,
            fetch_field('does_not_exist', self.test_item)
        )

    def test_get_field_with_underscore(self):
        self.assertEqual(
            'Go',
            fetch_field('do_it', self.test_item)
        )

    def test_get_text_field(self):
        self.assertEqual(
            "Bow of boat",
            fetch_field('name', self.test_item)
        )

    def test_get_text_field_multiline(self):
        self.assertEqual(
            "<p>There's something about knowing the bow from the stern that "
            "makes sense in regard to this project.</p>",
            fetch_field('description', self.test_item)
        )

    def test_fetch_category_field(self):
        self.assertEqual(
            [(1, "Entered"), (2, "Accepted"), (3, "Rejected")],
            fetch_field('status2__choices', self.test_item)
        )
        self.assertEqual(
            "Accepted",
            fetch_field('status2', self.test_item)
        )
        self.assertEqual(
            "Accepted",
            fetch_field('status2__active', self.test_item)['text']
        )
        self.assertEqual(
            2,
            fetch_field('status2__active', self.test_item)['id']
        )
        self.assertEqual(
            "DCEBD8",
            fetch_field('status2__active', self.test_item)['color']
        )

    def test_fetch_app_field(self):
        self.assertEqual(
            [503454054],
            fetch_field('projects', self.test_item)
        )
        # self.assertEqual(
        #     503454054,
        #    fetch_field('projects__first', self.test_item)
        #)
        #self.assertEqual(
        #    503454054,
        #    fetch_field('projects__last', self.test_item)
        #)

    def test_fetch_calculation_field(self):
        self.assertEqual(
            "Hello,  John Doe",
            fetch_field('calc', self.test_item)
        )

    def test_fetch_date_field(self):
        self.assertEqual(
            '2018-07-27 01:00:00',
            fetch_field('date', self.test_item)
        )
        self.assertEqual(
            datetime.datetime(2018, 7, 27, 1, 0),
            fetch_field('date__datetime', self.test_item)
        )
        
        self.assertEqual(
            '2018-07-27 01:00:00',
            fetch_field('date__start', self.test_item)
        )
        # item[‘date__start_datetime’]
        self.assertEqual(
            datetime.datetime(2018, 7, 27, 1, 0),
            fetch_field('date__start_datetime', self.test_item)
        )
        self.assertEqual(
            datetime.datetime(2018, 7, 28, 1, 0),
            fetch_field('date__end_datetime', self.test_item)
        )

    def test_fetch_embed_field(self):
        self.assertEqual(
            "http://www.newsletter-webversion.de/?c=0-v0yw-0-11xa&utm_source=newsletter&utm_medium=email&utm_campaign=02%2F2017+DT&newsletter=02%2F2017+DT",
            fetch_field('embed', self.test_item)
        )


class TestItem(TestCase):

    def setUp(self):
        json_path = os.path.join(os.path.dirname(__file__), 'test_item.json')
        with open(json_path, mode='r') as fh:
            self.test_item = json.load(fh)
        self.item = Item(item_data=self.test_item)

    def test__getitem__(self):
        self.assertEqual(
            "Bow of boat",
            self.item['name']
        )

    def test__setitem__(self):
        self.assertEqual(0, len(self.item._tainted))
        self.item['name'] = 'Bow of ship'
        # after setting the value, the number of tainted fields should go up.
        self.assertEqual(1, len(self.item._tainted))
        res = self.item.as_podio_dict(fields=self.item._tainted)
        self.assertEqual("Bow of ship", res['name'])

    def test__setitem__textfield_none(self):
        self.assertEqual(0, len(self.item._tainted))
        self.item['name'] = None
        # after setting the value, the number of tainted fields should go up.
        self.assertEqual(1, len(self.item._tainted))
        res = self.item.as_podio_dict(fields=self.item._tainted)
        self.assertEqual([], res['name'])

    def test_as_podio_dict(self):
        res = self.item.as_podio_dict(fields=['name'])
        self.assertEqual("Bow of boat", res['name'])

