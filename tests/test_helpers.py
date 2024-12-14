import json
import os
from unittest import TestCase

from tetrapod.helpers import (
    iterate_array,
    iterate_resource,
    intersection,
    union,
)


class TestIterateArray(TestCase):
    def setUp(self):
        pass

    def test_iterate_array(self):
        pass


class TestIterateResource(TestCase):
    def setUp(self):
        pass

    def test_iterate_resource(self):
        pass


class TestSetOpsResource(TestCase):

    def test_intersection(self):
        res = intersection([1, 2], [2, 3], [2, 4, 5])
        self.assertEqual(1, len(res))
        self.assertEqual(2, res[0])

    def test_union(self):
        res = union([1, 2], [2, 3], [2, 4, 5])
        self.assertEqual(5, len(res))
        self.assertEqual(1, res[0])