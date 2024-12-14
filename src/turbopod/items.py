import datetime
import logging
from collections.abc import Mapping
from decimal import Decimal
from typing import Union

import dateutil.parser


log = logging.getLogger(__name__)


class PodioFieldMediator(object):
    """
    A Mediator is an object that converts a Python-side value of Podio item field
    to its Podio JSON form and back.

    When you use __getitem__() on an Item object, the Mediators take value and
    convert it into something easily useable in Python, e.g.:

    >>> item = Item(podio.get('https://api.podio.com/item/123455'))
    >>> print(item['title'])

    As soon as you call ['title'] the Mediator gets involved. The same goes
    for set-value operations, e.g.:

    >>> item['title'] = "Some example text."
    """

    def update(self, field, value, field_param=None):
        raise NotImplementedError()

    def fetch(self, field, field_param):
        raise NotImplementedError()

    def as_podio_dict(self, field):
        raise NotImplementedError()


class EmbedMediator(PodioFieldMediator):
    """
    embed:
      embed: The id of an embed returned from the Add an embed operation.
      file: The id of one the thumbnail files returned from the same operation.
    """
    def fetch(self, field, field_param=None):
        if field_param is None:
            for value in field.get('values', []):
                return value['embed']['url']
        elif field_param == 'all':
            return [v['embed']['url'] for v in field.get('values', [])]
        return None

# duration:
#   value: The duration in seconds

# video:
#   value: The file id of the video file

# location:
#   value: The location as entered by the user
#   formatted: The resolved formatted full address
#   street_number: The number in the street
#   street_name: The name of the street
#   postal_code: The zip code for the city
#   city: The name of the city
#   state: The state of the city, if any
#   country: The country of the city
#   lat: The latitude of the location
#   lng: The longitude of the location

# progress:
#   value: The current progress as an integer from 0 to 100

# money:
#   value: The decimal amount of the value as a string.
#   currency: The currency of the value.


class ContactMediator(PodioFieldMediator):
    """
    contact:
        value: The profile id of the contact

    Example:
      {
        "user_id": 1234567,
        "space_id": null,
        "rights": [
          "view"
        ],
        "url": [
          "http://example.com"
        ],
        "type": "user",
        "image": {
          "hosted_by": "podio",
          "hosted_by_humanized_name": "Podio",
          "thumbnail_link": "https://d2cmuesa4snpwn.cloudfront.net/public/123456789",
          "link": "https://d2cmuesa4snpwn.cloudfront.net/public/123456789",
          "file_id": 123456789,
          "external_file_id": null,
          "link_target": "_blank"
        },
        "profile_id": 123456789,
        "org_id": null,
        "phone": [
          "+xxxxxxxxxx"
        ],
        "link": "https://podio.com/users/1234567",
        "avatar": 123456789,
        "mail": [
          "john@example.com"
        ],
        "external_id": null,
        "last_seen_on": "2018-11-11 11:11:00",
        "name": "John Doe"
      }
    """
    def fetch(field, field_param=None):
        if field_param is None:
            for value in field.get('values', []):
                return value['value']
        elif field_param == 'all':
            return [v['value'] for v in field.get('values', [])]
        return None

# member:
#   value: The user id of the member

class AppMediator(PodioFieldMediator):
    """
    app:
      value: The id of the app item
    """
    def fetch(self, field, field_param=None):
        # We return the full list of values that Podio provides
        if field_param == 'values':
            return [v['value'] for v in field.get('values', [])]
        # Default case: Return just the item_id(s)
        items = [v['value']['item_id'] for v in field.get('values', [])]
        if not field_param:
            return items
        if field_param == 'first':
            return items[0]
        elif field_param == 'last':
            return items[:-1]

    def update(self, field, value, field_param=None):
        item_id_list = value
        if isinstance(value, int) or isinstance(value, str):
            item_id_list = [value]
        values = []
        for item_id in item_id_list:
            values.append({
                "value": {
                    "item_id": item_id
                }
            })
        return values

    def as_podio_dict(self, field):
        return self.fetch(field)


class DateMediator(PodioFieldMediator):
    """
    date:
        start_date: The start date
        start_time: The start time
        end_date: The end date
        end_time: The end time

        {
          "start": "2018-10-15 00:00:00",
          "start_date_utc": "2018-10-15",
          "start_time_utc": null,
          "start_time": null,
          "start_utc": "2018-10-15",
          "start_date": "2018-10-15"
        }
    """
    def update(self, field, value, field_param=None):
        if isinstance(value, datetime.datetime):
            start = value.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(value, str):
            start = dateutil.parser.parse(value).strftime('%Y-%m-%d %H:%M:%S')

        return [{
            'start': start
        }]


    def fetch(self, field, field_param=None):
        if field_param is None:
            for value in field.get('values', []):
                return value['start']
        if field_param == 'start':
            for value in field.get('values', []):
                return value['start']
        if field_param in ['start_datetime', 'startdatetime', 'start_dt', 'startdt']:
            for value in field.get('values', []):
                date_str = value['start']
                return datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        if field_param == 'end':
            for value in field.get('values', []):
                return value['end']
        if field_param in ['end_datetime', 'enddatetime', 'end_dt', 'enddt']:
            for value in field.get('values', []):
                date_str = value['end']
                return datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
        if field_param == 'datetime':
            for value in field.get('values', []):
                date_str = value['start']
                return datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')

        return None

    def as_podio_dict(self, field):
        for value in field.get('values', []):
            return {'start': value['start']}


class ImageMediator(PodioFieldMediator):
    """
    image:
      value: The file id of the image file
    
    Example:
        "type": "image",
        "field_id": 12345678,
        "label": "Images",
        "values": [
          {
            "value": {
              "mimetype": "image/jpeg",
              "perma_link": null,
              "hosted_by": "podio",
              "description": null,
              "hosted_by_humanized_name": "Podio",
              "size": 2151819,
              "thumbnail_link": "https://files.podio.com/1012345674",
              "link": "https://files.podio.com/1012345674",
              "file_id": 1012345674,
              "external_file_id": null,
              "link_target": "_blank",
              "name": "IMG_1234.JPG"
            }
          },
        ],
        external_id: "images"
    """
    def update(self, field, value, field_param=None):
        for id in value:
            pass
    
    def fetch(self, field, field_param=None):
        return [ val['value']['file_id'] for val in field.get('values', []) ]
        
    def as_podio_dict(self, field):
        pass


class NumberMediator(PodioFieldMediator):
    """
    number:
        value: The decimal value of the field as a string.

        "values": [
        {
          "value": "1.0000"
        }
        ],
    """
    def update(self, field, value, field_param=None):
        dvalue = Decimal(value)
        values = [{
            'value': f'{dvalue:.4f}'
        }]
        return values

    def fetch(self, field, field_param=None):
        if field_param is None:
            for value in field.get('values', []):
                dvalue = Decimal(value['value'])
                return f'{dvalue:.4f}'
        if field_param == 'int':
            for value in field.get('values', []):
                return int(Decimal(value['value']).to_integral())
        if field_param == 'float':
            for value in field.get('values', []):
                return float(Decimal(value['value']))
        return None

    def as_podio_dict(self, field):
        return self.fetch(field)


class TextMediator(PodioFieldMediator):
    """
    text:
        value: The value of the field which can be any length.
        format: The format of the text, either plain, markdown or html
    """
    def update(self, field, value, field_param=None):
        if value is None:
            values = []
        else:
            values = [{
                'value': value.strip()
            }]
        return values

    def fetch(self, field, field_param=None):
        if field_param is None:
            values = field.get('values')
            if values:
                for value in values:
                    return value['value']
        return None

    def as_podio_dict(self, field):
        values = field.get('values')
        if values and len(values) > 0:
            for value in values:
                return value['value']
        else:
            return []


class CategoryMediator(PodioFieldMediator):
    """
    category:
        value: The id of the option
    
    "values": [
            {
              "value": {
                "status": "active",
                "text": "Go",
                "id": 1,
                "color": "DCEBD8"
              }
            }
          ]
    """
    def update(self, field, value: Union[str, int, list], field_param=None):
        opts = field['config']['settings']['options']
        selected_opts = []
        
        # single values
        if isinstance(value, str) or isinstance(value, int):
            selected_values = [value]
            
        for val in selected_values:
            for opt in opts:
                if isinstance(val, str) and opt['text'] == val:
                    selected_opts.append(opt)
                if isinstance(val, int) and opt['id'] == value:
                    selected_opts.append(opt)

        # Category field values are wrapped in a dictionary with a single key
        # named 'value' (see docstring of this class) – heaven only knows why.
        return [{'value': opt} for opt in selected_opts]
        
    def fetch(self, field, field_param=None):
        if field_param == 'choices':
            options = field['config']['settings']['options']
            # inactive options are not show to the user
            return [(opt['id'], opt['text']) for opt in options if opt['status'] == 'active']
        # The same as '__choices' but instead of a list of tuples it returns a dictionary
        # that contains the choices and choice ID numbers.
        elif field_param == 'choices_dict':
            options = field['config']['settings']['options']
            # inactive options are not show to the user
            return {opt['text']: opt['id'] for opt in options if opt['status'] == 'active'}
        elif field_param == 'active':
            val = field.get('values', [None])[0]
            if val is not None:
                try:
                    return val['value']
                except KeyError:
                    return None
            else:
                return None
        elif field_param == 'all':
            values = []
            for v in field.get('values', []):
                values.append(v.get('value'))
            return values
        elif field_param == 'labels':
            values = []
            for v in field.get('values', []):
                podval = v.get('value')
                if podval is not None:
                    values.append(podval['text'])
            return values
        elif field_param is None:
            val = field.get('values', [None])[0]
            if val is not None:
                return val['value']['text']
            else:
                return None
                
    def as_podio_dict(self, field):
        return [v['value']['id'] for v in field.get('values', [])]


class EmailMediator(PodioFieldMediator):
    """
    email:
        value: Text value (max 254 characters)
        type: "home"/"work"/ "other"
    """

    def fetch(self, field, field_param=None):
        """
        email: only the first value is returned
        email__all: [{"type": "work", "value": "xyz@example.com"}]
        email__work/home/other: The first value of the particular type is returned.
        """
        if field_param == 'all':
            vals = field.get('values', [])
            return vals
        elif field_param in ['work', 'home', 'other']:
            vals = field.get('values', None)
            if vals is None:
                return None
            for val in vals:
                if val.get('type') == field_param:
                    return val.get('value')
        elif field_param is None:
            val = field.get('values', [None])[0]
            if val is not None:
                return val.get('value')
            else:
                return None

# phone:
#   type: "mobile"/"work"/"home"/"main"/"work_fax"/"private_fax"/ "other"
#   value: string value  (max 50 characters)


class CalculationMediator(PodioFieldMediator):
    def fetch(self, field, field_param=None):
        # Dates are special
        if field['config']['settings'].get('return_type') == 'date':
            for value in field.get('values', []):
                dt = datetime.datetime.strptime(value['start'], '%Y-%m-%d %H:%M:%S')
                if field_param == 'datetime':
                    return dt
                else:
                    return '{}'.format(dt)
        for value in field.get('values', []):
            return value['value']

        print(field.get('values'))

MEDIATORS = {
    'app': AppMediator,
    'calculation': CalculationMediator,
    'category': CategoryMediator,
    'contact': ContactMediator,
    'date': DateMediator,
    'email': EmailMediator,
    'embed': EmbedMediator,
    'number': NumberMediator,
    'text': TextMediator,
    'image': ImageMediator,
    # ... add future mediators here
}


def split_descriptor_parts(field_descriptor):
    """
    :param field_descriptor:
    :return:
    """
    descriptor_parts = field_descriptor.split('__', 1)
    if len(descriptor_parts) == 2:
        external_id = descriptor_parts[0]
        field_param = descriptor_parts[1]
    else:
        external_id = descriptor_parts[0]
        field_param = None
    return external_id, field_param


def get_field_from_podio_json_list(item_json, external_id, app_config=None):
    """
    :param external_id:
    :return:
    """
    if '_' in external_id:
        external_id = external_id.replace('_', '-')

    fields = item_json.get('fields', [])

    for field in fields:
        if field['external_id'] == external_id:
            return field

    if app_config:
        for field in app_config['fields']:
            if field['external_id'] == external_id:
                return field
        # Only raise the KeyError if we have the app_config and can know for certain
        # that the field does not exist.
        raise KeyError('%s' % external_id)
    item_id = item_json.get('item_id', 'n/a')
    log.warning('Accessing field %s on item_id %s: Unknown of field exists or does '
                'not contain a value. Returning value = None.' % (external_id, item_id))
    return None


def find_mediator_class(field):
    field_type = field['type']
    # try to find the correct PodioFieldMediator class
    mediator_class = MEDIATORS.get(field_type)
    if not mediator_class:
        raise NotImplementedError('Field type "%s" is not supported, yet.' % field_type)
    return mediator_class


def fetch_field(field_descriptor, item_json, app_config=None):
    """
    Fetch the first value of a field - or None if the field is empty.
    :param field_descriptor: The Podio external_id name as shown in the developer view.
    :param item_json: The JSON representation of the Podio item.
    :return: First value or None
    """
    external_id, field_param = split_descriptor_parts(field_descriptor)

    # Get the only the JSON part of the desired field
    field = get_field_from_podio_json_list(item_json, external_id, app_config)
    if not field:
        return None

    # Find and instanciate the correct PodioFieldMediator for this kind of field.
    mediator_class = find_mediator_class(field)
    mediator = mediator_class()

    # Use the mediator to get the actual data
    return mediator.fetch(field, field_param)


def update_field(field_descriptor, new_value, item_json, app_config=None):
    external_id, field_param = split_descriptor_parts(field_descriptor)

    # Get the only the JSON part of the desired field
    field = get_field_from_podio_json_list(item_json, external_id, app_config)

    # Find and instanciate the correct PodioFieldMediator for this kind of field.
    mediator_class = find_mediator_class(field)
    mediator = mediator_class()

    # Use the mediator to get the actual data
    actual = mediator.update(field, new_value, field_param)

    for field in item_json['fields']:
        if field['external_id'] == field_descriptor:
            field['values'] = actual
            return actual

    for field in app_config['fields']:
        if field['external_id'] == field_descriptor:
            item_json['fields'].append({
                'type': field['type'],
                'external_id': field_descriptor,
                'values': actual
            })
    return actual


def fetch_podio_dict(field_descriptor, item_json, app_config=None):
    """
    Fetch the first value of a field - or None if the field is empty.
    :param field_descriptor: The Podio external_id name as shown in the developer view.
    :param item_json: The JSON representation of the Podio item.
    :return: First value or None
    """
    external_id, field_param = split_descriptor_parts(field_descriptor)

    # Get the only the JSON part of the desired field
    field = get_field_from_podio_json_list(item_json, external_id, app_config)
    if not field:
        return None

    # Find and instanciate the correct PodioFieldMediator for this kind of field.
    mediator_class = find_mediator_class(field)
    mediator = mediator_class()

    # Use the mediator to get the actual data
    return mediator.as_podio_dict(field)


class BaseItem(Mapping):
    def __getitem__(self, key):
        return fetch_field(key, self.get_item_data(), self.get_app_config())

    def __setitem__(self, key, value):
        update_field(key, value, self.get_item_data(), self.get_app_config())
        self._tainted.add(key)

    def __iter__(self):
        return iter(self.get_item_data()['fields'])

    def __len__(self):
        return len(self.get_item_data()['fields'])

    def get_item_data(self) -> list:
        raise NotImplementedError()

    def get_app_config(self):
        return self._app_config

    @property
    def app_id(self):
        return self.get_item_data()['app']['app_id']

    @property
    def app_id__str(self):
        return '%d' % self.app_id

    @property
    def item_id(self):
        return self.get_item_data()['item_id']

    @property
    def item_id__str(self):
        return '%d' % self.item_id

    @property
    def unique_id(self):
        return int(self.get_item_data()['link'].rsplit('/', 1)[1])

    @property
    def unique_id__str(self):
        return self.get_item_data()['link'].rsplit('/', 1)[1]

    @property
    def link(self):
        return self.get_item_data()['link']

    def as_podio_dict(self, fields=None):
        """
        Returns the object as a dictionary ready to be JSON-serialized and to be sent
        to Podio's "create item" (POST) or "update item values" (PUT).

        The fields parameter is an optional list of fields to be include. The default
        is to include all fields.
        """
        podio_dict = {}
        app_config = self.get_app_config()
        if not app_config:
            app_fields = self.get_item_data().get('fields', [])
        else:
            app_fields = app_config.get('fields', [])
        for field in app_fields:
            # Ignore calculation fields.
            if field.get('type') == 'calculation':
                continue

            external_id = field['external_id']

            # do not add fields to the dict that are not in the fields list.
            if fields != None and external_id not in fields:
                continue

            field_podio_dict = \
                fetch_podio_dict(external_id, self.get_item_data(), self.get_app_config())
            podio_dict = dict(
                podio_dict,
                **{external_id: field_podio_dict}
            )

        return podio_dict


class Item(BaseItem):

    def __init__(self, item_data: dict, app_config=None):
        self._tainted = set()
        self.item_data = item_data
        self._app_config = app_config

    def get_item_data(self) -> dict:
        return self.item_data
        
    def save(self, podio_session=None) -> None:
        if not podio_session:
            raise Exception("You need to supply a podio session")
        tainted_fields = list(self._tainted)
        podio_dict = self.as_podio_dict(fields=tainted_fields)
        resp = podio_session.put(
            f'https://api.podio.com/item/{self.item_id}/value',
            json=podio_dict
        )
        resp.raise_for_status()
        
        