import math
import logging
import mimetypes

from collections import UserList
from functools import reduce

from turbopod.items import Item

log = logging.getLogger(__name__)


def iterate_array(client, url, http_method='GET', limit=100, offset=0, params=None):
    """
    Get a list of objects from the Podio API and provide a generator to iterate
    over these items. Use this for 

    e.g. to read all the items of one app use:

        url = 'https://api.podio.com/comment/item/{}/'.format(item_id)
        for item in iterate_array(client, url, 'GET'):
            print(item)
    """
    all_elements = []
    if params is None:
        params = dict(limit=limit, offset=offset)
    else:
        params['limit'] = limit
        params['offset'] = offset
        
    do_requests = True
    while do_requests == True:
        if http_method == 'POST':
            api_resp = client.post(url, data=params)
        elif http_method == 'GET':
            api_resp = client.get(url, params=params)
        else:
            raise Exception("Method not supported.")
        
        if api_resp.status_code != 200:
            raise Exception('Podio API response was bad: {}'.format(api_resp.content))
            
        resp = api_resp.json()
        num_entries = len(resp)
        if num_entries < limit or num_entries <= 0:
            do_requests = False

        params['offset'] += limit
        
        all_elements.extend(resp) 
    # print(f"array of {len(all_elements)}")
    return all_elements


def iterate_resource(client, url, http_method='POST', limit=500, offset=0, params=None):
    """
    Get a list of items from the Podio API and provide a generator to iterate
    over these items.

    e.g. to read all the items of one app use:

        url = 'https://api.podio.com/item/app/{}/filter/'.format(app_id)
        for item in iterate_resource(client, url, 'POST'):
            print(item)
    """
    if params is None:
        params = dict(limit=limit, offset=offset)
    else:
        params['limit'] = limit
        params['offset'] = offset

    if http_method == 'POST':
        api_resp = client.post(url, json=params)
    elif http_method == 'GET':
        api_resp = client.get(url, params=params)
    else:
        raise Exception("Method not supported.")

    if api_resp.status_code != 200:
        raise Exception('Podio API response was bad: {}'.format(api_resp.content))

    all_items = []
    resp = api_resp.json()
    log.debug(f"Got {len(resp['items'])} ...")
    all_items.extend(resp['items'])

    total = resp['total']
    try: 
        total = resp['filtered']
    except KeyError:
        pass

    log.debug('Getting items from offset: %d, total: %d' % (offset, total))
    steps_left = []
    if total > limit:
        num_steps = int(math.ceil(total / limit))
        steps = list(range(0, num_steps * limit, limit))
        # we don't need step 0 because we already got the data.
        steps_left = steps[1:]

    for curr_offset in steps_left:
        log.debug('Getting items from offset: %d, total: %d' % (curr_offset, total))
        params['limit'] = limit
        params['offset'] = curr_offset
        if http_method == 'POST':
            api_resp = client.post(url, json=params)
        else: # method == 'GET'
            api_resp = client.get(url, params=params)

        if api_resp.status_code != 200:
            raise Exception('Podio API response was bad: {}'.format(api_resp.content))
        resp = api_resp.json()
        all_items.extend( resp['items'] )

    log.debug("Got all items!")
    return all_items


# We define intersection and union ourselves here,
# so we don't have to depend on another module (e.g. fnc)
def intersection(*args):
    return reduce(lambda a, b: list(set(a) & set(b)), args)


def union(*args):
    return reduce(lambda a, b: list(set(a) | set(b)), args)


class SearchableList(UserList):
    """Represent a complete app, used with load_complete_app"""

    def __init__(self, initlist=None):
        super().__init__(initlist)
        self.search_index = {}

    # stop deleltion from List
    def remove(self, s=None):
        raise RuntimeError("Deletion not allowed")

    # stop pop from List
    def pop(self, s=None):
        raise RuntimeError("Deletion not allowed")

    def append(self, item: Item) -> None:
        index = len(self.data)  # index of appended element at end of list
        self.make_searchable(index, item)
        super().append(item)

    def insert(self, i: int, item: Item) -> None:
        raise RuntimeError("Insert would mess up the search idx. Use .append()")

    def make_searchable(self, index: int, item: Item):
        """Create the searchable values for the item in the search index."""
        for field in item.item_data['fields']:
            external_id = field['external_id']
            searchable_text = str(item[external_id]).strip().lower()
            try:
                index_for_field = self.search_index[external_id]
            except KeyError:
                index_for_field = {}
                self.search_index[external_id] = index_for_field
            if searchable_text in index_for_field.keys():
                index_for_field[searchable_text] += [index]
            else:
                index_for_field[searchable_text] = [index]

    SEARCH_AND = 1
    SEARCH_OR = 2

    def search_multiple(self, external_ids_and_search_terms: dict, mode=SEARCH_AND):
        """
        Example:
        items = SearchableList()
        mlp = items.search_multiple({'title': 'My little Pony', 'tag-line': 'Friendship is Magic'})

        :param external_ids_and_search_terms: A dict that contains the external id
        :param mode: AND and OR is available.
           - AND: All of the search terms must be present (intersection of found items for
            each search term)
           - OR: At least one of the search terms must be present (union of the found items)
        :return: List of items found or an empty list.
        """
        if len(self.data) == 0:
            log.warning('Tried search in empty list.')
            return []
        for external_id in external_ids_and_search_terms.keys():
            if external_id not in self.search_index.keys():
                log.warning('Searching for unknown field "%s", field might be null for '
                            'every item in this list or not exist at all.' % external_id)
                if mode == self.SEARCH_AND:
                    return []

        results_indexes = []  # list of lists of indexes of items found
        for external_id, search_term in external_ids_and_search_terms.items():
            query = str(search_term).strip().lower()
            field_data = self.search_index[external_id]
            try:
                index_list = field_data[query]  # returns a list of indexes
                results_indexes.append(index_list)
            except KeyError:
                results_indexes.append([])
        # the final result is the indexes that were found for every search term
        if mode == self.SEARCH_AND:
            final_result_indexes = list(intersection(*results_indexes))
        elif mode == self.SEARCH_OR:
            final_result_indexes = list(union(*results_indexes))

        result_items = [self.data[idx] for idx in final_result_indexes]
        return result_items

    def search(self, external_id: str, look_for: str) -> list:
        if len(self.data) == 0:
            log.warning('Tried search in empty list.')
            return []
        if external_id not in self.search_index.keys():
            log.warning('Searching for unknown field "%s", field might be null for '
                        'every item in this list or not exist at all.' % external_id)
            return []
        query = str(look_for).strip().lower()
        search_results = []
        field_data = self.search_index[external_id]
        try:
            index_list = field_data[query]
            # Use the sorted index
            for index in sorted(index_list):
                search_results.append(self.data[index])
        except KeyError:
            pass
        return search_results

    def search_first(self, external_id: str, look_for: str) -> Item:
        """Do a search but only return the first found item or None if not found."""
        items_found = self.search(external_id, look_for)
        if len(items_found) < 1:
            return None
        else:
            return items_found[0]


def load_complete_app(podio, app_id):
    url = f'https://api.podio.com/item/app/{app_id}/filter/'

    payload = SearchableList()
    for item in iterate_resource(podio, url, 'POST', limit=250):
        payload.append(Item(item))

    return payload


def upload_file(podio, item_id, raw_data, new_file_name):
    log.info(f'Uploading and attaching file {new_file_name} to item {item_id}')
    files = {'source': (new_file_name, raw_data, mimetypes.guess_type(new_file_name)[0])}
    data = {'filename': new_file_name.encode('utf-8')}
    upload_resp = podio.post('https://api.podio.com/file', data=data, files=files)
    log.info(f"Upload response is: {upload_resp.status_code}, "
             f"content(-repr): {repr(upload_resp.content)}")
    upload_resp.raise_for_status()
    new_file_id = upload_resp.json()['file_id']
    attach_resp = podio.post('https://api.podio.com/file/%d/attach' % new_file_id,
                             json={'ref_type': 'item', 'ref_id': item_id})
    log.info(f"Attach response is: {attach_resp.status_code}, "
             f"content(-repr): {repr(attach_resp.content)}")