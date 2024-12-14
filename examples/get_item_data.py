from tetrapod.session import create_podio_session

ITEM_ID=123456789  # <- Replace with your own item_id


def get_podio_item(item_id):
    # reads the access token from .tetrapod_credentials.json
    podio = create_podio_session()

    # see https://developers.podio.com/doc/items/get-item-22360
    item_url = f'https://api.podio.com/item/{item_id}'

    # podio.get() works almost the same way that requests.get() works
    resp = podio.get(item_url)
    resp.raise_for_status()
    item_data = resp.json()
    return item_data


if __name__ == '__main__':
    item_data = get_podio_item(ITEM_ID)
    # print something from the item_data, then exit
    print(f"Item-ID: {item_data['item_id']}")
    print(f"Item title: {item_data['title']}")
