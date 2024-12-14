from turbopod.helpers import iterate_resource
from turbopod.items import Item

try:
    import pandas as pd   # type: ignore
except ImportError as err:
    print("The module pandas is not installed. Run 'pip install pandas' or equivalent to install.")
    raise err

def load_from_app(podio_session, app_id:int, limit:int=300,
                            external_ids:list=[], labels:list=[]):
    """
    Creates a Pandas dataframe from a Podio app.
    :param app_id: The app_id of the Podio app to be loaded.
    :param view_id: The view_id (if any) that the app should be filtered by.
    :return: A datagrame (pandas.df) that contains data from the Podio app.
    """
    app_resp = podio_session.get('https://api.podio.com/app/{}/'.format(app_id))
    app_resp.raise_for_status()
    app_data = app_resp.json()

    url = 'https://api.podio.com/item/app/{}/filter/'.format(app_id)
    all_item_data = iterate_resource(podio_session, url, limit=limit)

    if len(external_ids) > 0 and len(labels) > 0:
        raise ValueError('labels and external_ids cannot be used at the same time.')

    field_ids = [] # contains external_ids
    column_labels = [] # contains the label or the external_id
    for field in app_data.get('fields', []):
        if field.get('label') in labels:
            field_ids.append(field['external_id'])
            column_labels.append(field.get('label'))
        if field['external_id'] in external_ids:
            field_ids.append(field['external_id'])
            column_labels.append(field['external_id'])

    all_rows = []
    for item_data in all_item_data:
        row = []
        item = Item(item_data)
        for field_id in field_ids:
            row.append(item[field_id])
        all_rows.append(row)

    return pd.DataFrame(all_rows, columns=column_labels)

