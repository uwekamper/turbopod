import logging
import json
import sqlite3

try:
    from collections.abc import Iterable  # noqa
except ImportError:
    from collections import Iterable # noqa

from typing import Union
from turbopod.helpers import iterate_resource
from turbopod.items import Item
from turbopod.podio_auth import PodioOAuth2Session

log = logging.getLogger(__name__)


class CachedItem(Item):

    def __init__(self, item_storage, item_data):
        self._item_storage = item_storage
        super().__init__(item_data)

    def get_podio_session(self):
        return self._item_storage.podio

    def get_app_config(self):
        app_id = self.get_item_data()['app']['app_id']
        return self._item_storage.get_app_config(app_id)

    def save(self):
        if len(self._tainted) == 0:
            return
        podio = self.get_podio_session()
        podio_dict = self.as_podio_dict(fields=self._tainted)
        resp = podio.put(
            f'https://api.podio.com/item/{self.item_id}/value',
            json=podio_dict
        )
        resp.raise_for_status()
        self._item_storage.update_item(item=self)
        self._tainted = set()


class CachedItemNotFound(Exception):
    pass


class CachedItemStorage(object):
    """
    One object to connect a PodioOauth2Session and a SQLite3 database together.

    Example:
    >>> import sqlite3
    >>> from tetrapod.session import create_podio_session
    >>> podio = create_podio_session()
    >>> conn = sqlite3.connect('database.sqlite3')
    >>> factory = CachedItemFactory(conn, podio)
    >>> factory.get_item(12929939)
    """

    def __init__(self, conn:sqlite3.Connection, podio:PodioOAuth2Session):
        self.app_configs = {}
        self.conn = conn
        self.podio = podio
        self.cache_configs = {}

    def _find_item_sql(self, sql, parameters):
        clean_params = []
        for param in parameters:
            if isinstance(param, list):
                clean_params.append(repr(param))
            else:
                clean_params.append(param)
        cursor = self.conn.cursor()
        cursor.execute(sql, clean_params)
        found = cursor.fetchall()
        cursor.close()

        if len(found) == 0:
            raise CachedItemNotFound(f'Item not found, SQL query: {sql}, '
                                     f'parameters: {repr(clean_params)}')
        elif len(found) == 1:
            item = CachedItem(self, json.loads(found[0][0]))
            return item
        elif len(found) >= 2:
            raise Exception('Natural keys must be unique: %s' % repr(found))

    def get_item(self, app_id: int, item_id: int):
        table_name = f'podio_app_{app_id}'

        cursor = self.conn.cursor()
        sql = "SELECT item_data FROM %s WHERE item_id = ?" % table_name
        vars = (item_id,)
        cursor.execute(sql, vars)
        item_data = json.loads(cursor.fetchone()[0])
        cursor.close()

        item = CachedItem(item_storage=self, item_data=item_data)
        return item

    def get_item_by_join_ids(self, podio_app_id: int, select_for: dict):
        table_name = f'podio_app_{podio_app_id:d}'
        where_clauses = []
        for key, val in select_for.items():
            where_clauses.append(f'"{key}" = ?')
        where_clauses_str = ' AND '.join(where_clauses)
        sql = f"""SELECT item_data FROM {table_name} WHERE {where_clauses_str}"""
        return self._find_item_sql(sql, list(select_for.values()))

    def get_referenced_item(self, podio_app_id: int, item_ids: Iterable, select_for: dict):
        """
        Find one item but only return it, if it is
        """
        table_name = f'podio_app_{podio_app_id:d}'
        where_clauses = []
        for key, val in select_for.items():
            where_clauses.append(f'"{key}" = ?')

        # Now restrict even further by the list of allowed item_ids
        if len(item_ids) == 0:
            raise CachedItemNotFound()
        item_ids_str = ", ".join([f'{el:d}' for el in item_ids])
        where_clauses.append(f'item_id IN ({(item_ids_str)})')

        # Put it together
        where_clauses_str = ' AND '.join(where_clauses)
        sql = f"""SELECT item_data FROM {table_name} WHERE {where_clauses_str}"""
        return self._find_item_sql(sql, list(select_for.values()))

    def get_item_by_natural_key(self, podio_app_id: int, key: Union[Iterable, str]) -> CachedItem:
        if isinstance(key, Iterable):
            key_val = '-'.join(key)
        else:
            key_val = key

        table_name = f'podio_app_{podio_app_id:d}'
        sql = f"""SELECT item_data FROM {table_name} WHERE __natural_key = ?"""

        return self._find_item_sql(sql, (key_val, ))

    def update_item(self, item: CachedItem):
        app_id = item.get_item_data()['app']['app_id']
        table_name = f'podio_app_{app_id}'
        extra_fields = self.cache_configs[table_name]['extra_fields']
        natural_key_list = self.cache_configs[table_name]['natural_key']

        self.insert_item_data_into_db(app_id, item.get_item_data(),
                                      extra_fields, natural_key_list)

    def create_item(self, app_id: int, item_values: dict):
        table_name = f'podio_app_{app_id}'
        extra_fields = self.cache_configs[table_name]['extra_fields']
        natural_key_list = self.cache_configs[table_name]['natural_key']
        resp = self.podio.post(f'https://api.podio.com/item/app/{app_id:d}/',
                               json={'fields': item_values})
        resp.raise_for_status()
        item_data = resp.json()
        self.insert_item_data_into_db(app_id, item_data, extra_fields, natural_key_list)
        return CachedItem(self, item_data)

    def delete_item(self, app_id: int, item_id: int):
        raise NotImplementedError()

    def get_app_config(self, podio_app_id: int):
        try:
            return self.app_configs[podio_app_id]
        except KeyError:
            resp = self.podio.get(f'https://api.podio.com/app/{podio_app_id:d}/')
            resp.raise_for_status()
            config = resp.json()
            self.app_configs[int(podio_app_id)] = config
            return config

    def init_cache(self):
        sql = """SELECT table_name, extra_fields, natural_key FROM cached_apps"""
        cursor = self.conn.cursor()
        cursor.execute(sql)
        all = cursor.fetchall()
        for table_name, extra_fields, natural_key in all:
            self.cache_configs[table_name] = {
                'extra_fields': extra_fields.split(',') if extra_fields else [],
                'natural_key': natural_key.split(',') if natural_key else None,
            }
        cursor.close()
        log.debug('Cache initialized with cache configuration:')
        log.debug(json.dumps(self.cache_configs, indent=2))

    def cache_app(self, podio_app_id: int, extra_fields: list, natural_key: Union[Iterable, str]):
        """
        Create a local copy of all the items in one app.
        """
        table_name = 'podio_app_%d' % podio_app_id
        natural_key_list = None
        if natural_key:
            if not isinstance(natural_key, list):
                natural_key_list = [natural_key]
            else:
                natural_key_list = natural_key

        # Store the list of extra field names and the list of field names needed to
        # construct the __natural_key. This can later be used to run queries and update
        # entries.
        setup_sql = """CREATE TABLE IF NOT EXISTS cached_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT UNIQUE NOT NULL,
            extra_fields TEXT NULL,
            natural_key TEXT NULL)"""
        self.conn.execute(setup_sql)

        if natural_key:
            new_cache_sql = """
            INSERT INTO cached_apps(table_name, extra_fields, natural_key)
                VALUES(?, ?, ?)
            """
            try:
                self.conn.execute(
                	new_cache_sql,
                	(table_name, f"{','.join(extra_fields)}", f"{','.join(natural_key_list)}")
            	)
            except sqlite3.IntegrityError:
                log.warning("Integrity Error in table_name = %s" % table_name)
                update_cache_sql = """
                UPDATE cached_apps SET 
                       extra_fields = ? ,
                       natural_key = ?
                WHERE table_name = ?
                """
                self.conn.execute(
                	update_cache_sql,
                	(f"{','.join(extra_fields)}", f"{','.join(natural_key_list)}", table_name)
            	)
	    
        else:
            new_cache_sql = """
            INSERT INTO cached_apps(table_name, extra_fields)
                VALUES(?, ?)
            """
            try:
                self.conn.execute(
                    new_cache_sql,
                    (table_name, f"{','.join(extra_fields)}")
                )
            except sqlite3.IntegrityError:
                update_cache_sql = """
                UPDATE cached_apps SET 
                       extra_fields = ?
                WHERE table_name = ?
                """
                self.conn.execute(
                	update_cache_sql,
                	(f"{','.join(extra_fields)}", table_name)
            	)

        # Build the actual table for the items.
        cols = [
            'item_id INT PRIMARY KEY NOT NULL',
            'item_data TEXT NULL',
        ]
        if natural_key_list:
            cols.append('__natural_key TEXT NULL')

        for field_name in extra_fields:
            cols.append('"%s" TEXT NULL' % field_name)
        cols_sql = ", ".join(cols)
        create_sql = f'CREATE TABLE IF NOT EXISTS {table_name} ({cols_sql});'
        log.debug(create_sql)
        self.conn.execute(create_sql)
        self.conn.commit()
        url = "https://api.podio.com/item/app/%d/filter/" % podio_app_id
        all_items = iterate_resource(self.podio, url, limit=300)
        for item_data in all_items:
            self.insert_item_data_into_db(podio_app_id, item_data, extra_fields, natural_key_list)

        self.conn.commit()
        if natural_key_list:
            idx_sql = \
                f'CREATE UNIQUE INDEX IF NOT EXISTS idx_{podio_app_id:d}_natural_key ' \
                f'ON "{table_name}" (__natural_key)'
            log.debug(idx_sql)
            try:
                self.conn.execute(idx_sql)
            except sqlite3.IntegrityError as err:
                log.debug(err)
                raise err

    def insert_item_data_into_db(self, app_id, item_data,
                                 extra_fields=None, natural_key_list=None):
        table_name = f'podio_app_{app_id}'

        # Make sure that the Podio app ID is always included.
        try:
            item_data['app']['app_id']
        except KeyError:
            item_data['app'] = {'app_id': app_id}

        item = Item(item_data)

        # item-ID and json-dump of the whole item go first.
        columns = ['item_id', 'item_data']
        values = [item_data['item_id'], json.dumps(item_data)]

        # determine the value of the natural key
        if natural_key_list:
            nat_key_val = []
            for key in natural_key_list:
                # TODO: This only works if the related app has only one
                # natural key and the title of the app contains only that
                # How do we deal with complex values?
                if isinstance(item[key], dict):
                    related = [item[key]['item_id']]
                    nat_key_val.append(repr(related))
                else:
                    nat_key_val.append('%s' % item[key])
            values.append('-'.join(nat_key_val))
            columns.append('__natural_key')

        if extra_fields:
            for field_name in extra_fields:
                # TODO: This only works if the related app has only one
                # natural key and the title of the app contains only that
                # How do we deal with complex values?
                if isinstance(item[field_name], dict):
                    related = [item[key]['item_id']]
                    values.append(repr(related))
                    columns.append(f'"{field_name}"')
                else:
                    values.append('%s' % item[field_name])
                    columns.append(f'"{field_name}"')

        # create enough questionsmarks for the SQL
        column_names = ', '.join(columns)
        placeholders = ', '.join('?' * len(values))
        sql = f'INSERT OR REPLACE INTO {table_name} ({column_names}) VALUES ({placeholders})'
        self.conn.execute(
            sql,
            values
        )
        self.conn.commit()
