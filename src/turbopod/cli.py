#!/usr/bin/env python3
'''
This module contains the command line interface for the 'tpod' command.
'''
import click
import configparser
import json
import os

from pathlib import Path

from turbopod import podio_auth
from turbopod.session import create_podio_session


@click.group()
def cli():
    pass


@click.command()
@click.option('--client-id', default=None, help='The Podio client ID')
@click.option('--client-secret', default=None, help='The Podio client secret')
def init(client_id, client_secret):
    # client secret is probably not needed
    if client_id is None: # or client_secret is None:
        # and a 'client secret'.\n" \
        msg = "You need to supply a valid 'client ID' " \
              "You will find it in the 'API keys' settings of your Podio account.\n" \
              "\n" \
              "\thttps://podio.com/settings/api"
        raise click.UsageError(msg)

    try:
        token = podio_auth.authorize(client_id, client_secret)
        podio_auth.save_token(token)
        click.secho('Token saved. Ready to add apps.')

    except podio_auth.CouldNotAcquireToken as e:
        print(e)


@click.command(help='List your organisations')
def orgs():
    podio = create_podio_session()
    orgas = podio.get('https://api.podio.com/org/').json()
    for org in orgas:
        click.echo(click.style(org['name'], bold=True) \
                   + click.style(' {}'.format(org['org_id']), bold=False))


@click.command(help='List all workspaces of an organization')
@click.argument('organization')
def spaces(organization):
    podio = create_podio_session()
    url = 'https://api.podio.com/space/org/{}/'.format(int(organization))
    spaces = podio.get(url).json()
    for space in spaces:
        click.echo(click.style(space['name'], bold=True) \
                   + click.style(' {}'.format(space['space_id']), bold=False))


@click.command(help='List all apps of a workspace')
@click.argument('space')
def apps(space):
    podio = create_podio_session()
    url = 'https://api.podio.com/app/space/{}/'.format(int(space))
    apps = podio.get(url).json()
    for app in apps:
        click.echo(click.style(app['config']['name'], bold=True) \
                   + click.style(' {}'.format(app['app_id']), bold=False))


@click.command(help='Add an app to this project.')
@click.argument('app_id')
@click.argument('field')
def add_app(app_id, field):
    podio = create_podio_session()
    url = 'https://api.podio.com/app/{:d}'.format(int(app_id))
    app = podio.get(url).json()
    space_id = app['space_id']
    space_url = 'https://api.podio.com/space/{:d}'.format(int(space_id))
    space = podio.get(space_url).json()
    print(json.dumps(app['space_id'], indent=2))
    print(app['url_label'], app['app_id'])
    print(space['url_label'])
    path = Path( os.path.join(space['url_label'], app['url_label']) )
    path.mkdir(parents=True, exist_ok=True)
    config = configparser.ConfigParser()
    config['project'] = {
        'name': space['url_label'],
        'apps': app['url_label']
    }
    for one_field in app['fields']:
        if one_field['external_id'] == field:
            script_filename = os.path.join(path, '{}.js'.format(field))
            with open(script_filename, mode='w+') as fh:
                script = one_field['config']['settings']['script']
                fh.write(script)
            json_filename = os.path.join(path, '{}.json'.format(field))
            with open(json_filename, mode='w+') as fh:
                settings = json.dumps(one_field, indent=2)
                fh.write(settings)
            config['{}.{}'.format(space['url_label'], app['url_label'])] = {
                'app_id': app['app_id'],
                'fields': field,
            }
            config['{}.{}.{}'.format(space['url_label'], app['url_label'], field)] = {
                'field_id': one_field['field_id'],
                'script': script_filename,
                'settings': json_filename,
            }
            print(' \_', one_field['external_id'], '[synced]')
            print(json.dumps(one_field, indent=2))
        else:
            print(' \_', one_field['external_id'])

    with open('{}.tpodproject'.format(space['url_label']), 'w+') as configfile:
        config.write(configfile)


@click.command(help='Update the calculation fields')
@click.argument('space_name')
def deploy(space_name):
    config = configparser.ConfigParser()
    config.read('{}.tpodproject'.format(space_name))
    space_name = config['project']['name']
    # TODO: for-loop
    app_name = config['project']['apps']
    app_section = '{}.{}'.format(space_name, app_name)
    app_id = config[app_section]['app_id']
    fields_raw = config[app_section]['fields']
    fields_all = [f.strip() for f in fields_raw.split(',')]
    for fields in fields_all:
        field_section = '{}.{}.{}'.format(space_name, app_name, fields)
        field_id = config[field_section]['field_id']
        with open(config[field_section]['script'], mode='r') as script_file:
            field_script = script_file.read()
        with open(config[field_section]['settings'], mode='r') as settings_file:
            field_settings = json.load(settings_file)

        # Now we got everything to makte the request:
        payload = {
            "label": field_settings['label'],
            "description": field_settings['config']['description'],
            "delta": field_settings['config']['delta'],
            "settings": field_settings['config']['settings'],
            "mapping": field_settings['config']['mapping'],
            "required": field_settings['config']['required'],
            "hidden_create_view_edit": field_settings['config']['hidden_create_view_edit'],
        }
        payload['settings']['script'] = field_script
        print(json.dumps(payload, indent=2))

        # Upload the payload
        podio = create_podio_session()
        url = 'https://api.podio.com/app/{:d}/field/{:d}'.format(int(app_id), int(field_id))
        print(url)
        resp = podio.put(url, data=json.dumps(payload))
        print(resp.status_code)
        print(json.dumps(resp.json(), indent=2))


@click.command(help="Get user info")
@click.argument('user_id')
def user(user_id):
    podio = create_podio_session()
    url = 'https://api.podio.com/user/{:d}'.format(int(user_id))
    print(url)
    resp = podio.get(url)
    print(resp.status_code)
    print(json.dumps(resp.json(), indent=2))

cli.add_command(init)
cli.add_command(orgs)
cli.add_command(spaces)
cli.add_command(apps)
cli.add_command(add_app)
cli.add_command(deploy)
cli.add_command(user)

if __name__ == '__main__':
    cli()
