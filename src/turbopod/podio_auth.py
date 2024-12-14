import cgi
import click
import datetime
import json
import logging
import os
import requests
import requests.exceptions

from time import sleep
from urllib.parse import parse_qs
from oauthlib.oauth2 import MobileApplicationClient, TokenExpiredError
from requests_oauthlib import OAuth2Session
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer

AUTHORIZATION_BASE_URL = 'https://podio.com/oauth/authorize'
TOKEN_URL = 'https://podio.com/oauth/access_token'
REFRESH_URL = 'https://podio.com/oauth/authorize'
APP_AUTH_TOKEN_URL = 'https://podio.com/oauth/token' # https://developers.podio.com/authentication/app_auth
KEEP_RUNNING = True

credentials = None

log = logging.getLogger(__name__)


TETRAPOD_MINIMUM_RATE_LIMIT = os.environ.get('TETRAPOD_MINIMUM_RATE_LIMIT')
if TETRAPOD_MINIMUM_RATE_LIMIT:
    TETRAPOD_MINIMUM_RATE_LIMIT = int(TETRAPOD_MINIMUM_RATE_LIMIT) / 100.0
else:
    # Ten percent is the default
    TETRAPOD_MINIMUM_RATE_LIMIT = 0.1


def keep_running():
    return KEEP_RUNNING


class CouldNotAcquireToken(Exception):
    """ Common base class for all non-exit exceptions. """
    pass


class OAuth2CallbackHandler(BaseHTTPRequestHandler):
    # These two static members will be overwritten by a (dynamically generated) subclass
    # of OAuth2CallbackHandler.

    def do_GET(self):
        """Respond to a GET request that contains the 'code'."""
        if self.path == '/':
            self.send_response(200)
            self.send_header(b"Content-type", b"text/html")
            self.end_headers()
            with open(os.path.join(os.path.dirname(__file__), 'authpage.html'), mode='r') as fh:
                page = fh.readlines()
                for line in page:
                    self.wfile.write(line.encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header(b"Content-type", b"application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    def do_POST(self):
        """Handle POST requests that contain the fragment code we get from Podio."""
        # http://stackoverflow.com/questions/4233218/python-basehttprequesthandler-post-variables
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)

        # Respond
        self.send_response(200)
        self.send_header(b"Content-type", b"text/html")
        self.end_headers()
        self.wfile.write(b'Done!')

        # Store the credentials outside of this object so the main thread can access it.
        global credentials
        credentials = parse_qs(post_body.decode('utf-8'))

        # Stop the server
        global KEEP_RUNNING
        KEEP_RUNNING = False


def MakeHandlerClass(client_id, client_secret=None):
    """
    Factory method that will create a subclass of OAuth2CallbackHandler that additionally contains
    client_id and client_secret.
    :param client_id: The Podio client ID
    :param client_secret: the Podio client secret
    :return: A HTTPRequestHandler subclass that can be used with http.server().
    """
    class CustomHandler(OAuth2CallbackHandler):
        def __init__(self, *args, **kwargs):
            self.client_id = client_id
            super(CustomHandler, self).__init__(*args, **kwargs)
    return CustomHandler


class PodioOAuth2Session(OAuth2Session):
    def __init__(self, client_id=None, client=None, auto_refresh_url=None,
            auto_refresh_kwargs=None, scope=None, redirect_uri=None, token=None,
            state=None, token_updater=None, enable_robustness=False, **kwargs):
        super(PodioOAuth2Session, self).__init__(
            client_id=client_id, client=client, auto_refresh_url=auto_refresh_url,
            auto_refresh_kwargs=auto_refresh_kwargs, scope=scope, redirect_uri=redirect_uri,
            token=token, state=state, token_updater=token_updater, **kwargs
        )
        self.enable_robustness = enable_robustness

    def request(self, method, url, data=None, headers=None, withhold_token=False,
                client_id=None, client_secret=None, **kwargs):
        # the usual way of doing requests
        if not self.enable_robustness:
            return super(PodioOAuth2Session, self) \
                .request(method, url,
                         data=data, headers=headers, withhold_token=withhold_token,
                         client_id=client_id, client_secret=client_secret, **kwargs)

        # robust way that tries to deal with most of the data
        retry_counter = 5
        while True:
            try:
                response = super(PodioOAuth2Session, self)\
                    .request(method, url,
                             data=data, headers=headers, withhold_token=withhold_token,
                             client_id=client_id, client_secret=client_secret, **kwargs)
            except requests.exceptions.ConnectionError as err:
                log.warning('ConnectionError while trying to access the Podio API.')
                # Connection error means we wait one second and try again.
                retry_counter -= 1
                if retry_counter < 1:
                    raise err
                else:
                    sleep(3.0)
                    continue

            # all retries have been used up. Return the response regardless of the status code.
            if retry_counter < 1:
                return response


            # everything went well
            if response.status_code < 400:
                limit = response.headers.get('X-Rate-Limit-Limit')
                remaining = response.headers.get('X-Rate-Limit-Remaining')
                # Less than x percent => wait one hour
                if remaining and limit and int(remaining) / int(limit) < TETRAPOD_MINIMUM_RATE_LIMIT:
                    log.warning('X-Rate-Limit-Remaining is less than %d percent.' % TETRAPOD_MINIMUM_RATE_LIMIT)
                    log.warning('Waiting one hour for Rate-Limit to return.')
                    for i in range(12):
                        sleep(300.0)
                        mins = int((3600 - (i*300)) / 60.0)
                        log.debug('Waiting one hour for Rate-Limit, %d minutes remaining.' % mins)
                return response

            if 400 <= response.status_code < 500:
                log.error("HTTP Error happened, status: %s" % response.status_code)
                log.error('* method: %s' % method)
                log.error('* url: %s' % url)
                if kwargs.get('json'):
                    log.error('* json: %s' % repr(kwargs['json']))
                log.error('* server response: %s' % repr(response.content))
                sleep(3.0)
                # Errors like 404 or 403 are most likely our own fault and we return immediately
                return response

            if 500 <= response.status_code < 600:
                # Most likely, we have encountered a 504 Gateway timeout error.
                retry_counter -= 1
                log.warning('Response from URL "%s" with status code %d. Retrying in 3 seconds ...' % (url, response.status_code))
                sleep(3.0)
                continue


def authorize(client_id, client_secret=None):
    """
    :param client_id:
    :param client_secret:
    :return:
    """
    # The HTTP request handler stores the credentials in a module-global
    # variable, make sure it is clean.
    global credentials
    credentials = None

    # Create a temporary class that extends the handler class above. This will add the
    # client-ID and client secret as static members to OAuth2CallbackHandler.
    server = HTTPServer(('localhost', 0), MakeHandlerClass(client_id, client_secret))

    port = server.socket.getsockname()[1]
    client = MobileApplicationClient(client_id=client_id)# client_secret=client_secret)
    podio = OAuth2Session(client=client, scope=['global:all'],
                          redirect_uri='http://localhost:%d/' % port)
    # Try the client-side flow
    authorization_url, state = podio.authorization_url(AUTHORIZATION_BASE_URL)

    click.echo('Opening authorization flow in the ')
    click.launch(authorization_url)
    try:
        # Getting a valid POST request from the logged in user will set KEEP_RUNNING to False
        # which will stop this while-loop.
        while keep_running():
            server.handle_request()
    except KeyboardInterrupt:
        server.server_close()
        raise CouldNotAcquireToken()
    server.server_close()
    # Check the credentials
    if credentials is None:
        raise CouldNotAcquireToken()
    # Transform the credentials a little bit.
    token = {
        'client_id': client_id,
        'access_token': credentials['access_token'][0],
        'refresh_token': credentials['refresh_token'][0],
        'token_type': credentials['token_type'][0],
        'expires_in': credentials['expires_in'][0],
    }
    return token


def make_client(client_id, token, check=True, client_token=None, enable_robustness=False):
    expires_at = token.get('expires_at', None)
    if expires_at != None:
        expires_at_dt = datetime.datetime.utcfromtimestamp(expires_at)
        token['expires_in'] = (expires_at_dt - datetime.datetime.utcnow()).total_seconds()
    #client = OAuth2Session(client_id, token=token)
    extra = {
        'client_id': client_id
    }
    if client_token != None:
        extra['client_token'] = client_token
    
    client = PodioOAuth2Session(client_id, token=token, auto_refresh_url=REFRESH_URL,
                                auto_refresh_kwargs=extra, token_updater=save_token,
                                enable_robustness=enable_robustness)
    if check is True:
        r = client.get('https://api.podio.com/user/profile/')
        r.raise_for_status()
        #if r.status_code != 200:
        #    refresh_token = token['refresh_token']
        #    new_token = client.refresh_token(REFRESH_URL, refresh_token=refresh_token, client_id=client_id)
        #    save_token(new_token)
        #    client = OAuth2Session(client_id, token=new_token)
        #    r = client.get('https://api.podio.com/user/profile/')
        # print('Logged in as "{}"'.format(r.json()['name']))
    return client


def make_app_auth_client(client_id, client_secret, app_id, app_token, robust=False):
    token_resp = requests.post(APP_AUTH_TOKEN_URL, data={
        "grant_type": "app",
        "app_id": "%s" % app_id,
        "app_token": "%s" % app_token,
        "client_id": "%s" % client_id,
        "client_secret": "%s" % client_secret,
    })
    token_resp.raise_for_status()
    token = token_resp.json()

    client = PodioOAuth2Session(client_id, token=token, enable_robustness=robust)
    return client


def save_token(token):
    with open('.tetrapod_credentials.json', mode='w') as fh:
        expires_at = datetime.datetime.utcnow() \
                     + datetime.timedelta(seconds=int(token.get('expires_in', 0)))
        # strftime depends on the platform. Windows does not support the '%s' format for
        # unix timestamps. Therefore we need to create our own unix timestamp here.
        epoch = datetime.datetime(1970, 1, 1)
        token['expires_at'] = int((expires_at - epoch).total_seconds())
        json.dump(token, fh, indent=2, sort_keys=True)


def load_token(token_filename=None):
    if token_filename is None:
        fname = '.tetrapod_credentials.json'
    else:
        fname = token_filename
    with open(fname, mode='r') as fh:
        token = json.load(fh)
        return token
