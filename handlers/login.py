import json
import random
import string
import requests

from flask import session as login_session, render_template, request
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

from app import app
from helpers import json_response, get_user_id, create_user, redirect, url_for
from session import session_scope


with open('client_secrets.json', 'r') as f:
    CLIENT_SECRETS = json.load(f)
    CLIENT_ID = CLIENT_SECRETS['web']['client_id']


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_letters + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', client_id=CLIENT_ID, state=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # On the login page should have generated a state token and supplied it.
    # Some malicious user might attempt to go to /gconnect without going
    # through the login page.
    if request.args.get('state') != login_session['state']:
        return json_response('Invalid state token', 401)

    # authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object

        # We send requests to google with oauth_flow as it has our client id
        # and secret so google know's it's from us (we have an account there)
        # and valid.
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='',
                                             redirect_uri='postmessage')
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return json_response('Failed to upgrade the authorization code', 401)

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
           .format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        return json_response(result.get('error'), 500)

    # Verify that the access token in used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return json_response(
            "Token's user ID doesn't match given user ID.", 401)

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return json_response("Token's client ID does not match app's.", 401)

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token,
              'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session.update(
        username=data['name'],
        picture=data['picture'],
        email=data['email'])

    with session_scope() as session:
        user_id = get_user_id(login_session['email'], session)
        if not user_id:
            user_id = create_user(login_session, session)

    login_session['user_id'] = user_id

    return render_template("connected.html",
                           username=login_session['username'],
                           picture_src=login_session['picture'])


@app.route("/gdisconnect")
def gdisconnect():
    # only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        return json_response('Current user not connected', 401)

    requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': login_session['access_token']},
        headers={'content-type': 'application/x-www-form-urlencoded'})

    to_remove = {'access_token', 'gplus_id', 'username', 'email',
                 'picture', 'user_id'}

    for key in to_remove:
        del login_session[key]

    return redirect(url_for('mainpage'))
