import json
from contextlib import contextmanager
import random
import string
from functools import wraps, update_wrapper
from datetime import datetime

from flask import (Flask, render_template, redirect, url_for, request,
                   session as login_session, make_response, flash)
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import requests
import httplib2

from database_setup import Base, User, Catalog, Item

app = Flask(__name__)
app.secret_key = 'super secret key'

with open('client_secrets.json', 'r') as f:
    CLIENT_SECRETS = json.load(f)
    CLIENT_ID = CLIENT_SECRETS['web']['client_id']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)


@contextmanager
def session_scope():
    session = DBSession()
    yield session
    try:
        session.commit()
    finally:
        session.close()


@app.route('/login')
def login():
    state = ''.join(random.choice(string.ascii_letters + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', client_id=CLIENT_ID, state=state)


@app.route('/')
@app.route('/catalog/')
def catalog():
    with session_scope() as session:
        _catalog = session.query(Catalog).all()
        catalog_info = [(c.name, c.id, equal_session_id(c.user_id))
                        for c in _catalog]
        latest_items = (session.query(Item)
                        .order_by(desc(Item.created))
                        .limit(6)
                        .all())
        print(latest_items)
        return render_template("mainpage.html", catalog_info=catalog_info)


def equal_session_id(user_id):
    if 'user_id' in login_session:
        return user_id == login_session['user_id']


@app.route('/catalog/<int:catalog_id>/')
def catalog_items(catalog_id):
    session = DBSession()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items = session.query(Item).filter_by(catalog_id=catalog_id).all()
    return str(catalog_id)


@app.route('/catalog/<int:id>/edit/', methods=['Get'])
def edit_catalog_get(id):
    if not user_owns(id):
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog_name = get_catalog(id, session).name

    return render_template("edit_catalog.html", id=id, name=catalog_name)

@app.route('/catalog/<int:id>/edit/', methods=['Post'])
def edit_catalog_post(id):
    if not user_owns(id):
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog = get_catalog(id, session)
        catalog.name = request.form['name']

    return redirect(url_for('catalog'))

def user_owns(catalog_id):
    with session_scope() as session:
        catalog = session.query(Catalog).filter_by(id=catalog_id).first()
        return catalog.user_id == login_session['user_id']

def get_catalog(id, session):
    return session.query(Catalog).filter_by(id=id).first()


@app.route('/catalog/<int:id>/delete/')
def delete_catalog_get(id):
    pass


@app.route('/catalog/new', methods=['Get'])
def new_catalog_get():
    if 'username' not in login_session:
        return redirect('/login')

    return render_template('new_catalog.html')


@app.route('/catalog/new', methods=['Post'])
def new_catalog_post():
    if 'username' not in login_session:
        return redirect('/login')

    with session_scope() as session:
        session.add(
            Catalog(name=request.form['name'],
                    user_id=login_session['user_id']))

    return redirect(url_for('catalog'))


def json_response(message, error_code):
    response = make_response(json.dumps(message), error_code)
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # On the login page should have generated a state token and supplied it.
    # Some malicious user might attempt to go to /gconnect without going
    # through the login page.
    if request.args.get('state') != login_session['state']:
        return json_response('Invalid state token', 401)

    # authorization code
    code  = request.data
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

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)

    login_session['user_id'] = user_id

    return render_template("connected.html",
                           username=login_session['username'],
                           picture_src=login_session['picture'])

@app.route("/gdisconnect")
def gdisconnect():
    # only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        return json_response('Current user not connected', 401)

    print 'In gdisconnect access token is {}'.format(access_token)
    print 'User name is '
    print login_session['username']
    url = ('https://accounts.google.com/o/oauth2/revoke?token={}'
           .format(login_session['access_token']))
    h = httplib2.Http()
    result, _ = h.request(url, 'GET')
    print 'result is '
    print result

    if result['status'] == '200':
        to_remove = {'access_token', 'gplus_id', 'username', 'email',
                     'picture'}
        for key in to_remove:
            del login_session[key]

        return json_response('Successfully disconnected.', 200)

    return json_response('Failed to revoke token for given user', 400)


def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = ('no-store, no-cache,'
                                             ' must-revalidate, post-check=0,'
                                             ' pre-check=0, max-age=0')
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return update_wrapper(no_cache, view)


@app.route('/static/style.css')
@nocache
def stylesheet():
    with open("static/style.css", 'r') as f:
        return f.read()

def create_user(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    with session_scope() as session:
        session.add(new_user)
        session.flush()
        return new_user.id


def get_user_id(email):
    with session_scope() as session:
        return session.query(User).filter_by(email=email).first().id


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
