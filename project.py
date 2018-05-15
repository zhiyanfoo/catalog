import json
from contextlib import contextmanager
import random
import string
from functools import wraps, update_wrapper
from datetime import datetime

from flask import (Flask, render_template, redirect, url_for, request,
                   session as login_session, make_response)
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import requests
import httplib2

from database_setup import Base, Catalog, Item
from helpers import (equal_session_id, get_catalog_info, get_catalog_name,
                     get_catalog, get_user_id, create_user, json_response,
                     item_to_json)

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
def mainpage():
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        latest_items = (session.query(Item)
                        .order_by(desc(Item.created))
                        .limit(6)
                        .all())
        latest_items_info = [(item, get_catalog_name(item.catalog_id, session))
                             for item in latest_items]
        return render_template("mainpage.html", catalog_info=catalog_info,
                               latest_items_info=latest_items_info)


@app.route('/catalog/<int:catalog_id>/')
def catalog_items(catalog_id):
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        current_catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        items = (session.query(Item)
                 .filter_by(catalog_id=catalog_id)
                 .order_by(desc(Item.created))
                 .all())
        items_info = [(item, equal_session_id(item.user_id)) for item in items]
        return render_template("catalog_items.html",
                               current_catalog=current_catalog,
                               catalog_info=catalog_info,
                               items_info=items_info)


@app.route('/catalog/<int:id>/edit/', methods=['Get'])
def edit_catalog_get(id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog = get_catalog(id, session)
        if not catalog or not equal_session_id(catalog.user_id):
            return redirect(url_for('login'))

        return render_template("edit_catalog.html", id=id, name=catalog.name)


@app.route('/catalog/<int:id>/edit/', methods=['Post'])
def edit_catalog_post(id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog = get_catalog(id, session)
        if not catalog or not equal_session_id(catalog.user_id):
            return redirect(url_for('login'))

        catalog.name = request.form['name']
        return redirect(url_for('mainpage'))


@app.route('/catalog/<int:id>/delete/')
def delete_catalog_get(id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog = get_catalog(id, session)
        if not catalog or not equal_session_id(catalog.user_id):
            return redirect(url_for('login'))

        return render_template("confirm_delete.html")


@app.route('/catalog/<int:id>/delete/', methods=['Post'])
def delete_catalog_post(id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog = get_catalog(id, session)
        if not catalog or not equal_session_id(catalog.user_id):
            return redirect(url_for('login'))

        catalog_items = (session.query(Item)
                         .filter_by(catalog_id=catalog.id)
                         .all())
        for item in catalog_items:
            session.delete(item)

        session.delete(catalog)
        return redirect(url_for('mainpage'))


@app.route('/catalog/<int:catalog_id>/item/new')
@app.route('/catalog/item/new')
def new_item_get(catalog_id=None):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        catalog_info = get_catalog_info(session)

        return render_template("new_item.html",
                               catalog_info=catalog_info)


@app.route('/catalog/item/new', methods=['Post'])
def new_item_post():
    if 'username' not in login_session:
        return redirect(url_for('login'))

    all_filled = all([request.form['name'],
                      request.form['description'],
                      request.form['price']])
    if not all_filled:
        return redirect(url_for('new_item_get'))

    with session_scope() as session:
        catalog = session.query(
            Catalog).filter_by(name=request.form['catalog']).first()
        session.add(
            Item(name=request.form['name'],
                 description=request.form['description'],
                 price=request.form['price'],
                 user_id=login_session['user_id'],
                 catalog_id=catalog.id))

        return redirect(url_for('catalog_items', catalog_id=catalog.id))


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/delete/')
def delete_item_get(catalog_id, item_id):
    if 'username' not in login_session:
        return redirect(url_for('/login'))

    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        session.delete(item)
        return redirect(url_for('catalog_items', catalog_id=catalog_id))


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/edit/')
def edit_item_get(catalog_id, item_id):
    if 'username' not in login_session:
        return redirect(url_for('/login'))

    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        catalog_info = get_catalog_info(session)
        return render_template("edit_item.html",
                               catalog_info=catalog_info,
                               item=item)


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/edit/',
           methods=['Post'])
def edit_item_post(catalog_id, item_id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not equal_session_id(item.user_id):
            return redirect('/login')

        item.name = request.form['name']
        item.description = request.form['description']
        item.price = request.form['price']

        return redirect(url_for('catalog_items', catalog_id=catalog_id))


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

    return redirect(url_for('mainpage'))


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
        print 'Access Token is None'
        return json_response('Current user not connected', 401)

    print 'In gdisconnect access token is {}'.format(access_token)
    print 'User name is '
    print login_session['username']

    requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': login_session['access_token']},
        headers={'content-type': 'application/x-www-form-urlencoded'})

    to_remove = {'access_token', 'gplus_id', 'username', 'email',
                 'picture', 'user_id'}

    for key in to_remove:
        del login_session[key]

    return redirect(url_for('mainpage'))


@app.route('/catalog/<int:catalog_id>/item/<int:item_id>/json/')
def item_get_json(catalog_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if item:
            return json_response(item_to_json(item), 200)

        json_response({"error": "item does not exist"}, 404)


@app.route('/catalog/json')
def catalog_get_json():
    with session_scope() as session:
        catalog = session.query(Catalog).all()
        catalog_list = []
        for category in catalog:
            items = session.query(Item).filter_by(catalog_id=category.id).all()
            from helpers import item_to_tuple
            d = {'id': category.id,
                 'name': category.name,
                 'items': dict(map(item_to_tuple, items))}
            catalog_list.append(d)

        return json_response(catalog_list, 200)


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


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
