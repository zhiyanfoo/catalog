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

from models import Base, Category, Item
from helpers import (equal_session_id, get_catalog_info, get_category_name,
                     get_category, get_user_id, create_user, json_response,
                     item_to_json, item_to_tuple, verify_item_form,
                     ensure_authenticated)

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
def mainpage():
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        latest_items = (session.query(Item)
                        .order_by(desc(Item.created))
                        .limit(6)
                        .all())
        latest_items_info = [(item, get_category_name(item.category_id, session))
                             for item in latest_items]
        return render_template("mainpage.html", catalog_info=catalog_info,
                               latest_items_info=latest_items_info)


@app.route('/category/<int:category_id>/')
def category(category_id):
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        current_category = (session.query(Category)
                            .filter_by(id=category_id).first())

        if not current_category:
            return json_response("invalid category", 404)

        items = (session.query(Item)
                 .filter_by(category_id=category_id)
                 .order_by(desc(Item.created))
                 .all())
        items_info = [(item, equal_session_id(item.user_id)) for item in items]
        return render_template("category.html",
                               current_category=current_category,
                               catalog_info=catalog_info,
                               items_info=items_info)


@app.route('/category/<int:category_id>/edit/', methods=['Get'])
def edit_category_get(category_id):
    if 'username' not in login_session:
        return redirect(url_for('login'))

    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        return render_template("edit_category.html", id=category_id,
                               name=category.name)


@app.route('/category/<int:category_id>/edit/', methods=['Post'])
@ensure_authenticated
def edit_category_post(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        new_category_name = request.form['name'].strip()
        if not new_category_name:
            return redirect(url_for('edit_category'))

        category.name = new_category_name
        return redirect(url_for('mainpage'))


@app.route('/category/<int:category_id>/delete/')
@ensure_authenticated
def delete_category_get(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        return render_template("confirm_delete.html")


@app.route('/category/<int:category_id>/delete/', methods=['Post'])
@ensure_authenticated
def delete_category_post(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        items = (session.query(Item)
                 .filter_by(category_id=category.id)
                 .all())
        for item in items:
            session.delete(item)

        session.delete(category)
        return redirect(url_for('mainpage'))


@app.route('/category/<int:category_id>/item/new')
@app.route('/category/item/new')
@ensure_authenticated
def new_item_get(category_id=None):
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        if not catalog_info:
            return json_response("Add Category first", 400)

        return render_template("new_item.html",
                               catalog_info=catalog_info)


@app.route('/category/item/new', methods=['Post'])
@ensure_authenticated
def new_item_post():
    items_or_response = verify_item_form(request)
    if not isinstance(items_or_response, tuple):
        return items_or_response

    item_name, item_description, item_price = items_or_response

    with session_scope() as session:
        category = (session.query(Category)
                    .filter_by(name=request.form['category']).first())

        session.add(
            Item(name=item_name,
                 description=item_description,
                 price=item_price,
                 user_id=login_session['user_id'],
                 category_id=category.id))

        return redirect(url_for('category', category_id=category.id))


@app.route('/category/<int:category_id>/item/<int:item_id>/delete/')
@ensure_authenticated
def delete_item_get(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        session.delete(item)
        return redirect(url_for('category', category_id=category_id))


@app.route('/category/<int:category_id>/item/<int:item_id>/edit/')
@ensure_authenticated
def edit_item_get(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        catalog_info = get_catalog_info(session)
        return render_template("edit_item.html",
                               catalog_info=catalog_info,
                               item=item)


@app.route('/category/<int:category_id>/item/<int:item_id>/edit/',
           methods=['Post'])
@ensure_authenticated
def edit_item_post(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item:
            return json_response("invalid id", 404)

        if not equal_session_id(item.user_id):
            return redirect('/login')

        items_or_response = verify_item_form(request)
        if not isinstance(items_or_response, tuple):
            return items_or_response

        item.name, item.description, item.price = items_or_response
        return redirect(url_for('category', category_id=category_id))


@app.route('/category/new', methods=['Get'])
@ensure_authenticated
def new_category_get():
    return render_template('new_category.html')


@app.route('/category/new', methods=['Post'])
@ensure_authenticated
def new_category_post():
    category_name = request.form['name'].strip()
    if not category_name:
        return redirect(url_for('new_category_get'))

    with session_scope() as session:
        session.add(
            Category(name=request.form['name'],
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


@app.route('/category/<int:category_id>/item/<int:item_id>/json/')
def item_get_json(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if item:
            return json_response(item_to_json(item), 200)

        json_response({"error": "item does not exist"}, 404)


@app.route('/json')
def catalog_get_json():
    with session_scope() as session:
        category = session.query(Category).all()
        category_list = []
        for category in catalog:
            items = session.query(Item).filter_by(catagory_id=category.id).all()
            d = {'id': category.id,
                 'name': category.name,
                 'items': dict(map(item_to_tuple, items))}
            catagory_list.append(d)

        return json_response(catalog_list, 200)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
